/* Bounded streaming Linux-v3 capture inspection. SPDX-License-Identifier: GPL-2.0-or-later */
#include "traces/trace-codec/decoder.hpp"
#include "qemu-memtrace/target/i386/plugin-paging.h"
#include <iostream>
#include <map>
using namespace tracecodec;
static U num(const string& s) {
    U n=0;size_t start=s.size()>2&&s.substr(0,2)=="0x"?2:0;
    auto r=from_chars(s.data()+start,s.data()+s.size(),n,start?16:10);
    require(start<s.size()&&r.ec==errc()&&r.ptr==s.data()+s.size(),"invalid integer: "+s);return n;
}
static string hexstr(U n){ostringstream s;s<<"0x"<<hex<<n;return esc(s.str());}
struct Manifest {
    map<string,U> v;
    explicit Manifest(const string& path){
        require(fs::file_size(path)<=65536,"workload output exceeds 64 KiB bound");
        ifstream f(path);require(bool(f),"cannot open workload output");
        array<char,65537> buffer{};
        f.read(buffer.data(),buffer.size());
        require(!f.bad()&&f.eof()&&f.gcount()<=65536,"workload output changed/exceeds 64 KiB or read failed");
        istringstream input(string(buffer.data(),static_cast<size_t>(f.gcount())));
        string line;size_t bytes=0;
        while(getline(input,line)){
            bytes+=line.size()+1;require(bytes<=65536,"workload output exceeds 64 KiB bound");
            if(!line.empty()&&line.back()=='\r')line.pop_back();
            auto p=line.find('=');require(p!=string::npos,"unexpected workload output line: "+line);
            string key=line.substr(0,p);require(!v.count(key),"duplicate workload field: "+key);
            v[key]=num(line.substr(p+1));
        }require(input.eof(),"workload output read failure");
        for(auto k:{"linux_v3_test","page_size","cross_base","cross_va","cross_load_pc","cross_store_pc",
                     "remap_va","remap_old_pc","remap_new_pc","cross_verified","remap_old_value",
                     "remap_new_value","remap_verified","linux_v3_success"})require(v.count(k),string("missing workload field: ")+k);
        require(v["linux_v3_test"]==1&&v["page_size"]==4096&&v["cross_verified"]==1&&v["remap_verified"]==1&&v["linux_v3_success"]==1,
                "workload did not report successful completion");
        require(v["remap_old_value"]==49&&v["remap_new_value"]==167,"unexpected backing page values");
        require(!(v["cross_base"]&4095)&&v["cross_base"]<=UINT64_MAX-8191&&v["cross_va"]==v["cross_base"]+4088&&
                !(v["remap_va"]&4095),"invalid workload mapping bounds");
    }
};
struct ReadPath {const vector<TcPte>& path;size_t next=0;};
static qemu_plugin_x86_walk_status read_path(void *p,uint64_t pa,uint64_t *value){
    auto& r=*static_cast<ReadPath*>(p);
    if(r.next>=r.path.size()||r.path[r.next].address!=pa)return QEMU_PLUGIN_X86_WALK_READ_FAILED;
    *value=r.path[r.next++].value;return QEMU_PLUGIN_X86_WALK_OK;
}
static void validate_segment(const Access& s){
    require(s.memory.mask==7&&s.context.mask==63&&s.walk.result.mask==7&&s.memory_type==0,
            "target requires observed RAM PA and complete paging snapshot");
    require(s.walk.status=="OK"&&s.walk.comparison=="match","target walk is not OK/match");
    require(s.size&&s.memory.value[1]<=UINT64_MAX-(s.size-1)&&s.memory.value[2]<=UINT64_MAX-(s.size-1),"target range overflow");
    const auto& c=s.context;struct qemu_plugin_x86_walk w{};
    w.paging={c.value[0],c.value[1],c.value[2],c.value[3],c.value[4],static_cast<uint32_t>(c.value[5]),true};
    require(c.value[5]>=32&&c.value[5]<=52&&!(c.value[3]&(U(1)<<17)),"unsupported target paging state/PCIDE");
    ReadPath path{s.walk.entries};x86_plugin_decode_walk(&w,s.memory.value[1],read_path,&path);
    require(w.status==QEMU_PLUGIN_X86_WALK_OK&&w.leaf_size==4096&&s.walk.result.value[0]==4096&&
        path.next==s.walk.entries.size()&&w.n_entries==s.walk.entries.size(),"target PTE path does not decode to a complete 4 KiB leaf");
    require(w.paging.root_pa==c.value[1]&&w.pa==s.memory.value[2]&&w.pa==s.walk.result.value[1]&&w.pa==s.walk.result.value[2],
            "target observed/reconstructed/callback PA mismatch");
    for(size_t i=0;i<path.path.size();i++)require(path.path[i].level==w.entries[i].level,"target PTE level ordering mismatch");
    require(s.size<=4096-(s.memory.value[1]&4095),"target segment crosses mapping boundary");
}
struct Counts {
    U interval=0,begin=0,end=0,originals=0,segments=0,targets=0,kernel=0,other=0,ram_lines=0;
    array<U,6> contexts{};bool began=false,ended=false;
};
struct Target {string name;U pc,va,size,op,interval,order=0;Access access;bool found=false;};
static string target_json(const Target& t){
    const auto& a=t.access;ostringstream o;
    o<<"{\"name\":"<<esc(t.name)<<",\"sequence\":"<<a.sequence<<",\"order\":"<<t.order
     <<",\"pc\":"<<hexstr(t.pc)<<",\"va\":"<<hexstr(t.va)<<",\"size\":"<<a.size<<",\"operation\":"<<esc(a.operation?"W":"R")<<",\"segments\":[";
    for(size_t i=0;i<a.segments.size();i++){
        if(i)o<<',';
        const auto& s=a.segments[i];
        o<<"{\"offset\":"<<s.offset<<",\"length\":"<<s.size<<",\"va\":"<<hexstr(s.memory.value[1])
         <<",\"pa\":"<<hexstr(s.memory.value[2])<<",\"cr3\":"<<hexstr(s.context.value[0])<<",\"root\":"<<hexstr(s.context.value[1])
         <<",\"leaf_size\":4096,\"reconstructed_pa\":"<<hexstr(s.walk.result.value[1])<<",\"pte_path\":[";
        for(size_t j=0;j<s.walk.entries.size();j++){if(j)o<<',';auto& p=s.walk.entries[j];
            o<<"{\"level\":"<<unsigned(p.level)<<",\"entry_pa\":"<<hexstr(p.address)<<",\"raw\":"<<hexstr(p.value)<<'}';}
        o<<"]}";
    }o<<"]}";return o.str();
}
int main(int argc,char **argv){
    try{
        require(argc==6,"usage: verify-linux-v3 TRACE WORKLOAD_OUTPUT CROSS_INTERVAL REMAP_INTERVAL MAX_RECORDS");
        Manifest m(argv[2]);U cross=num(argv[3]),remap=num(argv[4]),max_records=num(argv[5]);
        require(cross&&remap&&cross!=remap&&max_records&&max_records<=1000000000,"invalid interval IDs or record bound (1..1000000000)");
        array<Counts,2> counts{};counts[0].interval=cross;counts[1].interval=remap;
        array<Target,4> targets{{{"wide-load",m.v["cross_load_pc"],m.v["cross_va"],16,0,cross},
            {"wide-store",m.v["cross_store_pc"],m.v["cross_va"],16,1,cross},
            {"old-mapping",m.v["remap_old_pc"],m.v["remap_va"],1,0,remap},
            {"new-mapping",m.v["remap_new_pc"],m.v["remap_va"],1,0,remap}}};
        for(size_t i=0;i<4;i++)for(size_t j=0;j<i;j++)require(targets[i].pc!=targets[j].pc,"target PCs must be distinct");
        Decoder decoder(argv[1]);require(decoder.opt.execution,"requires version-3 execution-binary; legacy captures lack required evidence");
        Record r;U records=0,current=0,between_contexts=0,applicable=0;
        string first_event;vector<string> examples; // at most eight explanatory context records
        while(decoder.next(r)){
            require(++records<=max_records,"record bound exceeded: footer/EOF NOT validated; increase --max-records explicitly");
            if(r.event){
                auto& e=r.boundary;
                if(e.kind=="BEGIN")current=e.interval;
                for(auto& c:counts)if(c.interval==e.interval){
                    if(e.kind=="BEGIN"){require(!c.began,"duplicate selected BEGIN");c.began=true;c.begin=e.sequence;}
                    else{require(e.kind=="END","selected interval lacks complete END: "+e.kind);c.ended=true;c.end=e.sequence;}
                }
                if(e.kind!="BEGIN")current=0;
                continue;
            }
            if(r.context_event){
                const auto& c=r.context;
                for(auto& n:counts)if(current==n.interval)++n.contexts[c.kind];
                if(current==remap&&targets[2].found&&!targets[3].found&&c.kind){
                    ++between_contexts;const auto& old=targets[2].access.segments.front();
                    bool same_root=c.after.value[1]==old.context.value[1];
                    bool nonglobal=!(old.walk.entries.back().value&256);
                    // scope=1 is conservative-all, but require stronger evidence
                    // for this Linux test: matching-root INVLPG at our page or a
                    // PCIDE-off CR3 write/reload that clears non-global entries.
                    bool eligible=c.kind==1?same_root&&((c.operand>>12)==(m.v["remap_va"]>>12)):
                        c.kind==3&&nonglobal&&c.operand==c.after.value[0]&&!(c.after.value[3]&(U(1)<<17));
                    ostringstream e;e<<"{\"order\":"<<r.order<<",\"kind\":"<<c.kind<<",\"operand\":"<<hexstr(c.operand)
                        <<",\"root\":"<<hexstr(c.after.value[1])<<",\"applicable\":"<<(eligible?"true":"false")<<'}';
                    if(examples.size()<8)examples.push_back(e.str());
                    if(eligible){++applicable;if(first_event.empty())first_event=e.str();}
                }continue;
            }
            auto& a=r.access;bool targeted=false;
            for(auto& t:targets)if(t.interval==current&&a.memory.value[0]==t.pc){
                require(!t.found,"duplicate targeted PC: "+t.name);
                require(a.cpu==0&&a.memory.value[1]==t.va&&a.size==t.size&&a.operation==t.op,
                        "target original access identity/VA/size/operation mismatch: "+t.name);
                require(a.segments.size()==(t.size==16?2u:1u),"target segment count mismatch: "+t.name);
                U covered=0;
                for(const auto& s:a.segments){
                    require(s.sequence==a.sequence&&s.offset==covered&&s.memory.value[0]==t.pc&&s.operation==t.op&&s.memory.value[1]==t.va+covered,
                        "target missing/duplicated bytes or segment identity mismatch");
                    require(s.size==(t.size==16?8u:1u),"target segment lengths must be 8+8 (wide) or 1 (remap)");
                    try { validate_segment(s); }
                    catch(const exception& e){fail("target "+t.name+" sequence "+to_string(a.sequence)+" offset "+to_string(s.offset)+": "+e.what());}
                    covered+=s.size;
                }require(covered==t.size,"target incomplete byte coverage");
                t.access=a;t.order=r.order;t.found=true;targeted=true;
            }
            for(auto& c:counts)if(current==c.interval){
                ++c.originals;c.segments+=a.segments.size();
                if(targeted)++c.targets;else if(a.memory.value[0]>=0xffff800000000000ULL)++c.kernel;else ++c.other;
                for(auto& s:a.segments)if(s.memory_type==0)c.ram_lines+=((s.memory.value[2]&63)+s.size+63)/64;
            }
        }
        require(decoder.done&&!decoder.opt.prefix&&decoder.total.status==0,"capture not finalized/completely END-closed; no prefix acceptance");
        for(auto& c:counts)require(c.began&&c.ended&&c.end-c.begin==c.originals&&c.targets==2,"selected interval missing targets/END or inconsistent access range");
        for(auto& t:targets)require(t.found,"missing target: "+t.name);
        require(targets[0].order<targets[1].order,"wide load must precede wide store");
        for(size_t i=0;i<2;i++)require(targets[0].access.segments[i].memory.value[2]==targets[1].access.segments[i].memory.value[2],"cross mapping changed between wide load/store");
        const auto& old=targets[2].access.segments[0];const auto& now=targets[3].access.segments[0];
        require(targets[2].order<targets[3].order,"old/new mapping order reversed");
        require(old.context.value[1]==now.context.value[1],"old/new application roots differ: not the intended same-root remap test");
        require((old.memory.value[2]>>12)!=(now.memory.value[2]>>12),"target remapping did not change the observed physical frame: old="+hexstr(old.memory.value[2])+" new="+hexstr(now.memory.value[2]));
        if(!applicable){
            ostringstream msg;msg<<"missing applicable recorded invalidation between old sequence "<<targets[2].access.sequence<<" and new "<<targets[3].access.sequence
                <<"; context records="<<between_contexts<<"; first examples=[";
            for(auto& s:examples)msg<<s<<',';
            msg<<"] (require matching-page/root INVLPG or PCIDE-off CR3 write/reload for nonglobal mapping)";fail(msg.str());
        }
        U first=targets[0].access.segments[0].memory.value[2],second=targets[0].access.segments[1].memory.value[2];
        bool noncontiguous=first+8!=second;
        cout<<"{\"capture_verified\":true,\"baseline_replay_required\":true,\"format_version\":3,\"full_input_validated\":true,\"records_scanned\":"<<records
            <<",\"cross_noncontiguous_coverage\":"<<esc(noncontiguous?"observed":"absent (captured frames are contiguous)")
            <<",\"old_frame\":"<<hexstr(old.memory.value[2]&~U(4095))<<",\"new_frame\":"<<hexstr(now.memory.value[2]&~U(4095))
            <<",\"between_context_records\":"<<between_contexts<<",\"applicable_invalidation_records\":"<<applicable
            <<",\"first_applicable_event\":"<<first_event<<",\"targets\":[";
        for(size_t i=0;i<4;i++){if(i)cout<<',';cout<<target_json(targets[i]);}
        cout<<"],\"intervals\":[";
        for(size_t i=0;i<2;i++){if(i)cout<<',';auto& c=counts[i];U context_total=0;for(size_t k=1;k<6;k++)context_total+=c.contexts[k];
            cout<<"{\"interval\":"<<c.interval<<",\"begin_sequence\":"<<c.begin<<",\"end_sequence\":"<<c.end
                <<",\"original_accesses\":"<<c.originals<<",\"segments\":"<<c.segments<<",\"targeted_accesses\":"<<c.targets
                <<",\"incidental_kernel_pc_accesses_heuristic\":"<<c.kernel<<",\"incidental_other_accesses\":"<<c.other
                <<",\"ram_cache_line_transactions\":"<<c.ram_lines<<",\"context_events\":"<<context_total<<'}';}
        cout<<"]}\n";require(bool(cout),"verification report output failure");
    }catch(const exception& e){cerr<<"verify-linux-v3: "<<e.what()<<'\n';return 1;}
}
