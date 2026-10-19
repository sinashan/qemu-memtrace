/* Small synthetic verifier fixtures, never evidence of actual guest mappings. */
#include "traces/trace-codec/wire.h"
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
using U=uint64_t;
struct Fixture {
    std::vector<uint8_t> payload;U order=0,accesses=0,events=0,contexts=0;
    void add(TcBuf& b,unsigned kind){
        if(b.failed)throw std::runtime_error("fixture serialization failure");
        uint8_t bytes[10];TcBuf o{bytes,0,sizeof(bytes),false};tc_var(&o,++order);
        payload.insert(payload.end(),bytes,bytes+o.size);payload.insert(payload.end(),b.data,b.data+b.size);
        if(kind==0)++accesses;else if(kind==1)++events;else ++contexts;
    }
    void event(unsigned interval,unsigned kind){uint8_t bytes[64];TcBuf b{bytes,0,sizeof(bytes),false};tc_event(&b,events+1,interval,kind,true,accesses);add(b,1);}
    void context(const TcCells& c,unsigned kind=0,U operand=0){uint8_t bytes[128];TcBuf b{bytes,0,sizeof(bytes),false};tc_arch_context(&b,kind,operand,&c);add(b,2);}
    void group(U size,const std::vector<TcAccess>& a){uint8_t bytes[TC_PACKET_CAP];TcBuf b{bytes,0,sizeof(bytes),false};tc_group(&b,size,a.size(),a.data());add(b,0);}
    void save(const char* path,unsigned status){
        std::ofstream f(path,std::ios::binary);uint8_t bytes[128];TcBuf b{bytes,0,sizeof(bytes),false};
        tc_header(&b,3,28,4*1024*1024,65536,0);f.write((const char*)bytes,b.size);
        b.size=0;tc_chunk_header(&b,payload.data(),payload.size(),1,accesses,events,contexts,0);f.write((const char*)bytes,b.size);f.write((const char*)payload.data(),payload.size());
        U counts[9]={accesses,events,1,contexts,0,0,0,0,0};b.size=0;tc_footer(&b,counts,status);f.write((const char*)bytes,b.size);f.close();if(!f)throw std::runtime_error("fixture output failure");
    }
};
static TcAccess make(U pc,U va,U frame,U size,unsigned op){
    TcAccess a{};U root=0x100000,pa=frame+(va&4095);
    a.memory={7,{pc,va,pa}};a.context={63,{root,root,0x80010001,0x20,0xd00,40}};a.result={7,{4096,pa,pa}};
    a.size=size;a.operation=op;a.memory_type=0;a.status="OK";a.status_size=2;a.comparison="match";a.comparison_size=5;a.path_tag=2;a.n_entries=4;
    U table=root;for(unsigned i=0;i<4;i++){unsigned level=4-i;U addr=table+((va>>(12+9*(level-1)))&511)*8;U next=i==3?frame:root+(i+1)*4096;a.entries[i]={(uint8_t)level,addr,next|7};table=next;}return a;
}
int main(int argc,char** argv){
    if(argc!=4)return 2;
    std::string mode=argv[1];Fixture f;
    auto load=make(0x401110,0x400ff8,0x300000,8,0),second=make(0x401110,0x401000,mode=="contiguous"?0x301000:0x500000,8,0);
    auto incidental=make(0xffffffff81000000ULL,0xffff800000002000ULL,0xa00000,4,0);
    if(mode=="mismatch")load.result.value[1]++;
    if(mode=="bad-path")load.entries[3].value&=~U(1);
    f.event(1,0);f.context(load.context);f.group(4,{incidental});f.group(16,{load,second});
    if(mode=="duplicate")f.group(16,{load,second});
    load.memory.value[0]=second.memory.value[0]=0x401120;load.operation=second.operation=1;f.group(16,{load,second});f.event(1,1);
    auto old=make(0x401130,0x600000,0x700000,1,0),now=make(0x401140,0x600000,mode=="same-frame"?0x700000:0x900000,1,0);
    f.event(2,0);f.context(old.context);f.group(1,{old});
    if(mode!="missing-event")f.context(old.context,mode=="cr3"?3:1,mode=="cr3"?0x100000:mode=="unrelated-event"?0x601000:0x600000);
    f.group(4,{incidental});f.group(1,{now});f.event(2,mode=="limit"?2:1);f.save(argv[2],mode=="limit"?1:0);
    std::ofstream m(argv[3]);m<<"linux_v3_test=1\npage_size=4096\ncross_base=0x400000\ncross_va=0x400ff8\n"
        "cross_load_pc=0x401110\ncross_store_pc=0x401120\nremap_va=0x600000\nremap_old_pc=0x401130\nremap_new_pc=0x401140\n"
        "cross_verified=1\nremap_old_value=49\nremap_new_value=167\nremap_verified=1\nlinux_v3_success=1\n";
    m.close();return m?0:1;
}
