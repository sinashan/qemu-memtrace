/* Runtime chunk sink; shares all inline packet/framing serialization with offline codec. */
#ifndef MEMTRACE_BINARY_H
#define MEMTRACE_BINARY_H
#include "../../../traces/trace-codec/wire.h"
#include "memtrace-writer.h"
#include <stdlib.h>
typedef struct {
    TraceWriter writer;
    unsigned char *payload;
    size_t used, cap;
    uint64_t accesses, events, chunks, first, contexts, order;
    unsigned na, ne, nc;
    bool execution;
    bool failed;
} TraceBinary;
static bool binary_flush(TraceBinary *b)
{
    unsigned char header[40];TcBuf h={header,0,sizeof(header),false};
    if(b->failed)return false;
    if(!b->used)return true;
    if(b->chunks==UINT64_MAX){b->failed=true;return false;}
    tc_chunk_header(&h,b->payload,b->used,b->first,b->na,b->ne,b->nc,0);
    if(h.failed || !writer_write(&b->writer,(const char *)header,h.size) ||
       !writer_write(&b->writer,(const char *)b->payload,b->used)){b->failed=true;return false;}
    b->chunks++;b->used=0;b->na=b->ne=b->nc=0;return true;
}
static bool binary_boundary(TraceBinary *b)
{ return binary_flush(b) && writer_boundary(&b->writer); }
static bool binary_open_version(TraceBinary *b,const char *path,size_t cap,unsigned level,bool execution)
{
    unsigned char header[36];TcBuf h={header,0,sizeof(header),false};
    b->cap=cap;b->payload=malloc(cap);b->execution=execution;
    if(!b->payload || !writer_open(&b->writer,"binary",path,true,level))return false;
    tc_header(&h,execution?3:2,4|TC_LIVE|(execution?TC_EXECUTION:0),cap,65536,0);
    return !h.failed && writer_write(&b->writer,(const char *)header,h.size) && writer_boundary(&b->writer);
}
static inline bool binary_open(TraceBinary *b,const char *path,size_t cap,unsigned level)
{ return binary_open_version(b,path,cap,level,false); }
static bool binary_packet(TraceBinary *b,TcBuf *packet,unsigned kind)
{
    if(b->failed || packet->failed || packet->size>b->cap ||
       (kind==0?b->accesses:kind==1?b->events:b->contexts)==UINT64_MAX){b->failed=true;return false;}
    unsigned char order_bytes[10];TcBuf o={order_bytes,0,sizeof(order_bytes),false};
    if(b->execution){if(b->order==UINT64_MAX){b->failed=true;return false;}tc_var(&o,b->order+1);}
    if((packet->size+o.size>b->cap-b->used || b->nc==65536) && !binary_flush(b))return false;
    /* Event-only chunks after UINT64_MAX cannot express first=MAX+1. Refuse. */
    if(!b->used){if(b->accesses==UINT64_MAX){b->failed=true;return false;}b->first=b->accesses+1;}
    if(b->execution){memcpy(b->payload+b->used,o.data,o.size);b->used+=o.size;b->order++;}
    memcpy(b->payload+b->used,packet->data,packet->size);b->used+=packet->size;
    if(kind==0){b->accesses++;b->na++;}else if(kind==1){b->events++;b->ne++;}else{b->contexts++;b->nc++;}return true;
}
static bool binary_access(TraceBinary *b,const TcAccess *a)
{
    unsigned char bytes[TC_PACKET_CAP];TcBuf p={bytes,0,sizeof(bytes),false};
    tc_inline(&p,a);return binary_packet(b,&p,0);
}
static bool binary_group(TraceBinary *b,uint64_t size,unsigned n,const TcAccess *segments)
{
    unsigned char bytes[TC_PACKET_CAP];TcBuf p={bytes,0,sizeof(bytes),false};
    tc_group(&p,size,n,segments);return binary_packet(b,&p,0);
}
static bool binary_context(TraceBinary *b,unsigned kind,uint64_t operand,const TcCells *after)
{
    unsigned char bytes[128];TcBuf p={bytes,0,sizeof(bytes),false};
    tc_arch_context(&p,kind,operand,after);return binary_packet(b,&p,2);
}
static bool binary_event(TraceBinary *b,uint64_t id,uint64_t interval,unsigned kind,bool cpu,uint64_t sequence)
{
    unsigned char bytes[64];TcBuf p={bytes,0,sizeof(bytes),false};
    if(sequence!=b->accesses || id!=b->events+1 || b->events==UINT64_MAX){b->failed=true;return false;}
    tc_event(&p,id,interval,kind,cpu,sequence);return binary_packet(b,&p,1);
}
static bool binary_finish(TraceBinary *b,unsigned status)
{
    unsigned char bytes[84];TcBuf p={bytes,0,sizeof(bytes),false};
    uint64_t counts[9]={b->accesses,b->events,b->chunks,b->contexts,0,0,0,0,0};
    if(!binary_flush(b))return false;
    counts[2]=b->chunks;
    tc_footer(&p,counts,status);
    return !p.failed && writer_write(&b->writer,(const char *)bytes,p.size) && writer_boundary(&b->writer);
}
static bool binary_close(TraceBinary *b)
{ bool ok=writer_close(&b->writer)&&!b->failed;free(b->payload);b->payload=NULL;return ok; }
#endif
