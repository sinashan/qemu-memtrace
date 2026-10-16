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
    uint64_t accesses, events, chunks, first;
    unsigned na, ne;
    bool failed;
} TraceBinary;
static bool binary_flush(TraceBinary *b)
{
    unsigned char header[40];TcBuf h={header,0,sizeof(header),false};
    if(b->failed)return false;
    if(!b->used)return true;
    if(b->chunks==UINT64_MAX){b->failed=true;return false;}
    tc_chunk_header(&h,b->payload,b->used,b->first,b->na,b->ne,0,0);
    if(h.failed || !writer_write(&b->writer,(const char *)header,h.size) ||
       !writer_write(&b->writer,(const char *)b->payload,b->used)){b->failed=true;return false;}
    b->chunks++;b->used=0;b->na=b->ne=0;return true;
}
static bool binary_boundary(TraceBinary *b)
{ return binary_flush(b) && writer_boundary(&b->writer); }
static bool binary_open(TraceBinary *b,const char *path,size_t cap,unsigned level)
{
    unsigned char header[36];TcBuf h={header,0,sizeof(header),false};
    b->cap=cap;b->payload=malloc(cap);
    if(!b->payload || !writer_open(&b->writer,"binary",path,true,level))return false;
    tc_header(&h,2,4|TC_LIVE,cap,65536,0);
    return !h.failed && writer_write(&b->writer,(const char *)header,h.size) && writer_boundary(&b->writer);
}
static bool binary_packet(TraceBinary *b,TcBuf *packet,bool access)
{
    if(b->failed || packet->failed || packet->size>b->cap ||
       (access?b->accesses:b->events)==UINT64_MAX){b->failed=true;return false;}
    if(packet->size>b->cap-b->used && !binary_flush(b))return false;
    /* Event-only chunks after UINT64_MAX cannot express first=MAX+1. Refuse. */
    if(!b->used){if(b->accesses==UINT64_MAX){b->failed=true;return false;}b->first=b->accesses+1;}
    memcpy(b->payload+b->used,packet->data,packet->size);b->used+=packet->size;
    if(access){b->accesses++;b->na++;}else{b->events++;b->ne++;}return true;
}
static bool binary_access(TraceBinary *b,const TcAccess *a)
{
    unsigned char bytes[TC_PACKET_CAP];TcBuf p={bytes,0,sizeof(bytes),false};
    tc_inline(&p,a);return binary_packet(b,&p,true);
}
static bool binary_event(TraceBinary *b,uint64_t id,uint64_t interval,unsigned kind,bool cpu,uint64_t sequence)
{
    unsigned char bytes[64];TcBuf p={bytes,0,sizeof(bytes),false};
    if(sequence!=b->accesses || id!=b->events+1 || b->events==UINT64_MAX){b->failed=true;return false;}
    tc_event(&p,id,interval,kind,cpu,sequence);return binary_packet(b,&p,false);
}
static bool binary_finish(TraceBinary *b,unsigned status)
{
    unsigned char bytes[84];TcBuf p={bytes,0,sizeof(bytes),false};
    uint64_t counts[9]={b->accesses,b->events,b->chunks,0,0,0,0,0,0};
    if(!binary_flush(b))return false;
    counts[2]=b->chunks;
    tc_footer(&p,counts,status);
    return !p.failed && writer_write(&b->writer,(const char *)bytes,p.size) && writer_boundary(&b->writer);
}
static bool binary_close(TraceBinary *b)
{ bool ok=writer_close(&b->writer)&&!b->failed;free(b->payload);b->payload=NULL;return ok; }
#endif
