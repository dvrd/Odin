package quic

import "core:bytes"
import "core:crypto"

// Legacy symbols remain source compatible; fragment density no longer uses a
// span table or returns Span_Exhausted. Normal TLS/H3 windows need no allocation.
CRYPTO_SPAN_CAP :: 32
CRYPTO_INLINE_WINDOW_MAX :: 64*1024+1024
CRYPTO_INLINE_COVERAGE_BYTES :: CRYPTO_INLINE_WINDOW_MAX/8
Crypto_Error :: enum {None,Discarded,Cap_Overflow,Overlap_Mismatch,Span_Exhausted,Invalid_Input,Coverage_Required}
Crypto_Span :: struct {start,end:int}

// buf and optional external coverage are borrowed. Inline coverage is a value,
// never a self-referential slice. Use clone for an independent transactional
// preview: copying only buf would alias external coverage supplied by a caller.
Crypto_Reassembly :: struct {
 buf:[]u8,
 span_count,contiguous,received_bytes:int,
 discarded:bool,
 _external_coverage:[]u8,
 _inline_coverage:[CRYPTO_INLINE_COVERAGE_BYTES]u8,
}

// Exact metadata budget; division avoids overflow for arbitrarily large slices.
crypto_reassembly_coverage_size :: proc(storage_bytes:int)->int {
 if storage_bytes<=0 {return 0}
 return storage_bytes/8+int(storage_bytes%8!=0)
}
@(private)
crypto_reassembly_state_bytes :: proc(r:^Crypto_Reassembly)->[]u8 {return (cast([^]u8)r)[:size_of(Crypto_Reassembly)]}
@(private)
crypto_reassembly_coverage :: proc(r:^Crypto_Reassembly)->[]u8 {
 count:=crypto_reassembly_coverage_size(len(r.buf))
 if len(r._external_coverage)>=count&&count>0 {return r._external_coverage[:count]}
 if count>len(r._inline_coverage) {return nil}
 return r._inline_coverage[:count]
}

// A larger window requires explicit caller-owned coverage; no clamp or hidden
// heap allocation occurs. All size/alias validation precedes any owner mutation.
crypto_reassembly_init :: proc(r:^Crypto_Reassembly,storage:[]u8,coverage:[]u8=nil)->Crypto_Error {
 if r==nil||len(storage)>0&&raw_data(storage)==nil||len(coverage)>0&&raw_data(coverage)==nil {return .Invalid_Input}
 need:=crypto_reassembly_coverage_size(len(storage));external:[]u8
 if len(coverage)>0 {
  if len(coverage)<need {return .Coverage_Required};external=coverage[:need]
 } else if need>CRYPTO_INLINE_COVERAGE_BYTES {return .Coverage_Required}
 state:=crypto_reassembly_state_bytes(r)
 if bytes.alias(storage,state)||bytes.alias(external,state)||bytes.alias(storage,external) {return .Invalid_Input}
 r^={};r.buf=storage;r._external_coverage=external
 if len(external)>0 {crypto.zero_explicit(raw_data(external),len(external))}
 return .None
}

crypto_reassembly_discard :: proc(r:^Crypto_Reassembly) {
 if r==nil {return}
 buf,external:=r.buf,r._external_coverage
 if len(buf)>0&&raw_data(buf)!=nil {crypto.zero_explicit(raw_data(buf),len(buf))}
 if len(external)>0&&raw_data(external)!=nil {crypto.zero_explicit(raw_data(external),len(external))}
 r^={};r.buf=buf;r._external_coverage=external;r.discarded=true
}
crypto_reassembly_bytes :: proc(r:^Crypto_Reassembly)->([]u8,Crypto_Error) {
 if r==nil||r.discarded {return nil,.Discarded}
 return r.buf[:r.contiguous],.None
}

// Independent preview storage must not overlap either source plane or owner.
// Default-sized previews own coverage inline; larger previews supply coverage.
crypto_reassembly_clone :: proc(dst,source:^Crypto_Reassembly,storage:[]u8,coverage:[]u8=nil)->Crypto_Error {
 if dst==nil||source==nil {return .Invalid_Input}
 if source.discarded {return .Discarded}
 if len(storage)<len(source.buf) {return .Cap_Overflow}
 need:=crypto_reassembly_coverage_size(len(source.buf));external:[]u8
 if len(coverage)>0 {if len(coverage)<need {return .Coverage_Required};external=coverage[:need]
 } else if need>CRYPTO_INLINE_COVERAGE_BYTES {return .Coverage_Required}
 data:=storage[:len(source.buf)];source_map:=crypto_reassembly_coverage(source)
 if len(source_map)!=need {return .Invalid_Input}
 source_state:=crypto_reassembly_state_bytes(source);target_state:=crypto_reassembly_state_bytes(dst)
 if bytes.alias(source_state,target_state)||bytes.alias(data,source_state)||bytes.alias(external,source_state)||bytes.alias(target_state,source.buf)||bytes.alias(target_state,source_map)||bytes.alias(data,source.buf)||bytes.alias(data,source_map)||bytes.alias(external,source.buf)||bytes.alias(external,source_map) {return .Invalid_Input}
 if e:=crypto_reassembly_init(dst,data,external);e!=.None {return e}
 copy(dst.buf,source.buf);copy(crypto_reassembly_coverage(dst),source_map)
 dst.span_count=source.span_count;dst.contiguous=source.contiguous;dst.received_bytes=source.received_bytes
 return .None
}

@(private)
crypto_coverage_has :: proc(bits:[]u8,offset:int)->bool {return bits[offset/8]&(u8(1)<<uint(offset%8))!=0}

// Identical overlap is idempotent. Validate every overlapping byte before the
// memmove, then update coverage in linear time. Fragment count is not a resource.
crypto_reassembly_write :: proc(r:^Crypto_Reassembly,offset:u64,data:[]u8)->Crypto_Error {
 if r==nil||r.discarded {return .Discarded}
 if offset>u64(len(r.buf))||u64(len(data))>u64(len(r.buf))-offset {crypto_reassembly_discard(r);return .Cap_Overflow}
 if len(data)==0 {return .None}
 bits:=crypto_reassembly_coverage(r)
 if len(bits)!=crypto_reassembly_coverage_size(len(r.buf)) {crypto_reassembly_discard(r);return .Coverage_Required}
 start:=int(offset);end:=start+len(data)
 for position in start..<end {
  if crypto_coverage_has(bits,position)&&r.buf[position]!=data[position-start] {crypto_reassembly_discard(r);return .Overlap_Mismatch}
 }
 copy(r.buf[start:end],data)
 for position in start..<end {
  if crypto_coverage_has(bits,position) {continue}
  left:=position>0&&crypto_coverage_has(bits,position-1)
  right:=position+1<len(r.buf)&&crypto_coverage_has(bits,position+1)
  if left&&right {r.span_count-=1} else if !left&&!right {r.span_count+=1}
  bits[position/8]|=u8(1)<<uint(position%8);r.received_bytes+=1
 }
 for r.contiguous<len(r.buf)&&crypto_coverage_has(bits,r.contiguous) {r.contiguous+=1}
 return .None
}

// One CRYPTO frame at the front of src. data borrows src.
crypto_frame_decode :: proc(src: []u8) -> (offset: u64, data: []u8, consumed: int, err: Error) {
	typ, w, e := varint_decode(src)
	if e != .None {
		return 0, nil, 0, e
	}
	if typ != 6 {
		return 0, nil, 0, .Invalid_Input
	}
	p := w
	offset, w, e = varint_decode(src[p:])
	if e != .None {
		return 0, nil, 0, e
	}
	p += w
	length: u64
	length, w, e = varint_decode(src[p:])
	if e != .None {
		return 0, nil, 0, e
	}
	p += w
	if length > u64(len(src) - p) {
		return 0, nil, 0, .Truncated
	}
	n := int(length)
	return offset, src[p:p + n], p + n, .None
}
