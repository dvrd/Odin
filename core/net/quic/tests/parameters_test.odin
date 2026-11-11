package tests

import "core:net/quic"
import "core:testing"

@(private)
tp_put :: proc(dst:[]u8,at:^int,id:u64,value:[]u8) {
 n,e:=quic.varint_encode(dst[at^:],id);assert(e==.None);at^+=n
 n,e=quic.varint_encode(dst[at^:],u64(len(value)));assert(e==.None);at^+=n
 at^+=copy(dst[at^:],value)
}
@(private)
tp_source:=[?]u8{1,2,3,4,5,6,7,8}
@(private)
tp_original:=[?]u8{9,9,9,9,9,9,9,9}
@(private)
tp_context :: proc(sender:quic.Role)->quic.Transport_Parameter_Context {return {sender=sender,initial_source_id=tp_source[:],original_destination_id=tp_original[:]}}
@(private)
tp_base :: proc(dst:[]u8,ctx:quic.Transport_Parameter_Context)->int {at:=0;if ctx.sender==.Server {tp_put(dst,&at,0,ctx.original_destination_id)};tp_put(dst,&at,0x0f,ctx.initial_source_id);return at}

@(test)
transport_parameters_require_cid_presence_role_and_retry_binding :: proc(t:^testing.T) {
 for role in ([]quic.Role{.Client,.Server}) {
  ctx:=tp_context(role);bytes:[1024]u8;n:=tp_base(bytes[:],ctx)
  testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.None)
  testing.expect_value(t,quic.transport_parameters_validate(nil,ctx),.Missing)
  bytes[n-1]~=1;testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.CID_Mismatch)
 }
 ctx:=tp_context(.Server);ctx.retry_used=true;ctx.retry_source_id=[]u8{3,4,5}
 bytes:[1024]u8;n:=tp_base(bytes[:],ctx)
 testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Missing)
 tp_put(bytes[:],&n,0x10,ctx.retry_source_id);testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.None)
 bytes[n-1]~=1;testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.CID_Mismatch)
 ctx.retry_used=false;testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Role)
 for id in ([]u64{0,2,0x0d,0x10}) {
  client:=tp_context(.Client);n=tp_base(bytes[:],client);tp_put(bytes[:],&n,id,nil)
  testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],client),.Role)
 }
}

@(test)
transport_parameters_duplicate_unknown_and_nonminimal_ids_are_rejected :: proc(t:^testing.T) {
 ctx:=tp_context(.Client);bytes:[1024]u8;n:=tp_base(bytes[:],ctx)
 tp_put(bytes[:],&n,27,[]u8{1,2,3});testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.None)
 // Alternate-width encodings still identify the same parameter.
 bytes[n]=0x40;bytes[n+1]=27;bytes[n+2]=0;n+=3
 testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Duplicate)
 n=tp_base(bytes[:],ctx);tp_put(bytes[:],&n,0x0f,ctx.initial_source_id)
 testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Duplicate)
}

@(test)
transport_parameters_full_numeric_consumption_and_defined_ranges :: proc(t:^testing.T) {
 ctx:=tp_context(.Client);bytes:[1024]u8;value:[8]u8
 for id in ([]u64{1,3,4,5,6,7,8,9,0x0a,0x0b,0x0e}) {
  for invalid in ([][]u8{nil,[]u8{0x40},[]u8{0,0}}) {
   n:=tp_base(bytes[:],ctx);tp_put(bytes[:],&n,id,invalid)
   testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Malformed)
  }
 }
 cases:=[][3]u64{{3,1199,1200},{8,(u64(1)<<60)+1,u64(1)<<60},{9,(u64(1)<<60)+1,u64(1)<<60},{0x0a,21,20},{0x0b,u64(1)<<14,(u64(1)<<14)-1},{0x0e,1,2}}
 for item in cases {
  n:=tp_base(bytes[:],ctx);vn,e:=quic.varint_encode(value[:],item[1]);assert(e==.None);tp_put(bytes[:],&n,item[0],value[:vn])
  testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Range)
  n=tp_base(bytes[:],ctx);vn,e=quic.varint_encode(value[:],item[2]);assert(e==.None);tp_put(bytes[:],&n,item[0],value[:vn])
  testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.None)
 }
}

@(test)
transport_parameters_malformed_bounds_and_unknown_capacity :: proc(t:^testing.T) {
 ctx:=tp_context(.Client)
 for bytes in ([][]u8{[]u8{0x0f},[]u8{0x0f,0x40},[]u8{0x0f,0xff,255,255,255,255,255,255,255},[]u8{0x0f,8,1}}) {
  testing.expect_value(t,quic.transport_parameters_validate(bytes,ctx),.Malformed)
 }
 oversized:[quic.TRANSPORT_PARAMETERS_MAX+1]u8
 testing.expect_value(t,quic.transport_parameters_validate(oversized[:],ctx),.Limit)
 // A dense unknown-parameter flight has bounded work and no allocation.
 bytes:[quic.TRANSPORT_PARAMETERS_MAX]u8;n:=tp_base(bytes[:],ctx)
 for id in 128..<380 {tp_put(bytes[:],&n,u64(id),nil)}
 testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.None)
}

@(test)
transport_parameters_fixed_fields_zero_cid_and_preferred_address :: proc(t:^testing.T) {
 ctx:=tp_context(.Server);bytes:[1024]u8;n:=tp_base(bytes[:],ctx)
 tp_put(bytes[:],&n,0x0c,[]u8{0});testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Malformed)
 token:[16]u8;n=tp_base(bytes[:],ctx);tp_put(bytes[:],&n,2,token[:15]);testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Range)
 n=tp_base(bytes[:],ctx);tp_put(bytes[:],&n,2,token[:]);testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.None)
 preferred:[42]u8;preferred[24]=1;preferred[25]=42
 n=tp_base(bytes[:],ctx);tp_put(bytes[:],&n,0x0d,preferred[:]);testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.None)
 preferred[24]=0;n=tp_base(bytes[:],ctx);tp_put(bytes[:],&n,0x0d,preferred[:]);testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Malformed)
 ctx.initial_source_id=nil;n=tp_base(bytes[:],ctx)
 testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.None)
 tp_put(bytes[:],&n,2,token[:]);testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.Range)
}

@(test)
transport_parameters_preferred_cid_and_reset_token_are_distinct_order_independently :: proc(t:^testing.T) {
 ctx:=tp_context(.Server);bytes:[1024]u8;preferred:[49]u8;preferred[24]=8
 copy(preferred[25:],ctx.initial_source_id)
 n:=tp_base(bytes[:],ctx);tp_put(bytes[:],&n,0x0d,preferred[:])
 testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.CID_Mismatch)
 preferred[25]~=1;token:=[16]u8{0=42};copy(preferred[33:],token[:])
 for pref_first in ([]bool{false,true}) {
  n=tp_base(bytes[:],ctx)
  if pref_first {tp_put(bytes[:],&n,0x0d,preferred[:]);tp_put(bytes[:],&n,2,token[:])} else {tp_put(bytes[:],&n,2,token[:]);tp_put(bytes[:],&n,0x0d,preferred[:])}
  testing.expect_value(t,quic.transport_parameters_validate(bytes[:n],ctx),.CID_Mismatch)
 }
}
