package quic

// Matches the bounded TLS QUIC-extension profile. No allocation or retained
// slices: the binding validates before publishing any parameter side effects.
TRANSPORT_PARAMETERS_MAX :: 1024
Transport_Parameter_Error :: enum {None,Malformed,Duplicate,Role,Missing,CID_Mismatch,Range,Limit,Invalid_Context}
Transport_Parameter_Context :: struct {
 sender:Role,
 initial_source_id,original_destination_id,retry_source_id:[]u8,
 retry_used:bool,
}

transport_parameters_validate :: proc(src:[]u8,ctx:Transport_Parameter_Context)->Transport_Parameter_Error {
 if ctx.sender!=.Client&&ctx.sender!=.Server||len(ctx.initial_source_id)>20||len(ctx.original_destination_id)>20||len(ctx.retry_source_id)>20||ctx.sender==.Server&&len(ctx.original_destination_id)<8||ctx.sender==.Server&&ctx.retry_used&&len(ctx.retry_source_id)==0 {return .Invalid_Context}
 if len(src)>TRANSPORT_PARAMETERS_MAX {return .Limit}
 seen:[TRANSPORT_PARAMETERS_MAX/2]u64;count:=0;at:=0
 have_source,have_original,have_retry:=false,false,false
 preferred_id,preferred_token,reset_token:[]u8
 for at<len(src) {
  id,in_n,ie:=varint_decode(src[at:]);if ie!=.None {return .Malformed};at+=in_n
  size,sn,se:=varint_decode(src[at:]);if se!=.None {return .Malformed};at+=sn
  if size>u64(len(src)-at) {return .Malformed}
  if count==len(seen) {return .Limit}
  for previous in seen[:count] {if previous==id {return .Duplicate}};seen[count]=id;count+=1
  value:=src[at:at+int(size)];at+=int(size)
  if ctx.sender==.Client&&(id==0||id==2||id==0x0d||id==0x10) {return .Role}
  switch id {
  case 0:
   if len(value)>20 {return .Range};if string(value)!=string(ctx.original_destination_id) {return .CID_Mismatch};have_original=true
  case 0x0f:
   if len(value)>20 {return .Range};if string(value)!=string(ctx.initial_source_id) {return .CID_Mismatch};have_source=true
  case 0x10:
   if !ctx.retry_used {return .Role};if len(value)>20 {return .Range};if string(value)!=string(ctx.retry_source_id) {return .CID_Mismatch};have_retry=true
  case 2:
   if len(value)!=16||len(ctx.initial_source_id)==0 {return .Range};reset_token=value
  case 0x0c:
   if len(value)!=0 {return .Malformed}
  case 0x0d:
   if len(ctx.initial_source_id)==0||len(value)<42 {return .Range}
   n:=int(value[24]);if n<1||n>20||len(value)!=41+n {return .Malformed};preferred_id=value[25:25+n];preferred_token=value[25+n:]
  case 1,3,4,5,6,7,8,9,0x0a,0x0b,0x0e:
   integer,n,e:=varint_decode(value);if e!=.None||n!=len(value) {return .Malformed}
   if id==3&&integer<1200||id==8&&integer>u64(1)<<60||id==9&&integer>u64(1)<<60||id==0x0a&&integer>20||id==0x0b&&integer>=u64(1)<<14||id==0x0e&&integer<2 {return .Range}
  }
 }
 if len(preferred_id)>0&&(string(preferred_id)==string(ctx.initial_source_id)||len(reset_token)>0&&string(preferred_token)==string(reset_token)) {return .CID_Mismatch}
 if !have_source||ctx.sender==.Server&&(!have_original||ctx.retry_used&&!have_retry) {return .Missing}
 return .None
}
