#+build darwin, linux
package net

@(require) import posix "core:sys/posix"
@(require) import "core:sys/linux"

when ODIN_OS==.Linux {ECN_Length :: uint} else {ECN_Length :: u32}
@(private)
ECN_Control :: struct {length:ECN_Length, level,kind:i32}
@(private)
ecn_align :: proc(n:int)->int {a:=4;when ODIN_OS==.Linux {a=size_of(uint)};return (n+a-1)&~(a-1)}
@(private)
ecn_options :: proc(family:Address_Family)->(i32,i32,i32) {
 if family==.IP6 {when ODIN_OS==.Linux {return 41,66,67} else {return 41,35,36}}
 when ODIN_OS==.Linux {return 0,13,1} else {return 0,27,3}
}
@(private)
_udp_enable_ecn :: proc(socket:UDP_Socket,family:Address_Family)->bool {
 if family!=.IP4 && family!=.IP6 {return false}
 level,option,_:=ecn_options(family);value:i32=1
 when ODIN_OS==.Linux {return linux.setsockopt_base(linux.Fd(socket),int(level),int(option),&value)==.NONE}
 else {return posix.setsockopt(posix.FD(socket),level,posix.Sock_Option(option),&value,size_of(value))==.OK}
}
@(private)
ecn_control_parse :: proc(control:[]u8,truncated:bool)->UDP_Metadata {
 result:=UDP_Metadata{control_truncated=truncated};if truncated {return result}
 at:=0;head:=ecn_align(size_of(ECN_Control));rx4:i32=27;rx6:i32=36
 when ODIN_OS==.Linux {rx4=1;rx6=67}
 for len(control)-at>=size_of(ECN_Control) {
  // recvmsg provides aligned storage. Copy bytes as malformed-input tests may not.
  header:ECN_Control;copy(([^]u8)(&header)[:size_of(header)],control[at:][:size_of(header)])
  n:=int(header.length);if n<head || n>len(control)-at {return {}}
  if (header.level==0 && header.kind==rx4) || (header.level==41 && header.kind==rx6) {
   value:i32
   if header.level==0 {if n-head<1 {return {}};value=i32(control[at+head])}
   else {if n-head<size_of(value) {return {}};copy(([^]u8)(&value)[:size_of(value)],control[at+head:][:size_of(value)])}
   if result.ecn_valid || value<0 || value>255 {return {}}
   result.ecn=ECN_Codepoint(value&3);result.ecn_valid=true
  }
  step:=ecn_align(n);if step>len(control)-at {break};at+=step
 }
 return result
}
@(private)
_recv_udp_metadata :: proc(socket:UDP_Socket,dst:[]u8)->(int,Endpoint,UDP_Metadata,UDP_Recv_Error) {
 if len(dst)==0 {return 0,{},{},.Invalid_Argument}
 control:[16]u64
 when ODIN_OS==.Linux {
  from:linux.Sock_Addr_Any;iov:=[1]linux.IO_Vec{{base=raw_data(dst),len=len(dst)}}
  message:=linux.Msg_Hdr{name=&from,namelen=size_of(from),iov=iov[:],control=(cast([^]u8)(&control))[:size_of(control)]}
  n,e:=linux.recvmsg(linux.Fd(socket),&message,{})
  if e!=.NONE {return 0,{},{},_udp_recv_error(e)}
  metadata:=ecn_control_parse(message.control,.CTRUNC in message.flags)
  if .TRUNC in message.flags {return min(n,len(dst)),ecn_wrap_linux_address(from),metadata,.Excess_Truncated}
  return n,ecn_wrap_linux_address(from),metadata,nil
 } else {
  from:posix.sockaddr_storage;iov:=posix.iovec{iov_base=raw_data(dst),iov_len=uint(len(dst))}
  message:=posix.msghdr{msg_name=&from,msg_namelen=size_of(from),msg_iov=&iov,msg_iovlen=1,msg_control=&control,msg_controllen=size_of(control)}
  n:=posix.recvmsg(posix.FD(socket),&message,{})
  if n<0 {return 0,{},{},_udp_recv_error()}
  metadata:=ecn_control_parse((cast([^]u8)(&control))[:int(message.msg_controllen)],.CTRUNC in message.msg_flags)
  if .TRUNC in message.msg_flags {return int(n),_sockaddr_to_endpoint(&from),metadata,.Excess_Truncated}
  return int(n),_sockaddr_to_endpoint(&from),metadata,nil
 }
}
@(private)
_send_udp_ecn :: proc(socket:UDP_Socket,src:[]u8,to:Endpoint,ecn:ECN_Codepoint)->(int,UDP_Send_Error) {
 if u8(ecn)>3 || to.address==nil {return 0,.Invalid_Argument}
 family:=family_from_endpoint(to);level,_,kind:=ecn_options(family)
 control:[4]u64;head:=ecn_align(size_of(ECN_Control));length:=head+size_of(i32)
 header:=cast(^ECN_Control)(&control);header.length=type_of(header.length)(length);header.level=level;header.kind=kind
 value:=cast(^i32)(uintptr(&control)+uintptr(head));value^=i32(ecn)
 when ODIN_OS==.Linux {
  address:=_unwrap_os_addr(to);iov:=[1]linux.IO_Vec{{base=raw_data(src),len=len(src)}}
  message:=linux.Msg_Hdr{name=&address,namelen=16,iov=iov[:],control=(cast([^]u8)(&control))[:ecn_align(length)]}
  if family==.IP6 {message.namelen=28}
  n,e:=linux.sendmsg(linux.Fd(socket),&message,{})
  if e!=.NONE {return n,_udp_send_error(e)};return n,nil
 } else {
  address:=_endpoint_to_sockaddr(to);iov:=posix.iovec{iov_base=raw_data(src),iov_len=uint(len(src))}
  message:=posix.msghdr{msg_name=&address,msg_namelen=posix.socklen_t(address.ss_len),msg_iov=&iov,msg_iovlen=1,msg_control=&control,msg_controllen=posix.socklen_t(ecn_align(length))}
  n:=posix.sendmsg(posix.FD(socket),&message,{})
  if n<0 {return 0,_udp_send_error()};return int(n),nil
 }
}

when ODIN_OS==.Linux {
 @(private)
 ecn_wrap_linux_address :: proc(addr:linux.Sock_Addr_Any)->Endpoint {
  #partial switch addr.family {
  case .INET:return {IP4_Address(addr.sin_addr),int(addr.sin_port)}
  case .INET6:return {transmute(IP6_Address)addr.sin6_addr,int(addr.sin6_port)}
  }
  return {}
 }
}
