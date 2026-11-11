#+build darwin, linux
package net

@(require) import "core:sys/posix"
@(require) import "core:sys/linux"

when ODIN_OS==.Linux {UDP_Fragmentation_Length :: u32} else {UDP_Fragmentation_Length :: posix.socklen_t}

@(private)
udp_fragmentation_failure :: proc(cause:i32)->UDP_Fragmentation_Result {
 unsupported:=false
 when ODIN_OS==.Linux {unsupported=cause==i32(linux.Errno.ENOPROTOOPT)||cause==i32(linux.Errno.EOPNOTSUPP)}
 else {unsupported=cause==i32(posix.ENOPROTOOPT)||cause==i32(posix.EOPNOTSUPP)}
 status:=UDP_Fragmentation_Status.Failed
 if unsupported {status=.Unsupported}
 return {status=status,native_error=cause}
}
@(private)
udp_fragmentation_get :: proc(socket:UDP_Socket,level,option:i32)->(i32,i32) {
 value:i32;length:=UDP_Fragmentation_Length(size_of(value))
 when ODIN_OS==.Linux {
  result:=linux.syscall(linux.SYS_getsockopt,linux.Fd(socket),level,option,&value,&length)
  if result<0 {return 0,i32(-result)}
 } else {
  if posix.getsockopt(posix.FD(socket),level,posix.Sock_Option(option),&value,&length)!=.OK {return 0,i32(posix.errno())}
 }
 if length!=size_of(value) {return 0,-1}
 return value,0
}
@(private)
udp_fragmentation_set :: proc(socket:UDP_Socket,level,option,value:i32)->i32 {
 native_value:=value
 when ODIN_OS==.Linux {return i32(linux.setsockopt_base(linux.Fd(socket),int(level),int(option),&native_value))}
 else {
  if posix.setsockopt(posix.FD(socket),level,posix.Sock_Option(option),&native_value,size_of(native_value))!=.OK {return i32(posix.errno())}
  return 0
 }
}
@(private)
_udp_fragmentation_policy :: proc(socket:UDP_Socket,family:Address_Family,configure:bool)->UDP_Fragmentation_Result {
 if family!=.IP4&&family!=.IP6 {return {status=.Invalid_Family}}
 socket_level:i32=0xffff;type_option:i32=0x1008;v6only_option:i32=27
 when ODIN_OS==.Linux {socket_level=1;type_option=3;v6only_option=26}
 kind,cause:=udp_fragmentation_get(socket,socket_level,type_option)
 if cause!=0 {return udp_fragmentation_failure(cause)}
 if kind!=2 {return {status=.Invalid_Socket}}
 endpoint,endpoint_error:=bound_endpoint(socket)
 if endpoint_error!=.None {return {status=.Failed}}
 if family_from_endpoint(endpoint)!=family {return {status=.Invalid_Family}}
 result:=UDP_Fragmentation_Result{status=.Not_Configured}
 if family==.IP6 {
  only,only_error:=udp_fragmentation_get(socket,41,v6only_option)
  if only_error!=0 {return udp_fragmentation_failure(only_error)}
  result.dual_stack=only==0
 }
 if family==.IP4 {
  option:i32=28;expected:i32=1
  when ODIN_OS==.Linux {option=10;expected=2} // IP_MTU_DISCOVER = IP_PMTUDISC_DO
  if configure {if e:=udp_fragmentation_set(socket,0,option,expected);e!=0 {return udp_fragmentation_failure(e)}}
  value,e:=udp_fragmentation_get(socket,0,option)
  if e!=0 {return udp_fragmentation_failure(e)}
  result.ipv4=value==expected
 } else {
  option:i32=62;expected:i32=1
  when ODIN_OS==.Linux {option=23;expected=2} // IPV6_MTU_DISCOVER = IPV6_PMTUDISC_DO
  if configure {if e:=udp_fragmentation_set(socket,41,option,expected);e!=0 {return udp_fragmentation_failure(e)}}
  value,e:=udp_fragmentation_get(socket,41,option)
  if e!=0 {return udp_fragmentation_failure(e)}
  result.ipv6=value==expected
  if result.dual_stack {
   when ODIN_OS==.Linux {
    if configure {if e4:=udp_fragmentation_set(socket,0,10,2);e4!=0 {return udp_fragmentation_failure(e4)}}
    value4,e4:=udp_fragmentation_get(socket,0,10)
    if e4!=0 {return udp_fragmentation_failure(e4)}
    result.ipv4=value4==2
   } else {
    // XNU IPV6_DONTFRAG also sets INP2_DONTFRAG for IPv4-mapped output;
    // IP_DONTFRAG itself is rejected on AF_INET6. Preserve dual-stack policy.
    result.ipv4=result.ipv6
   }
  }
 }
 if (family==.IP4&&result.ipv4)||(family==.IP6&&result.ipv6&&(!result.dual_stack||result.ipv4)) {result.status=.Configured}
 return result
}
