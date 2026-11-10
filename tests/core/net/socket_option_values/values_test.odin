#+build darwin, linux, windows
package socket_option_values

import "core:net"
import "core:testing"

owned_socket :: proc()->net.TCP_Socket {
	socket,error:=net.create_socket(.IP4,.TCP);assert(error==nil)
	tcp,valid:=socket.(net.TCP_Socket);assert(valid)
	assert(net.bind(tcp,{net.IP4_Loopback,0})==nil)
	return tcp
}

// Use a distinct direct-syscall control so OS clamping remains part of the
// oracle. The control payload is a stable i32, never an Odin any container.
@(test)
public_i32_buffer_value_matches_independent_kernel_control :: proc(t:^testing.T) {
	for option in ([2]net.Socket_Option{.Send_Buffer_Size,.Receive_Buffer_Size}) {
		actual:=owned_socket();defer net.close(actual)
		control:=owned_socket();defer net.close(control)
		requested:=i32(4096)
		native_ok:=kernel_set(control,option,requested)
		testing.expect(t,native_ok)
		public_error:=net.set_option(actual,option,requested)
		testing.expect_value(t,public_error,nil)
		expected,expected_ok:=kernel_get(control,option)
		observed,observed_ok:=kernel_get(actual,option)
		testing.expect(t,expected_ok && observed_ok)
		testing.expect_value(t,observed,expected)
	}
}

Value_Case :: struct {name:string,value:any,native:i32}

compare_value :: proc(t:^testing.T,option:net.Socket_Option,vector:Value_Case) {
	actual:=owned_socket();defer net.close(actual)
	control:=owned_socket();defer net.close(control)
	native_ok:=kernel_set(control,option,vector.native)
	public_error:=net.set_option(actual,option,vector.value)
	testing.expect_value(t,public_error==nil,native_ok)
	// Preserve the backend's existing value conversion and OS rejection/clamp
	// policy, rather than imposing a new portable range policy in these tests.
	if !native_ok || public_error!=nil do return
	expected,expected_ok:=kernel_get(control,option)
	observed,observed_ok:=kernel_get(actual,option)
	testing.expect(t,expected_ok && observed_ok,vector.name)
	testing.expect_value(t,observed,expected)
}

@(test)
public_buffer_options_cover_all_integer_payload_representations :: proc(t:^testing.T) {
	vectors:=[12]Value_Case{
		{"i8",i8(64),64},{"u8",u8(128),128},
		{"i16",i16(4096),4096},{"u16",u16(8192),8192},
		{"i32",i32(4096),4096},{"u32",u32(8192),8192},
		{"i64",i64(4096),4096},{"u64",u64(8192),8192},
		{"i128",i128(4096),4096},{"u128",u128(8192),8192},
		{"int",int(4096),4096},{"uint",uint(8192),8192},
	}
	for option in ([2]net.Socket_Option{.Send_Buffer_Size,.Receive_Buffer_Size}) {
		for vector in vectors do compare_value(t,option,vector)
	}
}

@(test)
public_buffer_options_preserve_unsigned_views_and_native_width_truncation :: proc(t:^testing.T) {
	vectors:=[16]Value_Case{
		{"negative-i8",i8(-1),255},{"negative-i16",i16(-1),65535},
		{"negative-i32",i32(-1),-1},{"negative-i64",i64(-1),-1},
		{"negative-i128",i128(-1),-1},{"negative-int",int(-1),-1},
		{"upper-u8",max(u8),255},{"upper-u16",max(u16),65535},
		{"upper-u32",max(u32),-1},{"upper-u64",max(u64),-1},
		{"upper-u128",max(u128),-1},{"upper-uint",max(uint),-1},
		{"truncated-i64",i64(1)<<40 | 4096,4096},
		{"truncated-u64",u64(1)<<40 | 4096,4096},
		{"truncated-i128",i128(1)<<100 | 4096,4096},
		{"truncated-u128",u128(1)<<100 | 4096,4096},
	}
	for option in ([2]net.Socket_Option{.Send_Buffer_Size,.Receive_Buffer_Size}) {
		for vector in vectors do compare_value(t,option,vector)
	}
}

@(test)
public_boolean_options_cover_false_true_in_every_supported_representation :: proc(t:^testing.T) {
	vectors:=[10]Value_Case{
		{"bool-false",false,0},{"bool-true",true,1},
		{"b8-false",b8(false),0},{"b8-true",b8(true),1},
		{"b16-false",b16(false),0},{"b16-true",b16(true),1},
		{"b32-false",b32(false),0},{"b32-true",b32(true),1},
		{"b64-false",b64(false),0},{"b64-true",b64(true),1},
	}
	for option in ([5]net.Socket_Option{.Reuse_Address,.TCP_Nodelay,.Keep_Alive,
		.Out_Of_Bounds_Data_Inline,.Broadcast}) {
		for vector in vectors do compare_value(t,option,vector)
	}
}

socket_option_rvalue :: proc()->i32 {return 4096}

@(test)
public_options_accept_runtime_any_reassignment_and_rvalue_storage :: proc(t:^testing.T) {
	actual:=owned_socket();defer net.close(actual)
	control:=owned_socket();defer net.close(control)
	testing.expect(t,kernel_set(control,.Send_Buffer_Size,4096))
	testing.expect_value(t,net.set_option(actual,.Send_Buffer_Size,socket_option_rvalue()),nil)
	expected,expected_ok:=kernel_get(control,.Send_Buffer_Size)
	observed,observed_ok:=kernel_get(actual,.Send_Buffer_Size)
	testing.expect(t,expected_ok && observed_ok)
	testing.expect_value(t,observed,expected)
	payload:any=i32(4096)
	for index in 0..<4 {
		native:=i32(4096)
		switch index {
		case 0:payload=i64(4096)
		case 1:payload=u128(8192);native=8192
		case 2:payload=i16(4096)
		case 3:payload=u32(8192);native=8192
		}
		compare_value(t,.Send_Buffer_Size,{"runtime-any",payload,native})
	}
}
