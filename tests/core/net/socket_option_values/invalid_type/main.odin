#+build darwin, linux, windows
package main

import "core:net"
import "core:os"
import "core:time"

main :: proc() {
	assert(len(os.args) == 2)
	socket, error := net.create_socket(.IP4, .TCP)
	assert(error == nil)
	// This isolated process deliberately traps; the OS closes its socket at exit.
	switch os.args[1] {
	case "buffer-string":
		net.set_option(socket, .Send_Buffer_Size, "4096")
	case "buffer-float":
		net.set_option(socket, .Send_Buffer_Size, f64(4096))
	case "buffer-duration":
		net.set_option(socket, .Send_Buffer_Size, time.Duration(4096))
	case "buffer-nil":
		value: any
		net.set_option(socket, .Receive_Buffer_Size, value)
	case "boolean-integer":
		net.set_option(socket, .Reuse_Address, i32(1))
	case "timeout-integer":
		net.set_option(socket, .Send_Timeout, i64(1000))
	case "linger-integer":
		net.set_option(socket, .Linger, i64(1000))
	case:
		panic("unknown test mode")
	}
	net.close(socket)
	panic("invalid type unexpectedly returned instead of preserving the API panic")
}
