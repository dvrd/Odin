// One accepted connection on the server engine with the Upstream offer: the
// handshake, one read and a fixed answer, then close_notify.
//
//	server <certificate.pem> <key.pem>
package main

import tls "../../../../../../core/crypto/tls"
import credentials "../../../../../../core/crypto/tls/credentials"
import store "../../../../../../core/crypto/tls/credentials/store"
import "core:fmt"
import "core:nbio"
import "core:net"
import "core:os"
import "core:time"

ANSWER :: "served by odin\n"

Session :: struct {
	server:             tls.Server_Async_Conn,
	tcp:                nbio.TCP_Async_Connection,
	handshake:          tls.Server_Async_Handshake_Operation,
	read, write, close: net.Async_Operation,
	input:              [256]u8,
	received:           int,
	established:        bool,
	answered:           bool,
	closed:             bool,
}

session_close :: proc(s: ^Session) {
	s.close = {callback = session_closed, user_data = s}
	submitted := net.async_close(tls.server_async_connection(&s.server), &s.close)
	assert(submitted == nil)
}

session_closed :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	s.closed = true
}

session_written :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	s.answered = op.result.err == nil && op.result.count == len(ANSWER)
	session_close(s)
}

session_read :: proc(op: ^net.Async_Operation) {
	s := cast(^Session)op.user_data
	if op.result.err != nil {
		fmt.eprintf("read failure: %v\n", op.result.err)
		session_close(s)
		return
	}

	s.received = op.result.count
	answer := ANSWER
	s.write = {callback = session_written, user_data = s}
	submitted := net.async_write(tls.server_async_connection(&s.server), &s.write, transmute([]u8)answer, time.time_add(time.now(), 10 * time.Second))
	assert(submitted == nil)
}

session_established :: proc(op: ^tls.Server_Async_Handshake_Operation) {
	s := cast(^Session)op.user_data
	if op.err != nil {
		fmt.eprintf("handshake failure: transport=%v kind=%v engine=%v\n", op.err, op.result.kind, op.result.engine)
		session_close(s)
		return
	}

	s.established = true
	s.read = {callback = session_read, user_data = s}
	submitted := net.async_read(tls.server_async_connection(&s.server), &s.read, s.input[:], time.time_add(time.now(), 10 * time.Second))
	assert(submitted == nil)
}

load_credential :: proc(certificate, key: string) -> ^credentials.Credential {
	chain, chain_error := os.read_entire_file(certificate, context.allocator)
	assert(chain_error == nil)
	defer delete(chain)

	secret, secret_error := os.read_entire_file(key, context.allocator)
	assert(secret_error == nil)
	defer delete(secret)

	result, created := credentials.create(chain, secret, {}, context.allocator)
	assert(created == .None)
	return result
}

main :: proc() {
	assert(len(os.args) == 3)

	credential := load_credential(os.args[1], os.args[2])
	held, store_error := store.create({}, context.allocator)
	assert(store_error.kind == .None)
	defer store.destroy(&held)
	replaced := store.replace(held, &credential)
	assert(replaced.kind == .None)

	listener, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	assert(listen_error == nil)
	defer net.close(listener)
	bound, bound_error := net.bound_endpoint(listener)
	assert(bound_error == nil)
	fmt.printf("READY 127.0.0.1:%d\n", bound.port)

	loop_error := nbio.acquire_thread_event_loop()
	assert(loop_error == nil)
	defer nbio.release_thread_event_loop()

	s := new(Session)
	defer free(s)
	socket, _, accept_error := net.accept_tcp(listener)
	assert(accept_error == nil)
	init_error := nbio.tcp_async_connection_init(&s.tcp, socket)
	assert(init_error == nil)

	config := tls.Server_Async_Config{store = held, credential_time = time.now()}
	config.handshake = tls.SERVER_HANDSHAKE_DEFAULT_CONFIG
	config.handshake.offer = .Upstream
	started := tls.server_async_server(&s.server, nbio.tcp_async_connection(&s.tcp), nbio.async_executor(), config, context.allocator)
	assert(started == nil)

	s.handshake = {callback = session_established, user_data = s}
	submitted := tls.server_async_handshake(&s.server, &s.handshake)
	assert(submitted == nil)

	run_error := nbio.run()
	assert(run_error == nil)

	fmt.printf("DONE established=%v answered=%v closed=%v received=%d\n", s.established, s.answered, s.closed, s.received)
	if !s.established || !s.answered || !s.closed {
		os.exit(1)
	}
}
