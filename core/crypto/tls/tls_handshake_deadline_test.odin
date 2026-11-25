package tls

import "core:net"
import "core:testing"
import "core:time"

Deadline_Test_Transport :: struct {
	first: time.Time,
	delay: time.Duration,
	writes: int,
}
deadline_test_set :: proc(data: rawptr, deadline: time.Time) -> net.Network_Error {
	s := cast(^Deadline_Test_Transport)data
	if deadline != (time.Time{}) && s.first == (time.Time{}) {
		s.first = deadline
		if s.delay > 0 {time.sleep(s.delay)}
	}
	return {}
}
deadline_test_close :: proc(data: rawptr) -> net.Network_Error {return {}}
deadline_test_read :: proc(data: rawptr, dst: []u8) -> (int, net.Network_Error) {return 0,net.Connection_Error.Peer_Closed}
deadline_test_write :: proc(data: rawptr, src: []u8) -> (int, net.Network_Error) {
	s := cast(^Deadline_Test_Transport)data
	s.writes += 1
	return 0,net.Connection_Error.Peer_Closed
}
deadline_test_conn :: proc(state: ^Deadline_Test_Transport) -> Conn {
	return {
		phase=.Handshake_Pending,
		config={server_name="fixture.invalid"},
		transport={data=state,read=deadline_test_read,write=deadline_test_write,close=deadline_test_close,set_read_deadline=deadline_test_set,set_write_deadline=deadline_test_set},
	}
}

@(test)
handshake_absolute_deadline_is_not_rebased :: proc(t: ^testing.T) {
	state: Deadline_Test_Transport
	conn := deadline_test_conn(&state)
	deadline := time.time_add(time.now(),time.Second)
	error := engine_handshake_until(&conn,deadline)
	testing.expect(t,error.kind != .None)
	testing.expect_value(t,state.first,deadline)
	testing.expect_value(t,state.writes,1)
}

@(test)
handshake_configured_limit_still_caps_absolute_budget :: proc(t: ^testing.T) {
	state: Deadline_Test_Transport
	conn := deadline_test_conn(&state)
	conn.config.handshake_timeout=time.Millisecond*20
	start := time.now()
	_ = engine_handshake_until(&conn,time.time_add(start,time.Second))
	testing.expect(t,time.diff(start,state.first) >= 20*time.Millisecond)
	testing.expect(t,time.diff(start,state.first) < 100*time.Millisecond)
}

@(test)
handshake_slow_deadline_callback_cannot_start_io_after_expiry :: proc(t: ^testing.T) {
	state := Deadline_Test_Transport{delay=20*time.Millisecond}
	conn := deadline_test_conn(&state)
	error := engine_handshake_until(&conn,time.time_add(time.now(),time.Millisecond))
	testing.expect_value(t,error.kind,.Deadline_Failed)
	testing.expect_value(t,error.transport,net.Network_Error(net.TCP_Recv_Error.Timeout))
	testing.expect_value(t,state.writes,0)
}

@(test)
handshake_until_requires_bounded_transport_and_preserves_old_signature :: proc(t: ^testing.T) {
	state: Deadline_Test_Transport
	conn := deadline_test_conn(&state)
	conn.transport.set_read_deadline=nil
	conn.transport.set_write_deadline=nil
	error := engine_handshake_until(&conn,time.time_add(time.now(),time.Second))
	testing.expect_value(t,error.transport,net.Network_Error(net.Connection_Error.Deadline_Unsupported))
	testing.expect_value(t,state.writes,0)
	conn=deadline_test_conn(&state)
	conn.transport.set_read_deadline=nil
	conn.transport.set_write_deadline=nil
	error=engine_handshake_until(&conn,{})
	testing.expect(t,error.kind != .None && state.writes == 1)
}

@(test)
handshake_until_expired_terminal_success_cannot_expose_application_state :: proc(t: ^testing.T) {
	conn := Conn{phase=.Established,handshake_complete=true}
	error := engine_handshake_until(&conn,time.time_add(time.now(),-time.Second))
	testing.expect_value(t,error.kind,.Deadline_Failed)
	testing.expect_value(t,conn.phase,.Failed)
	testing.expect(t,!conn.handshake_complete)
}
