package tls

import "core:mem"
import "core:net"
import "core:testing"
import "core:time"

idle_test_submit :: proc(_:rawptr,_:^net.Async_Operation,_:net.Async_Operation_Kind,_:[]u8,_:time.Time)->net.Connection_Error {panic("classification performed IO")}
idle_test_cancel :: proc(_:rawptr,_:^net.Async_Operation)->net.Connection_Error {panic("classification cancelled IO")}
idle_test_schedule :: proc(_:rawptr,_:proc(rawptr),_:rawptr) {panic("classification scheduled work")}
// A local-state fixture, not a claim that a cryptographic handshake occurred.
idle_test_ready :: proc()->Async_Conn {
 result:Async_Conn
 result.initialized=true
 result.transport={submit=idle_test_submit,cancel=idle_test_cancel}
 result.executor={schedule=idle_test_schedule}
 result.protocol.phase=.Established
 result.protocol.handshake_complete=true
 result.protocol.application.initialized=true
 record_protection_init(&result.protocol.application.send,[16]u8{},[12]u8{})
 record_protection_init(&result.protocol.application.receive,[16]u8{},[12]u8{})
 return result
}
idle_test_expect :: proc(t:^testing.T,c:^Async_Conn,want:Async_Idle_State) {
 before:=c^
 previous:=context
 context.allocator,context.temp_allocator=mem.panic_allocator(),mem.panic_allocator()
 actual:=async_idle_state(c)
 context=previous
 testing.expect_value(t,actual,want)
 testing.expect_value(t,mem.compare(mem.byte_slice(c,size_of(c^)),mem.byte_slice(&before,size_of(before))),0)
}

@(test)
async_idle_local_ready_is_pure_and_ignores_consumed_history :: proc(t:^testing.T) {
 c:=idle_test_ready()
 idle_test_expect(t,&c,.Ready)
 c.finishing=true;c.flight_used=37;c.tx_size=87;c.tx_plain_count=19
 c.read_cancel=true;c.write_cancel=true
 c.read_deadline={_nsec=9};c.write_deadline={_nsec=17}
 c.rx.result={count=5,err={kind=.Cancelled}}
 c.tx.result={count=7};c.shutdown.result={err={kind=.Timeout}}
 c.protocol.application.inbound_at=13;c.protocol.application.inbound_size=13
 c.rx_wire[0]=91;c.rx_plain[0]=73;c.tx_wire[0]=37
 idle_test_expect(t,&c,.Ready)
}

@(test)
async_idle_invalid_local_shapes_and_unauthenticated_state_fail_closed :: proc(t:^testing.T) {
 testing.expect_value(t,async_idle_state(nil),.Invalid)
 zero:Async_Conn;idle_test_expect(t,&zero,.Invalid)
 c:=idle_test_ready()
 c.transport.submit=nil;idle_test_expect(t,&c,.Invalid)
 c=idle_test_ready();c.executor.schedule=nil;idle_test_expect(t,&c,.Invalid)
 c=idle_test_ready();c.protocol.handshake_complete=false;idle_test_expect(t,&c,.Invalid)
 c=idle_test_ready();c.protocol.application.initialized=false;idle_test_expect(t,&c,.Invalid)
 c=idle_test_ready();c.protocol.application.receive.initialized=false;idle_test_expect(t,&c,.Invalid)
 for field in 0..<7 {
  c=idle_test_ready()
  switch field {
  case 0:c.rx_used=-1
  case 1:c.rx_expected=len(c.rx_wire)+1
  case 2:c.tx_size=len(c.tx_wire)+1
  case 3:c.protocol.application.inbound_at=1
  case 4:c.protocol.application.inbound_size=len(c.protocol.application.inbound)+1
  case 5:c.protocol.application.post_used=-1
  case 6:c.protocol.application.post_expected=len(c.protocol.application.post_handshake)+1
  }
  idle_test_expect(t,&c,.Invalid)
 }
}

@(test)
async_idle_pending_callbacks_and_protocol_work_are_busy :: proc(t:^testing.T) {
 c:=idle_test_ready()
 operation:net.Async_Operation
 handshake:Async_Handshake_Operation
 for field in 0..<9 {
  c=idle_test_ready()
  switch field {
  case 0:c.handshake_op=&handshake
  case 1:c.read_op=&operation
  case 2:c.write_op=&operation
  case 3:c.close_op=&operation
  case 4:c.rx.pending=true
  case 5:c.tx.pending=true
  case 6:c.shutdown.pending=true
  case 7:c.queued=true
  case 8:c.tx_done=true
  }
  idle_test_expect(t,&c,.Busy)
 }
 c=idle_test_ready();c.protocol.phase=.Handshake_Pending
 c.protocol.handshake_complete=false;c.protocol.application={}
 idle_test_expect(t,&c,.Busy)
}

@(test)
async_idle_partial_plaintext_records_control_and_key_update_are_buffered :: proc(t:^testing.T) {
 c:=idle_test_ready()
 storage:[8]u8
 for field in 0..<16 {
  c=idle_test_ready()
  switch field {
  case 0:c.protocol.application.inbound_size=1
  case 1:c.protocol.application.post_used=1
  case 2:c.protocol.application.post_expected=4
  case 3:c.protocol.application.key_update_pending=true
  case 4:c.rx_used=1
  case 5:c.rx_expected=5
  case 6:c.rx_error.kind=.Cancelled
  case 7:c.tx_kind=.Key_Update
  case 8:c.read_buffer=storage[:0]
  case 9:c.write_buffer=storage[:0]
  case 10:c.flight=storage[:0]
  case 11:c.hello_used=1
  case 12:c.protocol.server_handshake_header_used=1
  case 13:c.protocol.server_handshake_remaining=1
  case 14:c.protocol.handshake_receive.initialized=true
  case 15:c.protocol.application.send.seq=MAX_RECORDS_PER_KEY-1
  }
  idle_test_expect(t,&c,.Buffered)
 }
}

@(test)
async_idle_terminal_state_precedes_busy_and_never_means_callbacks_drained :: proc(t:^testing.T) {
 c:=idle_test_ready()
 for field in 0..<9 {
  c=idle_test_ready();c.rx.pending=true
  switch field {
  case 0:c.closing=true
  case 1:c.transport_closing=true
  case 2:c.transport_closed=true
  case 3:c.protocol.phase=.Failed
  case 4:c.protocol.application.peer_closed=true
  case 5:c.failure.kind=.Cancelled
  case 6:c.close_error.kind=.Timeout
  case 7:c.protocol.application.send.seq=MAX_RECORDS_PER_KEY
  case 8:c.protocol.application.receive.seq=MAX_RECORDS_PER_KEY
  }
  idle_test_expect(t,&c,.Closed)
 }
}
