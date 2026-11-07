package net

import "core:testing"
import "core:time"

@(test)
deadline_socket_timeout_never_disables_positive_wait :: proc(t: ^testing.T) {
	for duration in ([?]time.Duration{1, 999, 1000, time.Millisecond}) {
		wait := dns_socket_timeout(duration)
		testing.expect(t, wait / time.Microsecond > 0)
		testing.expect(t, wait >= duration)
	}
}

@(test)
deadline_expired_operations_fail_without_io :: proc(t: ^testing.T) {
	past := time.time_add(time.now(), -time.Second)
	_, dial_error := dial_tcp_until({address=IP4_Address{127,0,0,1},port=80},past)
	testing.expect(t,dial_error == Network_Error(Dial_Error.Timeout))
	_, dns_error := get_dns_records_from_nameservers_until("fixture.invalid",.IP4,nil,nil,past)
	// Empty nameserver list is valid but an expired caller deadline still wins.
	testing.expect(t,dns_error == .Timeout)
	_, resolve_error := resolve_endpoint_until("127.0.0.1",80,past)
	testing.expect(t,resolve_error == Network_Error(DNS_Error.Timeout))
}

@(test)
deadline_legacy_entrypoint_signatures_remain_exact :: proc(t: ^testing.T) {
	old_resolve: proc(string) -> (Endpoint, Endpoint, Network_Error) = resolve
	old_ip4: proc(string) -> (Endpoint, Network_Error) = resolve_ip4
	old_ip6: proc(string) -> (Endpoint, Network_Error) = resolve_ip6
	old_dial: proc(Endpoint, TCP_Options) -> (TCP_Socket, Network_Error) = dial_tcp_from_endpoint
	testing.expect(t, old_resolve != nil && old_ip4 != nil && old_ip6 != nil && old_dial != nil)
}
