package tests
import "core:bytes"
import "core:net"
import "core:net/quic"
import "core:testing"

@(private)
reset_test_key :: proc() -> [32]u8 {return [32]u8{0 = 1, 31 = 7}}
@(test)
reset_keys_keep_live_and_recent_cid_generations :: proc(t: ^testing.T) {
	s: quic.Reset_Secrets; k := reset_test_key()
	assert(quic.reset_secrets_init(&s, k[:], 7, {retention_ms = 1000}, 0) == .None)
	cid: [16]u8; lease, e := quic.reset_cid_issue(&s, cid[:], 0); assert(e == .None)
	testing.expect_value(t, quic.reset_secrets_destroy(&s), .Busy)
	k[0] = 2; testing.expect_value(t, quic.reset_secrets_rotate(&s, k[:], 8, 1), .None)
	k[0] = 3; testing.expect_value(t, quic.reset_secrets_rotate(&s, k[:], 9, 2000), .Busy)
	copied := lease; testing.expect_value(t, quic.reset_cid_release(&s, &lease, 2000), .None)
	testing.expect_value(t, quic.reset_cid_release(&s, &copied, 2000), .Invalid)
	testing.expect_value(t, quic.reset_secrets_rotate(&s, k[:], 9, 2999), .Busy)
	testing.expect_value(t, quic.reset_secrets_rotate(&s, k[:], 9, 3000), .None)
	testing.expect_value(t, quic.reset_secrets_destroy(&s), .None)
}
@(test)
reset_response_reproduces_cid_token_after_connection_release_and_rotation :: proc(t: ^testing.T) {
	s: quic.Reset_Secrets; k := reset_test_key()
	assert(quic.reset_secrets_init(&s, k[:], 17, {retention_ms = 1000}, 0) == .None)
	defer quic.reset_secrets_destroy(&s)
	cid: [16]u8; lease, e := quic.reset_cid_issue(&s, cid[:], 0); assert(e == .None)
	token := lease.token
	assert(quic.reset_cid_release(&s, &lease, 10) == .None); k[0] = 9
	assert(quic.reset_secrets_rotate(&s, k[:], 18, 20) == .None)
	trigger: [100]u8; trigger[0] = 0x40; copy(trigger[1:17], cid[:]); out: [64]u8
	n, re := quic.reset_packet(&s, out[:], trigger[:], {net.IP4_Loopback, 1234}, 21)
	testing.expect_value(t, re, .None); testing.expect(t, n >= 21 && n <= 43 && n < len(trigger))
	testing.expect(t, bytes.equal(out[n - 16:n], token[:]))
	inplace := trigger
	n, re = quic.reset_packet(&s, inplace[:], inplace[:], {net.IP4_Loopback, 1234}, 22)
	testing.expect_value(t, re, .None); testing.expect(t, bytes.equal(inplace[n - 16:n], token[:]))
	trigger[10] ~= 1
	n, re = quic.reset_packet(&s, out[:], trigger[:], {net.IP4_Loopback, 1234}, 22)
	testing.expect_value(t, re, .None); testing.expect(t, !bytes.equal(out[n - 16:n], token[:]))
}
@(test)
reset_generation_limits_ports_and_rejects_loops_long_headers_and_clock_rollback :: proc(
	t: ^testing.T,
) {
	s: quic.Reset_Secrets; k := reset_test_key()
	assert(
		quic.reset_secrets_init(&s, k[:], 4, {peer_burst = 2, peer_per_second = 1}, 100) == .None,
	); defer quic.reset_secrets_destroy(&s)
	cid: [16]u8; assert(quic.reset_cid_random(&s, cid[:], 100) == .None)
	trigger: [100]u8; trigger[0] = 0x40; copy(trigger[1:17], cid[:]); out: [64]u8
	for port in 2000 ..< 2002 {
		n, e := quic.reset_packet(&s, out[:], trigger[:], {net.IP4_Loopback, port}, 100)
		testing.expect_value(t, e, .None); testing.expect(t, n > 0)
	}
	_, e := quic.reset_packet(&s, out[:], trigger[:], {net.IP4_Loopback, 9999}, 100)
	testing.expect_value(t, e, .Limited)
	_, e = quic.reset_packet(&s, out[:], trigger[:21], {net.IP4_Loopback, 9999}, 100)
	testing.expect_value(t, e, .Discarded)
	trigger[0] = 0xc0
	_, e = quic.reset_packet(&s, out[:], trigger[:], {net.IP4_Loopback, 9999}, 100)
	testing.expect_value(t, e, .Discarded)
	trigger[0] = 0x40
	_, e = quic.reset_packet(&s, out[:], trigger[:], {net.IP4_Loopback, 9999}, 99)
	testing.expect_value(t, e, .Clock)
	_, e = quic.reset_packet(&s, out[:], trigger[:], {net.IP4_Loopback, 9999}, 1100)
	testing.expect_value(t, e, .None)
}
@(test)
reset_lease_capacity_and_wrong_owner_release_are_bounded :: proc(t: ^testing.T) {
	s, other: quic.Reset_Secrets; k := reset_test_key()
	assert(quic.reset_secrets_init(&s, k[:], 4, {}, 0) == .None)
	assert(quic.reset_secrets_init(&other, k[:], 4, {}, 0) == .None)
	defer quic.reset_secrets_destroy(&s); defer quic.reset_secrets_destroy(&other)
	leases: [quic.RESET_LEASES]quic.Reset_CID_Lease; cid: [16]u8
	for &lease in leases {
		e: quic.Reset_Error; lease, e = quic.reset_cid_issue(&s, cid[:], 0); assert(e == .None)
	}
	_, e := quic.reset_cid_issue(&s, cid[:], 0); testing.expect_value(t, e, .Capacity)
	testing.expect_value(t, quic.reset_cid_release(&other, &leases[0], 0), .Invalid)
	for &lease in leases {testing.expect_value(t, quic.reset_cid_release(&s, &lease, 0), .None)}
}
@(test)
reset_unleased_retry_cid_prevents_early_key_eviction :: proc(t: ^testing.T) {
	s: quic.Reset_Secrets; k := reset_test_key()
	assert(quic.reset_secrets_init(&s, k[:], 1, {retention_ms = 1000}, 0) == .None)
	defer quic.reset_secrets_destroy(&s)
	cid: [16]u8; assert(quic.reset_cid_random(&s, cid[:], 900) == .None)
	k[0] = 2; assert(quic.reset_secrets_rotate(&s, k[:], 2, 1000) == .None)
	k[0] = 3; testing.expect_value(t, quic.reset_secrets_rotate(&s, k[:], 3, 1500), .Busy)
	lease, e := quic.reset_cid_acquire(&s, cid[:], 1500); testing.expect_value(t, e, .None)
	assert(quic.reset_cid_release(&s, &lease, 1500) == .None)
}

@(test)
reset_global_budget_cannot_be_bypassed_by_new_addresses :: proc(t: ^testing.T) {
	s: quic.Reset_Secrets; k := reset_test_key()
	assert(
		quic.reset_secrets_init(&s, k[:], 4, {burst = 2, per_second = 1, peer_burst = 100}, 0) ==
		.None,
	); defer quic.reset_secrets_destroy(&s)
	cid: [16]u8; assert(quic.reset_cid_random(&s, cid[:], 0) == .None)
	trigger: [64]u8; trigger[0] = 0x40; copy(trigger[1:], cid[:]); response: [43]u8
	for i in 1 ..< 40 {
		_, e := quic.reset_packet(
			&s,
			response[:],
			trigger[:],
			{net.IP4_Address{127, 0, 0, u8(i)}, 4000 + i},
			0,
		)
		if i <= 2 {
			testing.expect_value(t, e, .None)
		} else {
			testing.expect_value(t, e, .Limited)
		}
	}
}
