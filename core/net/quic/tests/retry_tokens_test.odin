package tests

import "core:net"
import quic "core:net/quic"
import "core:sync"
import "core:testing"
import "core:thread"

@(test)
retry_tokens_bind_endpoint_original_and_retry_ids :: proc(t: ^testing.T) {
	store: quic.Retry_Tokens; secret: [32]u8; secret[0] = 17
	testing.expect_value(t, quic.retry_tokens_init(&store, secret[:], 7, 30, 100), .None)
	defer quic.retry_tokens_destroy(&store)
	original := [8]u8{1, 2, 3, 4, 5, 6, 7, 8}; retry := [8]u8{8, 7, 6, 5, 4, 3, 2, 1}
	peer := net.Endpoint{net.IP4_Loopback, 43210}
	token: [quic.RETRY_TOKEN_CAP]u8
	n, e := quic.retry_token_issue(&store, token[:], peer, original[:], retry[:], 100)
	testing.expect_value(t, e, .None)
	claims, opened := quic.retry_token_open(&store, token[:n], peer, retry[:], 101)
	testing.expect_value(t, opened, .None)
	testing.expect_value(
		t,
		string(claims.original_destination_id[:claims.original_destination_id_len]),
		string(original[:]),
	)
	testing.expect_value(
		t,
		string(claims.retry_source_id[:claims.retry_source_id_len]),
		string(retry[:]),
	)
	for bad in ([]net.Endpoint {
			{net.IP4_Loopback, 43211},
			{net.IP4_Address{127, 0, 0, 2}, 43210},
			{net.IP6_Loopback, 43210},
		}) {
		_, err := quic.retry_token_open(&store, token[:n], bad, retry[:], 101)
		testing.expect_value(t, err, .Authentication)
	}
	wrong := retry; wrong[0] ~= 1
	_, wrong_e := quic.retry_token_open(&store, token[:n], peer, wrong[:], 101)
	testing.expect_value(t, wrong_e, .Authentication)
	for i in 0 ..< n {
		tampered := token; tampered[i] ~= 1
		_, err := quic.retry_token_open(&store, tampered[:n], peer, retry[:], 101)
		testing.expect(t, err != .None)
	}
}
@(test)
retry_tokens_expiry_rotation_and_clock_are_bounded :: proc(t: ^testing.T) {
	store: quic.Retry_Tokens; one, two, three: [32]u8; one[0] = 1; two[0] = 2; three[0] = 3
	testing.expect_value(t, quic.retry_tokens_init(&store, one[:], 1, 30, 100), .None)
	defer quic.retry_tokens_destroy(&store)
	original: [8]u8; original[0] = 1; retry: [8]u8; retry[0] = 2
	peer := net.Endpoint{net.IP6_Loopback, 54321}; token: [quic.RETRY_TOKEN_CAP]u8
	n, e := quic.retry_token_issue(&store, token[:], peer, original[:], retry[:], 100)
	testing.expect_value(t, e, .None)
	testing.expect_value(t, quic.retry_tokens_rotate(&store, two[:], 2, 105), .None)
	_, before := quic.retry_token_open(&store, token[:n], peer, retry[:], 129)
	testing.expect_value(t, before, .None)
	_, expired := quic.retry_token_open(&store, token[:n], peer, retry[:], 130)
	testing.expect_value(t, expired, .Expired)
	_, rollback := quic.retry_token_open(&store, token[:n], peer, retry[:], 129)
	testing.expect_value(t, rollback, .Clock)
	testing.expect_value(t, quic.retry_tokens_rotate(&store, three[:], 3, 130), .None)
	_, evicted := quic.retry_token_open(&store, token[:n], peer, retry[:], 130)
	testing.expect_value(t, evicted, .Authentication)
	quic.retry_tokens_destroy(&store)
	_, destroyed := quic.retry_token_open(&store, token[:n], peer, retry[:], 130)
	testing.expect_value(t, destroyed, .Invalid)
}
@(test)
retry_tokens_reject_invalid_input_without_writing :: proc(t: ^testing.T) {
	store: quic.Retry_Tokens; secret: [32]u8
	testing.expect_value(t, quic.retry_tokens_init(&store, secret[:], 1, 0, 100), .Invalid)
	testing.expect_value(t, quic.retry_tokens_init(&store, secret[:], 1, 30, 100), .None)
	defer quic.retry_tokens_destroy(&store)
	buffer := [4]u8{9, 9, 9, 9}; original: [8]u8; original[0] = 1; retry: [8]u8; retry[0] = 2
	n, e := quic.retry_token_issue(
		&store,
		buffer[:],
		{net.IP4_Loopback, 1},
		original[:],
		retry[:],
		100,
	)
	testing.expect_value(t, n, 0); testing.expect_value(t, e, .Destination_Undersized)
	testing.expect_value(t, buffer, [4]u8{9, 9, 9, 9})
	invalid: [60]u8
	for size in 0 ..< 60 {
		_, err := quic.retry_token_open(
			&store,
			invalid[:size],
			{net.IP4_Loopback, 1},
			retry[:],
			100,
		); testing.expect(t, err != .None)
	}
}

Retry_Token_Worker :: struct {
	store:  ^quic.Retry_Tokens,
	ready:  ^int,
	failed: bool,
}
@(test)
retry_tokens_shared_store_rotation_is_serialized :: proc(t: ^testing.T) {
	store: quic.Retry_Tokens; secret, next: [32]u8; secret[0] = 1; next[0] = 2
	assert(quic.retry_tokens_init(&store, secret[:], 1, 30, 100) == .None)
	defer quic.retry_tokens_destroy(&store)
	ready := 0; workers: [4]Retry_Token_Worker; threads: [4]^thread.Thread
	for &worker, i in workers {
		worker = {
			store = &store,
			ready = &ready,
		}
		threads[i] = thread.create_and_start_with_poly_data(&worker, proc(w: ^Retry_Token_Worker) {
			sync.atomic_add(w.ready, 1)
			original: [8]u8; original[0] = 1; retry: [8]u8; retry[0] = 2
			for _ in 0 ..< 200 {
				bytes: [quic.RETRY_TOKEN_CAP]u8
				n, e := quic.retry_token_issue(
					w.store,
					bytes[:],
					{net.IP4_Loopback, 1234},
					original[:],
					retry[:],
					100,
				)
				if e != .None {
					w.failed = true; break
				}
				_, opened := quic.retry_token_open(
					w.store,
					bytes[:n],
					{net.IP4_Loopback, 1234},
					retry[:],
					100,
				)
				if opened != .None {
					w.failed = true; break
				}
			}
		})
	}
	for sync.atomic_load(&ready) < len(workers) {thread.yield()}
	testing.expect_value(t, quic.retry_tokens_rotate(&store, next[:], 2, 100), .None)
	for i in 0 ..< len(
		workers,
	) {thread.join(threads[i]); thread.destroy(threads[i]); testing.expect(t, !workers[i].failed)}
}
@(test)
retry_tokens_reject_authenticated_future_timestamp :: proc(t: ^testing.T) {
	issuing, receiving: quic.Retry_Tokens; secret: [32]u8; secret[0] = 7
	assert(quic.retry_tokens_init(&issuing, secret[:], 1, 30, 120) == .None)
	defer quic.retry_tokens_destroy(&issuing)
	assert(quic.retry_tokens_init(&receiving, secret[:], 1, 30, 100) == .None)
	defer quic.retry_tokens_destroy(&receiving)
	original: [8]u8; original[0] = 1; retry: [8]u8; retry[0] = 2; token: [quic.RETRY_TOKEN_CAP]u8
	n, e := quic.retry_token_issue(
		&issuing,
		token[:],
		{net.IP4_Loopback, 1},
		original[:],
		retry[:],
		120,
	); assert(e == .None)
	_, opened := quic.retry_token_open(&receiving, token[:n], {net.IP4_Loopback, 1}, retry[:], 100)
	testing.expect_value(t, opened, .Clock)
}
