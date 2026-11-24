package tls

import "core:bytes"
import "core:crypto/sha2"
import "core:mem"
import "core:testing"

@(private)
layout_test_hello :: proc(conn: ^Conn, extended: bool) -> int {
	hello := Client_Hello {
		server_name    = "fixture.example",
		alpn_protocols = {"http/1.1"},
	}
	for &value, i in hello.random {value = byte(i)}
	size, error := client_hello_encode(conn.client_hello[:], hello)
	assert(error == .None)
	if extended {
		// Insert two legacy suites into the offered cipher vector, preserving
		// every extension. This is a layout fixture, not a shipped dual offer.
		copy(conn.client_hello[47:size + 4], conn.client_hello[43:size])
		conn.client_hello[39], conn.client_hello[40] = 0, 6
		conn.client_hello[43], conn.client_hello[44] = 0xc0, 0x2f
		conn.client_hello[45], conn.client_hello[46] = 0xc0, 0x2b
		size += 4
		retry_put_u24(conn.client_hello[:], 1, size - 4)
	}
	conn.client_hello_size = size
	return size
}

@(private)
layout_test_retry :: proc(dst: []byte, cookie: []byte) -> []byte {
	at := 4
	hello_put_u16(dst, &at, 0x0303)
	for value, i in HELLO_RETRY_REQUEST_RANDOM {dst[at + i] = value}; at += 32
	dst[at] = 0
	at += 1
	hello_put_u16(dst, &at, 0x1301)
	dst[at] = 0
	at += 1
	hello_put_u16(dst, &at, u16(12 + len(cookie)))
	hello_put_u16(dst, &at, 43)
	hello_put_u16(dst, &at, 2)
	hello_put_u16(dst, &at, 0x0304)
	hello_put_u16(dst, &at, 44)
	hello_put_u16(dst, &at, u16(2 + len(cookie)))
	hello_put_u16(dst, &at, u16(len(cookie)))
	copy(dst[at:], cookie)
	at += len(cookie)
	dst[0] = 2
	retry_put_u24(dst, 1, at - 4)
	return dst[:at]
}

@(private)
layout_test_prepare :: proc(t: ^testing.T, extended: bool) {
	conn := new(Conn)
	defer free(conn)
	size := layout_test_hello(conn, extended)
	first := conn.client_hello
	cookie := []byte{1, 2, 3, 4}
	retry_storage: [MAX_HELLO_RETRY_REQUEST_SIZE]byte
	retry := layout_test_retry(retry_storage[:], cookie)
	parsed_cookie, decode := hello_retry_request_decode(retry)
	assert(decode == .None)
	previous := context.allocator
	context.allocator = mem.panic_allocator()
	result := client_hello_retry_prepare(conn, retry, parsed_cookie)
	context.allocator = previous
	testing.expect_value(t, result, .None)
	if result != .None do return
	testing.expect_value(t, conn.client_hello, first)
	testing.expect_value(t, conn.retry_client_hello_size, size + 6 + len(cookie))
	length_at := 45
	if extended do length_at += 4
	expected := first
	retry_put_u24(expected[:], 1, size + 6 + len(cookie) - 4)
	retry_put_u16(expected[:], length_at, retry_u16(first[:], length_at) + u16(6 + len(cookie)))
	testing.expect(t, bytes.equal(conn.retry_client_hello[:size], expected[:size]))
	testing.expect(
		t,
		bytes.equal(conn.retry_client_hello[size:conn.retry_client_hello_size], []byte{0, 44, 0, 6, 0, 4, 1, 2, 3, 4}),
	)
	hash: [32]byte
	digest: sha2.Context_256
	sha2.init_256(&digest)
	sha2.update(&digest, first[:size])
	sha2.final(&digest, hash[:])
	testing.expect_value(t, conn.retry_transcript_size, 36 + len(retry))
	testing.expect(t, bytes.equal(conn.retry_transcript[:4], []byte{254, 0, 0, 32}))
	testing.expect(t, bytes.equal(conn.retry_transcript[4:36], hash[:]))
	testing.expect(t, bytes.equal(conn.retry_transcript[36:conn.retry_transcript_size], retry))
}

@(test)
client_hello_retry_preserves_existing_wire_and_transcript :: proc(t: ^testing.T) {
	layout_test_prepare(t, false)
}

@(test)
client_hello_retry_accepts_extended_cipher_vector_layout :: proc(t: ^testing.T) {
	layout_test_prepare(t, true)
}

@(private)
layout_test_outputs_seed :: proc(conn: ^Conn) {
	for &value in conn.retry_client_hello {value = 0xa5}
	for &value in conn.retry_transcript {value = 0xb6}
	conn.retry_client_hello_size = 7
}

@(private)
layout_test_reject_preserves :: proc(t: ^testing.T, conn: ^Conn, retry, cookie: []byte, expected: Server_Hello_Error) {
	first := conn.client_hello
	hello_output, transcript_output := conn.retry_client_hello, conn.retry_transcript
	hello_size, transcript_size := conn.retry_client_hello_size, conn.retry_transcript_size
	phase := conn.phase
	previous := context.allocator
	context.allocator = mem.panic_allocator()
	result := client_hello_retry_prepare(conn, retry, cookie)
	context.allocator = previous
	testing.expect_value(t, result, expected)
	testing.expect_value(t, conn.client_hello, first)
	testing.expect_value(t, conn.retry_client_hello, hello_output)
	testing.expect_value(t, conn.retry_transcript, transcript_output)
	testing.expect_value(t, conn.retry_client_hello_size, hello_size)
	testing.expect_value(t, conn.retry_transcript_size, transcript_size)
	testing.expect_value(t, conn.phase, phase)
}

@(test)
client_hello_layout_checks_all_prefixes_and_variable_vectors :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	for extended in ([2]bool{false, true}) {
		size := layout_test_hello(conn, extended)
		before := conn.client_hello
		layout, valid := client_hello_layout_decode(conn.client_hello[:size])
		testing.expect(t, valid)
		testing.expect_value(t, layout.cipher_size, extended ? 6 : 2)
		testing.expect_value(t, layout.extensions_length_offset, extended ? 49 : 45)
		for split in 0 ..< size {
			_, short_valid := client_hello_layout_decode(conn.client_hello[:split])
			testing.expect(t, !short_valid)
		}
		testing.expect_value(t, conn.client_hello, before)
	}
	// A session ID is structurally valid, while our no-resumption retry profile
	// still requires the empty ID. The parser must locate all later vectors.
	size := layout_test_hello(conn, false)
	copy(conn.client_hello[40:size + 1], conn.client_hello[39:size])
	conn.client_hello[38], conn.client_hello[39] = 1, 0x7e
	size += 1
	retry_put_u24(conn.client_hello[:], 1, size - 4)
	conn.client_hello_size = size
	layout, valid := client_hello_layout_decode(conn.client_hello[:size])
	testing.expect(t, valid)
	testing.expect_value(t, layout.session_size, 1)
	testing.expect_value(t, layout.extensions_length_offset, 46)
	layout_test_outputs_seed(conn)
	layout_test_reject_preserves(t, conn, nil, []byte{1}, .Invalid_Retry_Client_Hello)
}

@(test)
client_hello_retry_rejects_malformed_layout_without_writing :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	for fault in ([]struct {
			at:    int,
			value: byte,
		} {
			{0, 2},
			{4, 2},
			{38, 33},
			{39, 0xff},
			{40, 0},
			{40, 1},
			{43, 0},
			{43, 2},
			{44, 1},
			{45, 0xff},
			{46, 0},
			{49, 0xff},
		}) {
		layout_test_hello(conn, false)
		conn.client_hello[fault.at] = fault.value
		layout_test_outputs_seed(conn)
		layout_test_reject_preserves(t, conn, nil, []byte{1}, .Invalid_Retry_Client_Hello)
	}
	for invalid_size in ([3]int{-1, 0, MAX_CLIENT_HELLO_SIZE + 1}) {
		layout_test_hello(conn, false)
		conn.client_hello_size = invalid_size
		layout_test_outputs_seed(conn)
		layout_test_reject_preserves(t, conn, nil, []byte{1}, .Invalid_Retry_Client_Hello)
	}
	testing.expect_value(t, client_hello_retry_prepare(nil, nil, nil), .Invalid_Retry_Client_Hello)
}

@(private)
layout_test_append_extension :: proc(conn: ^Conn, extension: []byte) {
	at := conn.client_hello_size
	copy(conn.client_hello[at:], extension)
	conn.client_hello_size += len(extension)
	retry_put_u24(conn.client_hello[:], 1, conn.client_hello_size - 4)
	retry_put_u16(conn.client_hello[:], 45, u16(conn.client_hello_size - 47))
}

@(test)
client_hello_retry_rejects_duplicate_truncated_and_existing_cookie_extensions :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	layout_test_hello(conn, false)
	// Duplicate an entire existing SNI extension at a different offset.
	first_size := 4 + int(hello_u16(conn.client_hello[:], 49))
	layout_test_append_extension(conn, conn.client_hello[47:47 + first_size])
	layout_test_outputs_seed(conn)
	layout_test_reject_preserves(t, conn, nil, []byte{1}, .Invalid_Retry_Client_Hello)
	layout_test_hello(conn, false)
	layout_test_append_extension(conn, []byte{0})
	layout_test_outputs_seed(conn)
	layout_test_reject_preserves(t, conn, nil, []byte{1}, .Invalid_Retry_Client_Hello)
	layout_test_hello(conn, false)
	layout_test_append_extension(conn, []byte{0, 44, 0, 3, 0, 1, 7})
	layout, valid := client_hello_layout_decode(conn.client_hello[:conn.client_hello_size])
	testing.expect(t, valid && layout.has_cookie)
	layout_test_outputs_seed(conn)
	layout_test_reject_preserves(t, conn, nil, []byte{1}, .Invalid_Retry_Client_Hello)
}

@(test)
client_hello_retry_cookie_limits_and_repeated_retry_preserve_outputs :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	layout_test_hello(conn, false)
	layout_test_outputs_seed(conn)
	layout_test_reject_preserves(t, conn, nil, nil, .Invalid_Retry_Cookie)
	large_cookie: [MAX_RETRY_COOKIE_SIZE + 1]byte
	layout_test_reject_preserves(t, conn, nil, large_cookie[:], .Invalid_Retry_Cookie)
	large_retry: [MAX_HELLO_RETRY_REQUEST_SIZE + 1]byte
	layout_test_reject_preserves(t, conn, large_retry[:], []byte{1}, .Retry_Cookie_Oversized)
	conn.retry_transcript_size = 1
	layout_test_reject_preserves(t, conn, nil, []byte{1}, .Repeated_Hello_Retry)
	conn.retry_transcript_size = 0
	testing.expect_value(t, client_hello_retry_prepare(conn, nil, large_cookie[:MAX_RETRY_COOKIE_SIZE]), .None)
	testing.expect_value(t, conn.retry_client_hello_size, conn.client_hello_size + 6 + MAX_RETRY_COOKIE_SIZE)
}

@(test)
client_hello_retry_rejects_input_output_aliases_and_accepts_read_only_aliases :: proc(t: ^testing.T) {
	conn := new(Conn)
	defer free(conn)
	for destination in 0 ..< 2 {
		for offset in ([2]int{0, 3}) {
			layout_test_hello(conn, false)
			layout_test_outputs_seed(conn)
			output := conn.retry_client_hello[:]
			if destination == 1 do output = conn.retry_transcript[:]
			layout_test_reject_preserves(t, conn, nil, output[offset:offset + 2], .Invalid_Retry_Client_Hello)
			layout_test_reject_preserves(t, conn, output[offset:offset + 2], []byte{1}, .Invalid_Retry_Client_Hello)
		}
	}
	// Existing normal alias: cookie is a sub-slice of validated HRR input.
	layout_test_prepare(t, true)
	// Both immutable inputs may borrow CH1; neither destination overlaps it.
	layout_test_hello(conn, false)
	first := conn.client_hello
	testing.expect_value(t, client_hello_retry_prepare(conn, conn.client_hello[:8], conn.client_hello[8:10]), .None)
	testing.expect_value(t, conn.client_hello, first)
}
