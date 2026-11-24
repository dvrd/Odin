package conn
import "core:testing"

@(test)
post_handshake_owned_reorder_overlap_and_consumption :: proc(t: ^testing.T) {
	c := new(Connection)
	defer free(c)
	c.initialized = true
	input := [?]u8{4, 0, 0, 3, 1, 2, 3}
	testing.expect_value(
		t,
		post_handshake_received(c, {crypto = true, crypto_off = 3, crypto_data = input[3:]}),
		.None,
	)
	testing.expect_value(t, len(peek_post_handshake(c)), 0)
	testing.expect_value(
		t,
		post_handshake_received(c, {crypto = true, crypto_off = 0, crypto_data = input[:4]}),
		.None,
	)
	testing.expect_value(t, string(peek_post_handshake(c)), string(input[:]))
	input[0] = 99
	testing.expect_value(t, peek_post_handshake(c)[0], u8(4))
	bad := [?]u8{8, 9}
	testing.expect_value(
		t,
		post_handshake_received(c, {crypto = true, crypto_off = 4, crypto_data = bad[:]}),
		.Protocol,
	)
	testing.expect_value(t, peek_post_handshake(c)[4], u8(1))
	testing.expect_value(t, consume_post_handshake(c, 7), .None)
	testing.expect_value(t, len(peek_post_handshake(c)), 0)
	testing.expect_value(t, post_handshake_received(c, {crypto = true, crypto_off = 0, crypto_data = input[:]}), .None)
	testing.expect_value(t, len(peek_post_handshake(c)), 0)
	testing.expect_value(t, post_handshake_received(c, {crypto = true, crypto_off = 7, crypto_data = bad[:]}), .None)
	testing.expect_value(t, string(peek_post_handshake(c)), string(bad[:]))
	testing.expect_value(
		t,
		post_handshake_received(c, {crypto = true, crypto_off = 7 + POST_HANDSHAKE_CAP, crypto_data = bad[:]}),
		.Capacity,
	)
	post_handshake_clear(c)
	testing.expect_value(t, c.post_handshake, Post_Handshake_State{})
}

@(test)
post_handshake_owned_ack_retirement_and_replay_window :: proc(t: ^testing.T) {
	c := new(Connection)
	defer free(c)
	c.initialized = true
	bytes := [?]u8{1, 2, 3, 4, 5, 6}
	testing.expect_value(t, queue_post_handshake(c, bytes[:]), .None)
	bytes[0] = 99
	testing.expect_value(t, c.post_handshake.send[0], u8(1))
	c.post_handshake.send_off = 6
	c.post_handshake.packets[0] = {
		active = true,
		pn     = 7,
		offset = 0,
		n      = 3,
	}
	c.post_handshake.packets[1] = {
		active = true,
		pn     = 8,
		offset = 3,
		n      = 3,
	}
	ack := Parsed {
		ack   = true,
		ack_n = 1,
	}
	ack.ack_ranges[0] = {8, 8}
	post_handshake_ack(c, ack)
	testing.expect_value(t, c.post_handshake.send_n, 6)
	post_handshake_rewind(c)
	testing.expect_value(t, c.post_handshake.send_off, 0)
	ack.ack_ranges[0] = {7, 7}
	post_handshake_ack(c, ack)
	testing.expect_value(t, c.post_handshake.send_n, 0)
	testing.expect_value(t, c.post_handshake.send_base, u64(6))
	testing.expect_value(t, queue_post_handshake(c, bytes[:]), .None)
	testing.expect_value(t, c.post_handshake.send_n, 6)
	old := c.post_handshake
	oversized: [POST_HANDSHAKE_CAP]u8
	testing.expect_value(t, queue_post_handshake(c, oversized[:]), .Capacity)
	testing.expect_value(t, c.post_handshake, old)
	post_handshake_clear(c)
	testing.expect_value(t, c.post_handshake, Post_Handshake_State{})
}
