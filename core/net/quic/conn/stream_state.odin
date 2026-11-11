package conn

// Reports a peer RESET_STREAM without consuming its terminal state. This lets
// multiplexed protocol owners retire the cancelled exchange while continuing
// unrelated streams. A missing/uninitialized connection or stream returns false.
receive_reset :: proc(c: ^Connection, id: u64) -> bool {
	if c == nil || !c.initialized {
		return false
	}
	b := find_buf(c, id)
	return b != nil && b.recv_reset
}
