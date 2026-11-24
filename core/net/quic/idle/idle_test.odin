package idle
import "core:testing"
@(test)
idle_negotiation_floor_and_zero :: proc(t: ^testing.T) {
	s: State
	assert(configure(&s, 0, 0, 10))
	_, armed := deadline(&s, 100)
	testing.expect(t, !armed)
	assert(configure(&s, 30000, 0, 20))
	testing.expect(t, negotiated(&s) == 30000 && s.last_activity == 10)
	assert(configure(&s, 30000, 50, 20))
	testing.expect(t, period(&s, 100) == 300)
	testing.expect(t, !expired(&s, 100, 309) && expired(&s, 100, 310))
	assert(configure(&s, 0, 500, 20))
	testing.expect(t, period(&s, 100) == 500)
}

@(test)
idle_receive_and_only_first_successful_eliciting_send :: proc(t: ^testing.T) {
	s: State
	assert(configure(&s, 100, 0, 0))
	sent(&s, 20, false)
	testing.expect(t, s.last_activity == 0)
	sent(&s, 30, true)
	sent(&s, 60, true)
	testing.expect(t, s.last_activity == 30)
	received(&s, 70)
	sent(&s, 80, true)
	sent(&s, 90, true)
	testing.expect(t, s.last_activity == 80)
	received(&s, 10)
	testing.expect(t, s.last_activity == 80)
}

@(test)
idle_saturation_and_backwards_clock :: proc(t: ^testing.T) {
	s: State
	assert(!configure(&s, 1, 1, -1))
	assert(configure(&s, max(u64), 0, 100))
	at, armed := deadline(&s, max(i64))
	testing.expect(t, armed && at == max(i64) && !expired(&s, max(i64), max(i64) - 1))
}
