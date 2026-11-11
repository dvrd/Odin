# QUIC idle lifetime

This module tracks idle lifetime in monotonic milliseconds. Configure local and
validated peer `max_idle_timeout` values; zero means no preference, and both zero
disable expiry. `deadline` applies the negotiated minimum and the three-base-PTO
floor. Loss backoff is separate from the base PTO.

`received` is for successfully authenticated and processed packets. `sent` is for
successful ack-eliciting datagram transmission; only the first such send after a
receive advances activity. Packet preparation, ACK-only output and unauthenticated
traffic do not advance it. Peer-parameter updates preserve existing activity.

For `core:net/quic/conn`, a wire handshake driver retains this state before key
adoption, then calls `conn.configure_timing(connection, state, peer_max_ack_delay)`.
The ACK-delay default is25ms; an explicitly advertised zero remains zero. Generic
Core drivers must forward these validated values just as they forward flow limits.
The HTTP3 driver handles this automatically.

`conn.timer` combines idle, loss and draining deadlines. Its `idle` flag identifies
an idle deadline; `conn.idle_tick` quietly expires the owner, destroys keys and
retained state, and leaves a terminal Closed result. `conn.timing_stats` reports
negotiated/effective duration, remaining time, base PTO and expiry in milliseconds.

Custom datagram drivers must capture `conn.output_ack_eliciting` with returned
packet bytes and call `conn.output_sent` only after successful UDP transmission,
using the actual send time. Retained blocked bytes retain that boolean too. The
Core UDP facade and HTTP3 pending-output layer already do this. Idle expiry never
sends CONNECTION_CLOSE; local early abandonment uses explicit close instead.
