package tls

import "core:mem"
import "core:testing"
import credential_store "credentials/store"

// Recordless client side: collect exact accepted output into a separate hash,
// and use the public Read secret event rather than inspecting engine secrets.
finished_test_start :: proc(t: ^testing.T, o: ^Server_Handshake, a: ^Owner_Test_Audit, store: ^credential_store.Store) -> (wire: [36]u8) {
	storage: [1024]u8
	hello, _ := flight_test_hello(storage[:])
	flight_test_start(t, o, a, store, hello)
	transcript: Handshake_Transcript; transcript_init(&transcript)
	transcript_update(&transcript, hello)
	secret: [32]u8
	for _ in 0 ..< 100 {
		event, _ := server_handshake_peek(o)
		if event.kind == .None {break}
		testing.expect(t, event.kind != .Fatal && event.kind != .Complete)
		n, status, e := server_handshake_feed(o, .Handshake, ([]u8){20,0,0,32})
		testing.expect_value(t, n, 0); testing.expect_value(t, status, .Need_Event_Drain); testing.expect_value(t, e, .None)
		if event.kind == .Handshake_Bytes {transcript_update(&transcript, event.bytes)}
		if event.kind == .Traffic_Secret && event.level == .Handshake && event.direction == .Read {copy(secret[:], event.secret)}
		testing.expect_value(t, server_handshake_accept(o, event.id), .None)
	}
	testing.expect_value(t, o._phase, .Await_Client_Finished)
	testing.expect_value(t, transcript_snapshot(&o._transcript), transcript_snapshot(&transcript))
	n, e := finished_encode(wire[:], secret, transcript_snapshot(&transcript))
	testing.expect_value(t, n, 36); testing.expect_value(t, e, .None)
	return
}
finished_test_erased :: proc(t: ^testing.T, o: ^Server_Handshake, a: ^Owner_Test_Audit, store: ^credential_store.Store) {
	owner_test_clean(t, a)
	testing.expect(t, mem.check_zero_ptr(&o._flight, size_of(o._flight)))
	testing.expect(t, mem.check_zero_ptr(&o._transcript, size_of(o._transcript)))
	testing.expect(t, mem.check_zero(o._secret[:]) && mem.check_zero(o._header[:]))
	testing.expect(t, o._input == nil && o._output == nil && o._received == 0 && o._message_size == 0)
	stats, _ := server_handshake_stats(o); testing.expect_value(t, stats.live_bytes, 0)
	ss, _ := credential_store.stats(store); testing.expect_value(t, ss.active_leases, 0)
}

@(test)
server_finished_every_split_and_single_completion :: proc(t: ^testing.T) {
	store := flight_test_store(t); defer credential_store.destroy(&store)
	for split in 0 ..= 37 {
		a := Owner_Test_Audit{backing=context.allocator}; o: Server_Handshake
		wire := finished_test_start(t, &o, &a, store)
		calls := a.calls; a.fail_at = calls+1 // Finished never acquires another grant.
		if split == 37 {
			for i in 0 ..< 35 {
				n, status, e := server_handshake_feed(&o, .Handshake, wire[i:i+1])
				testing.expect_value(t,n,1); testing.expect_value(t,status,.Need_Input); testing.expect_value(t,e,.None)
			}
			n,status,e := server_handshake_feed(&o,.Handshake,wire[35:])
			testing.expect_value(t,n,1); testing.expect_value(t,status,.Need_Event_Drain); testing.expect_value(t,e,.None)
		} else {
			prefix := wire
			n,status,e := server_handshake_feed(&o,.Handshake,prefix[:split])
			testing.expect_value(t,n,split); testing.expect_value(t,e,.None)
			for &b in prefix[:] {b=0xaa} // Feed retained no caller borrow.
			if split < 36 {
				testing.expect_value(t,status,.Need_Input)
				n,status,e = server_handshake_feed(&o,.Handshake,wire[split:])
				testing.expect_value(t,n,36-split); testing.expect_value(t,e,.None)
			}
			testing.expect_value(t,status,.Need_Event_Drain)
		}
		finished_test_erased(t,&o,&a,store); testing.expect_value(t,a.calls,calls)
		event,_:=server_handshake_peek(&o); testing.expect_value(t,event.kind,.Complete)
		for _ in 0 ..< 3 {
			again,_:=server_handshake_peek(&o); testing.expect_value(t,again.id,event.id)
			testing.expect_value(t,server_handshake_accept(&o,event.id+1),.Invalid_Event)
		}
		// Terminal feed never consumes a duplicate, a later old-level suffix,
		// or application bytes. Only the binding can handle application input.
		for level in Server_Handshake_Level {
			n,status,e:=server_handshake_feed(&o,level,wire[:])
			testing.expect_value(t,n,0); testing.expect_value(t,status,.Terminal); testing.expect_value(t,e,.Invalid_State)
		}
		testing.expect_value(t,server_handshake_accept(&o,event.id),.None)
		testing.expect_value(t,server_handshake_accept(&o,event.id),.Invalid_Event)
		n,status,e:=server_handshake_feed(&o,.Handshake,nil)
		testing.expect_value(t,n,0); testing.expect_value(t,status,.Terminal); testing.expect_value(t,e,.None)
		none,_:=server_handshake_peek(&o); testing.expect_value(t,none.kind,.None)
		server_handshake_destroy(&o); finished_test_erased(t,&o,&a,store)
	}
}

@(test)
server_finished_malformed_mac_transcript_suffix_and_exhaustion :: proc(t: ^testing.T) {
	store:=flight_test_store(t); defer credential_store.destroy(&store)
	for mode in 0 ..< 40 {
		a:=Owner_Test_Audit{backing=context.allocator}; o:Server_Handshake
		wire:=finished_test_start(t,&o,&a,store)
		input:[72]u8; copy(input[:],wire[:]); length:=36
		want:=Server_Handshake_Error.Finished_Failed; count:=36
		if mode < 36 {
			input[mode] ~= 1
			if mode < 4 {want=.Malformed; count=1 if mode==0 else 4}
		} else if mode == 36 {
			transcript_update(&o._transcript,([]u8){0}) // Correct MAC for a different transcript.
		} else if mode == 37 {
			copy(input[36:],wire[:]); length=72; want=.Malformed
		} else if mode == 38 {
			input[36]=0xff; length=37; want=.Malformed
		} else {o._next_id=max(u64); want=.Identity_Exhausted}
		n,status,e:=server_handshake_feed(&o,.Handshake,input[:length])
		testing.expect_value(t,n,count); testing.expect_value(t,status,.Terminal); testing.expect_value(t,e,want)
		event,_:=server_handshake_peek(&o)
		testing.expect_value(t,event.kind,.None if mode==39 else .Fatal)
		finished_test_erased(t,&o,&a,store)
		n,status,e=server_handshake_feed(&o,.Handshake,wire[:])
		testing.expect_value(t,n,0); testing.expect_value(t,status,.Terminal); testing.expect_value(t,e,want)
		if event.kind==.Fatal {testing.expect_value(t,server_handshake_accept(&o,event.id),.None)}
		server_handshake_abort(&o); server_handshake_destroy(&o); finished_test_erased(t,&o,&a,store)
	}
}

@(test)
server_finished_wrong_level_partial_cancel_and_pending_complete_teardown :: proc(t: ^testing.T) {
	store:=flight_test_store(t); defer credential_store.destroy(&store)
	for stop in 0 ..= 36 {
		for mode in 0 ..< 4 {
			a:=Owner_Test_Audit{backing=context.allocator}; o:Server_Handshake
			wire:=finished_test_start(t,&o,&a,store)
			n,_,e:=server_handshake_feed(&o,.Handshake,wire[:stop])
			testing.expect_value(t,n,stop); testing.expect_value(t,e,.None)
			if stop < 36 && mode < 2 {
				level:=Server_Handshake_Level.Initial if mode==0 else .Application
				n,status,e:=server_handshake_feed(&o,level,wire[stop:])
				testing.expect_value(t,n,0); testing.expect_value(t,status,.Terminal); testing.expect_value(t,e,.Wrong_Level)
			} else if mode % 2 == 0 {server_handshake_abort(&o)} else {server_handshake_destroy(&o)}
			finished_test_erased(t,&o,&a,store)
			server_handshake_abort(&o); server_handshake_destroy(&o); finished_test_erased(t,&o,&a,store)
		}
	}
}

@(test)
server_finished_retains_credential_generation_through_authentication :: proc(t:^testing.T) {
	for mode in 0..<5 {
		store:=flight_test_store(t)
		a:=Owner_Test_Audit{backing=context.allocator};o:Server_Handshake
		wire:=finished_test_start(t,&o,&a,store)
		ss,_:=credential_store.stats(store);testing.expect_value(t,ss.active_leases,1)
		// Host retirement cannot free the pinned immutable generation before
		// authentication/abort, even with all DER/output events accepted.
		testing.expect_value(t,credential_store.close(store).kind,.None)
		ss,_=credential_store.stats(store);testing.expect_value(t,ss.generations,1)
		if mode<2 {
			if mode==1 {wire[35]~=1}
			_,_,e:=server_handshake_feed(&o,.Handshake,wire[:]);testing.expect_value(t,e,.None if mode==0 else .Finished_Failed)
		} else if mode==2 {server_handshake_abort(&o)} else if mode==3 {server_handshake_destroy(&o)} else {
			_,_,e:=server_handshake_feed(&o,.Initial,wire[:]);testing.expect_value(t,e,.Wrong_Level)
		}
		ss,_=credential_store.stats(store);testing.expect_value(t,ss.active_leases,0);testing.expect_value(t,ss.generations,0)
		server_handshake_destroy(&o);owner_test_clean(t,&a)
		ss,_=credential_store.stats(store);testing.expect_value(t,ss.active_leases,0)
		credential_store.destroy(&store)
	}
}
