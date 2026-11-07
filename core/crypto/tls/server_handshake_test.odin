package tls

import "core:mem"
import "core:fmt"
import "core:testing"

Owner_Test_Audit :: struct {
	backing: mem.Allocator,
	calls, fail_at, delta: int,
	error_with_grant: bool,
	live, peak, requested, freed: int,
	dirty, bad_free: bool,
	pointers: [2]rawptr,
	sizes: [2]int,
}
owner_test_allocator_proc :: proc(data: rawptr, mode: mem.Allocator_Mode, size, alignment: int, old: rawptr, old_size: int, loc := #caller_location) -> ([]u8, mem.Allocator_Error) {
	a := cast(^Owner_Test_Audit)data
	#partial switch mode {
	case .Alloc:
		a.calls += 1; a.requested += size
		if a.calls == a.fail_at {return nil, .Out_Of_Memory}
		grant_size := size + a.delta
		grant, error := a.backing.procedure(a.backing.data, .Alloc, grant_size, alignment, nil, 0, loc)
		if error != nil {return grant, error}
		for &b in grant {b = 0xa5}
		for i in 0..<len(a.pointers) {
			if a.pointers[i] == nil {
				a.pointers[i], a.sizes[i] = raw_data(grant), len(grant); break
			}
		}
		a.live += len(grant); a.peak = max(a.peak, a.live)
		return grant, .Out_Of_Memory if a.error_with_grant else .None
	case .Free:
		found := false
		for i in 0..<len(a.pointers) {
			if a.pointers[i] == old && old != nil {
				found = true
				if a.sizes[i] != old_size {a.bad_free = true}
				a.dirty = a.dirty || !mem.check_zero_ptr(old, a.sizes[i])
				a.live -= a.sizes[i]; a.freed += 1
				a.pointers[i], a.sizes[i] = nil, 0
				break
			}
		}
		if !found {a.bad_free = true}
		return a.backing.procedure(a.backing.data, mode, size, alignment, old, old_size, loc)
	case: return nil, .Mode_Not_Implemented
	}
}
owner_test_allocator :: proc(a: ^Owner_Test_Audit) -> mem.Allocator {return {owner_test_allocator_proc, a}}
owner_test_ready :: proc(t: ^testing.T, o: ^Server_Handshake, a: ^Owner_Test_Audit, wire: []u8) {
	testing.expect_value(t,server_handshake_init(o,SERVER_HANDSHAKE_DEFAULT_CONFIG,owner_test_allocator(a)),.None)
	n,status,e := server_handshake_feed(o,.Initial,wire)
	testing.expect_value(t,n,len(wire)); testing.expect_value(t,status,.Need_Event_Drain); testing.expect_value(t,e,.None)
	event,_ := server_handshake_peek(o)
	testing.expect_value(t,event.kind,.Peer_Parameters)
	testing.expect_value(t,server_handshake_accept(o,event.id),.None)
}
owner_test_clean :: proc(t: ^testing.T, a: ^Owner_Test_Audit) {
	testing.expect_value(t,a.live,0)
	testing.expect(t,!a.dirty && !a.bad_free)
}

@(test)
server_owner_admission_and_address_identity :: proc(t: ^testing.T) {
	o: Server_Handshake
	testing.expect(t,size_of(o) <= 4096)
	fmt.printf("recordless owner=%d event=%d fixed bytes; CH cap=%d scratch=%d\n",size_of(o),size_of(Server_Handshake_Event),SERVER_CLIENT_HELLO_MAX_WIRE,SERVER_HANDSHAKE_OUTPUT_CAP)
	testing.expect_value(t,server_handshake_init(nil,SERVER_HANDSHAKE_DEFAULT_CONFIG,context.allocator),.Invalid_Owner)
	for config in ([]Server_Handshake_Config{{44,128},{65537,128},{65536,0},{65536,129}}) {
		testing.expect_value(t,server_handshake_init(&o,config,context.allocator),.Invalid_Config)
		testing.expect(t,o._self == nil)
	}
	testing.expect_value(t,server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,{}),.Invalid_Config)
	testing.expect_value(t,server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,mem.nil_allocator()),.None)
	testing.expect_value(t,server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,context.allocator),.Invalid_State)
	alias := o
	_,_,e := server_handshake_feed(&alias,.Initial,nil)
	testing.expect_value(t,e,.Invalid_Owner)
	testing.expect_value(t,server_handshake_destroy(&alias),.Invalid_Owner)
	testing.expect_value(t,server_handshake_destroy(&o),.None)
	testing.expect_value(t,server_handshake_destroy(&o),.None)
	testing.expect_value(t,server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,context.allocator),.Invalid_State)
}

@(test)
server_owner_fragmentation_borrows_and_suffix :: proc(t: ^testing.T) {
	// Existing fixture decoder avoids any production dependency on test helpers.
	wire := transmute([]u8)#load("testdata/server_go_client_hello.wire")
	for split in 0..=len(wire) {
		a := Owner_Test_Audit{backing=context.allocator}
		o: Server_Handshake
		testing.expect_value(t,server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,owner_test_allocator(&a)),.None)
		prefix := make([]u8,split); copy(prefix,wire[:split])
		n,_,e := server_handshake_feed(&o,.Initial,prefix)
		for &b in prefix {b=0xdd}; delete(prefix)
		testing.expect_value(t,n,split); testing.expect_value(t,e,.None)
		if split < len(wire) {
			// Overwrite and free the remaining caller input after feed returns.
			input := make([]u8,len(wire)-split+3); copy(input,wire[split:]); input[len(input)-1]=0xff
			n,status,e := server_handshake_feed(&o,.Initial,input)
			testing.expect_value(t,n,len(wire)-split); testing.expect_value(t,status,.Need_Event_Drain); testing.expect_value(t,e,.None)
			for &b in input {b = 0xcc}; delete(input)
		}
		event,_ := server_handshake_peek(&o)
		testing.expect_value(t,event.kind,.Peer_Parameters)
		testing.expect_value(t,string(event.peer.server_name),"fixture.invalid")
		digest := transcript_snapshot(&o._transcript)
		for _ in 0..<3 {
			peek,_ := server_handshake_peek(&o)
			testing.expect_value(t,peek.id,event.id)
			testing.expect(t,raw_data(peek.peer.server_name)==raw_data(event.peer.server_name))
			n,status,_ := server_handshake_feed(&o,.Handshake,([]u8){20,0,0,32})
			testing.expect_value(t,n,0); testing.expect_value(t,status,.Need_Event_Drain)
		}
		testing.expect_value(t,server_handshake_accept(&o,event.id+1),.Invalid_Event)
		testing.expect_value(t,transcript_snapshot(&o._transcript),digest)
		testing.expect_value(t,server_handshake_accept(&o,event.id),.None)
		testing.expect_value(t,server_handshake_accept(&o,event.id),.Invalid_Event)
		_,status,_ := server_handshake_feed(&o,.Initial,([]u8){1})
		testing.expect_value(t,status,.Await_Flight)
		testing.expect_value(t,a.calls,1); testing.expect_value(t,a.peak,len(wire))
		server_handshake_destroy(&o); owner_test_clean(t,&a)
	}
}

@(test)
server_owner_single_byte_and_limits :: proc(t: ^testing.T) {
	wire := transmute([]u8)#load("testdata/server_openssl_client_hello.wire")
	a := Owner_Test_Audit{backing=context.allocator}
	o: Server_Handshake
	config := Server_Handshake_Config{len(wire),128}
	server_handshake_init(&o,config,owner_test_allocator(&a))
	for i in 0..<len(wire) {
		n,status,e := server_handshake_feed(&o,.Initial,wire[i:i+1])
		testing.expect_value(t,n,1); testing.expect_value(t,e,.None)
		testing.expect_value(t,status,.Need_Event_Drain if i==len(wire)-1 else .Need_Input)
	}
	server_handshake_destroy(&o); owner_test_clean(t,&a)
	for header in ([][]u8{([]u8){1,1,0,0},([]u8){1,0,0,0},([]u8){2,0,1,0}}) {
		b := Owner_Test_Audit{backing=context.allocator}
		p: Server_Handshake; server_handshake_init(&p,config,owner_test_allocator(&b))
		n,status,e := server_handshake_feed(&p,.Initial,header)
		testing.expect(t,e==.Limit || e==.Malformed)
		testing.expect_value(t,status,.Terminal)
		testing.expect(t,n==4 || n==1); testing.expect_value(t,b.calls,0)
		server_handshake_destroy(&p); owner_test_clean(t,&b)
	}
	p: Server_Handshake; b := Owner_Test_Audit{backing=context.allocator}
	server_handshake_init(&p,{len(wire)-1,128},owner_test_allocator(&b))
	n,_,e := server_handshake_feed(&p,.Initial,wire)
	testing.expect_value(t,n,4); testing.expect_value(t,e,.Limit); testing.expect_value(t,b.calls,0)
	server_handshake_destroy(&p)
}

@(test)
server_owner_events_order_and_exact_hash :: proc(t: ^testing.T) {
	wire := transmute([]u8)#load("testdata/server_go_client_hello.wire")
	a := Owner_Test_Audit{backing=context.allocator}; o: Server_Handshake
	owner_test_ready(t,&o,&a,wire)
	defer server_handshake_destroy(&o)
	before := transcript_snapshot(&o._transcript)
	bytes := []u8{2,0,0,2,0x12,0x34}
	testing.expect_value(t,server_handshake_publish(&o,{kind=.Handshake_Bytes,level=.Initial,bytes=bytes}),.None)
	event,_ := server_handshake_peek(&o)
	bytes[4]=0xee
	testing.expect_value(t,event.bytes[4],u8(0x12))
	testing.expect_value(t,transcript_snapshot(&o._transcript),before)
	testing.expect_value(t,server_handshake_publish(&o,{kind=.Complete}),.Invalid_State)
	testing.expect_value(t,server_handshake_accept(&o,event.id+1),.Invalid_Event)
	testing.expect_value(t,server_handshake_accept(&o,event.id),.None)
	want := o._transcript; transcript_init(&want); transcript_update(&want,wire); transcript_update(&want,([]u8){2,0,0,2,0x12,0x34})
	testing.expect_value(t,transcript_snapshot(&o._transcript),transcript_snapshot(&want))
	testing.expect(t,mem.check_zero(o._output))
	for direction in ([]Server_Handshake_Direction{.Read,.Write}) {
		secret: [32]u8; for &v in secret[:] {v=0x77}
		testing.expect_value(t,server_handshake_publish(&o,{kind=.Traffic_Secret,level=.Handshake,direction=direction,cipher=.AES_128_GCM_SHA256,secret=secret[:]}),.None)
		key,_ := server_handshake_peek(&o)
		testing.expect(t,key.id>event.id); testing.expect_value(t,key.direction,direction)
		for &v in secret[:] {v=0}
		testing.expect_value(t,key.secret[0],u8(0x77))
		testing.expect_value(t,server_handshake_accept(&o,event.id),.Invalid_Event)
		testing.expect_value(t,key.secret[0],u8(0x77))
		testing.expect_value(t,server_handshake_accept(&o,key.id),.None)
		testing.expect(t,mem.check_zero(o._secret[:]))
	}
	stats,_ := server_handshake_stats(&o)
	testing.expect_value(t,stats.live_bytes,len(wire)+2048)
	testing.expect_value(t,stats.peak_bytes,a.peak); testing.expect_value(t,stats.requested_bytes,a.requested)
	server_handshake_destroy(&o); owner_test_clean(t,&a)
}

@(test)
server_owner_pending_event_cancellation :: proc(t: ^testing.T) {
	wire := transmute([]u8)#load("testdata/server_go_client_hello.wire")
	for kind in ([]Server_Handshake_Event_Kind{.Peer_Parameters,.Handshake_Bytes,.Traffic_Secret,.Complete,.Fatal}) {
		for destroy in ([]bool{false,true}) {
			a := Owner_Test_Audit{backing=context.allocator}; o: Server_Handshake
			server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,owner_test_allocator(&a))
			server_handshake_feed(&o,.Initial,wire)
			if kind != .Peer_Parameters {
				event,_:=server_handshake_peek(&o); server_handshake_accept(&o,event.id)
				secret:[32]u8; secret[0]=0x77
				if kind == .Fatal {server_handshake_fail(&o,.Unsupported)} else {
					testing.expect_value(t,server_handshake_publish(&o,{kind=kind,level=.Handshake,cipher=.AES_128_GCM_SHA256,bytes=([]u8){11,0,0,0},secret=secret[:]}),.None)
				}
			}
			event,_ := server_handshake_peek(&o)
			testing.expect_value(t,event.kind,kind)
			if destroy {server_handshake_destroy(&o)} else {server_handshake_abort(&o)}
			testing.expect(t,mem.check_zero(o._secret[:]) && mem.check_zero_ptr(&o._transcript,size_of(o._transcript)))
			testing.expect_value(t,server_handshake_accept(&o,event.id),.Invalid_Event)
			for _ in 0..<3 {server_handshake_abort(&o); server_handshake_destroy(&o)}
			owner_test_clean(t,&a)
		}
	}
}

@(test)
server_owner_allocator_failures_and_abnormal_grants :: proc(t: ^testing.T) {
	wire := transmute([]u8)#load("testdata/server_go_client_hello.wire")
	for fail_at in 1..=2 {
		a := Owner_Test_Audit{backing=context.allocator,fail_at=fail_at}; o: Server_Handshake
		server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,owner_test_allocator(&a))
		n,status,e := server_handshake_feed(&o,.Initial,wire)
		if fail_at == 1 {
			testing.expect_value(t,n,4); testing.expect_value(t,status,.Terminal); testing.expect_value(t,e,.Allocation_Failed)
		} else {
			event,_:=server_handshake_peek(&o); server_handshake_accept(&o,event.id)
			testing.expect_value(t,server_handshake_publish(&o,{kind=.Handshake_Bytes,bytes=([]u8){2,0,0,0}}),.Allocation_Failed)
		}
		fatal,_:=server_handshake_peek(&o)
		testing.expect_value(t,fatal.kind,.Fatal); testing.expect_value(t,fatal.error,.Allocation_Failed)
		testing.expect_value(t,server_handshake_accept(&o,fatal.id),.None)
		_,terminal,_:=server_handshake_feed(&o,.Initial,wire); testing.expect_value(t,terminal,.Terminal)
		server_handshake_destroy(&o); owner_test_clean(t,&a)
	}
	for delta in ([]int{-1,0,17}) {
		for with_error in ([]bool{false,true}) {
			if delta==0 && !with_error {continue}
			a:=Owner_Test_Audit{backing=context.allocator,delta=delta,error_with_grant=with_error}; o:Server_Handshake
			server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,owner_test_allocator(&a))
			_,_,e:=server_handshake_feed(&o,.Initial,wire)
			testing.expect_value(t,e,.Allocation_Failed)
			server_handshake_destroy(&o); owner_test_clean(t,&a)
			testing.expect_value(t,a.freed,1)
		}
	}
}

@(test)
server_owner_wrong_level_partial_cancel_and_borrowed_der :: proc(t: ^testing.T) {
	wire := transmute([]u8)#load("testdata/server_go_client_hello.wire")
	for split in 0..<len(wire) {
		a:=Owner_Test_Audit{backing=context.allocator}; o:Server_Handshake
		server_handshake_init(&o,SERVER_HANDSHAKE_DEFAULT_CONFIG,owner_test_allocator(&a))
		server_handshake_feed(&o,.Initial,wire[:split])
		n,_,e:=server_handshake_feed(&o,.Handshake,wire[split:])
		testing.expect_value(t,n,0); testing.expect_value(t,e,.Wrong_Level)
		server_handshake_destroy(&o); owner_test_clean(t,&a)
	}
	a:=Owner_Test_Audit{backing=context.allocator}; o:Server_Handshake
	owner_test_ready(t,&o,&a,wire)
	der:=[]u8{11,0,0,0}
	testing.expect_value(t,server_handshake_publish(&o,{kind=.Handshake_Bytes,level=.Handshake,bytes=der},true),.None)
	event,_:=server_handshake_peek(&o)
	testing.expect(t,raw_data(event.bytes)==raw_data(der)); testing.expect_value(t,a.calls,1)
	server_handshake_abort(&o)
	testing.expect_value(t,der[0],u8(11)) // Shared immutable DER must never be erased.
	server_handshake_destroy(&o); owner_test_clean(t,&a)
}

@(test)
server_owner_hard_caps_and_identity_exhaustion :: proc(t: ^testing.T) {
	storage := make([]u8,65536); defer delete(storage)
	padding := make([]u8,65536); defer delete(padding)
	share:=hello_test_share(); extensions:=hello_test_extensions(share[:])
	initial:=hello_test_wire(storage,extensions[:])
	extensions[4].data=padding[:65536-len(initial)+1]
	wire:=hello_test_wire(storage,extensions[:])
	testing.expect_value(t,len(wire),65536)
	a:=Owner_Test_Audit{backing=context.allocator}; o:Server_Handshake
	owner_test_ready(t,&o,&a,wire)
	output: [2049]u8; output[0]=11
	testing.expect_value(t,server_handshake_publish(&o,{kind=.Handshake_Bytes,level=.Handshake,bytes=output[:]}),.Invalid_Event)
	testing.expect_value(t,a.calls,1)
	testing.expect_value(t,server_handshake_publish(&o,{kind=.Handshake_Bytes,level=.Handshake,bytes=output[:2048]}),.None)
	event,_:=server_handshake_peek(&o)
	testing.expect_value(t,len(event.bytes),2048)
	testing.expect_value(t,server_handshake_accept(&o,event.id),.None)
	stats,_:=server_handshake_stats(&o)
	testing.expect_value(t,stats.peak_bytes,67584)
	testing.expect_value(t,stats.requested_bytes,67584)
	fmt.printf("recordless max CH+scratch: requested=%d peak=%d live=%d bytes, allocations=%d\n",stats.requested_bytes,stats.peak_bytes,stats.live_bytes,stats.allocation_attempts)
	o._next_id=max(u64)
	testing.expect_value(t,server_handshake_publish(&o,{kind=.Complete}),.Identity_Exhausted)
	_,status,e:=server_handshake_feed(&o,.Initial,wire)
	testing.expect_value(t,status,.Terminal); testing.expect_value(t,e,.Identity_Exhausted)
	server_handshake_destroy(&o); owner_test_clean(t,&a)
}

@(test)
server_owner_output_grant_failures_and_rejected_events :: proc(t: ^testing.T) {
	wire:=transmute([]u8)#load("testdata/server_go_client_hello.wire")
	for delta in ([]int{-1,0,17}) {
		for with_error in ([]bool{false,true}) {
			if delta==0 && !with_error {continue}
			a:=Owner_Test_Audit{backing=context.allocator}; o:Server_Handshake
			owner_test_ready(t,&o,&a,wire)
			a.delta,a.error_with_grant=delta,with_error
			testing.expect_value(t,server_handshake_publish(&o,{kind=.Handshake_Bytes,bytes=([]u8){2,0,0,0}}),.Allocation_Failed)
			server_handshake_destroy(&o); owner_test_clean(t,&a)
			testing.expect_value(t,a.freed,2)
		}
	}
	a:=Owner_Test_Audit{backing=context.allocator}; o:Server_Handshake
	owner_test_ready(t,&o,&a,wire)
	for event in ([]Server_Handshake_Event{{kind=.None},{kind=.Fatal},{kind=.Peer_Parameters},
		{kind=.Handshake_Bytes},{kind=.Handshake_Bytes,level=.Application,bytes=([]u8){1}},
		{kind=.Traffic_Secret,secret=([]u8){1}}}) {
		testing.expect_value(t,server_handshake_publish(&o,event),.Invalid_Event)
	}
	testing.expect_value(t,a.calls,1)
	server_handshake_destroy(&o); owner_test_clean(t,&a)
}
