package tls

import "core:crypto"
import "core:mem"
import "core:net"
import "core:time"
import credential_store "credentials/store"

SERVER_ASYNC_MAX_OWNED_BYTES :: 256*1024
Server_Async_Init_Error :: enum {None, Invalid_Owner, Invalid_State, Invalid_Config, Invalid_Transport}
Server_Async_Failure_Kind :: enum {None, Invalid_State, Handshake, Record, Transport, Limit, Unexpected_EOF, Peer_Alert, Post_Handshake}
Server_Async_Failure :: struct {
	kind: Server_Async_Failure_Kind,
	engine: Server_Handshake_Error,
	protection: Record_Protection_Error,
	record: Record_Error,
	transport: net.Connection_Error,
	wire_transferred: int,
	alert_level, alert_description: u8,
}
Server_Async_Config :: struct {
	store: ^credential_store.Store,
	// Zero uses the actual clock at admission. Nonzero is an explicit host clock.
	credential_time: time.Time,
	handshake_timeout, close_timeout: time.Duration,
	max_owned_bytes, max_handshake_records: int,
	handshake: Server_Handshake_Config,
	parameters: Server_Handshake_Parameters_Config, // TCP only; preferences borrow until handshake completion.
}
Server_Async_Handshake_Operation :: struct {
	callback: proc(^Server_Async_Handshake_Operation),
	user_data: rawptr,
	pending: bool,
	err: net.Connection_Error,
	result: Server_Async_Failure,
}
Server_Async_Stats :: struct {
	live_bytes, peak_bytes, requested_bytes, allocation_attempts: int,
	read_records, written_records, received_key_updates, sent_key_updates: int,
	engine: Server_Handshake_Stats, // Subset of owned bytes, not additional bytes.
}
@(private)
Server_Async_Phase :: enum {Uninitialized, Ready, Handshaking, Established, Closed}
@(private)
Server_Async_Send :: enum {None, Handshake, Data, Key_Update, Notify, Fatal_Alert}
@(private)
Server_Async_Keys :: struct {
	read, write: Record_Protection,
	application_read, application_write: [32]u8,
}

// Stable-address, serial owner. Calls/callbacks use the supplied executor's
// thread. Success transfers the transport; keep all state alive until close
// callback, the only callback permitted to free this owner. No copies/reentry
// from other threads. The backend/executor/allocator/store must outlive close.
Server_Async_Conn :: struct {
	_self: ^Server_Async_Conn,
	_transport: net.Async_Connection,
	_executor: net.Async_Executor,
	_allocator: mem.Allocator,
	_config: Server_Async_Config,
	_phase: Server_Async_Phase,
	_engine: Server_Handshake,
	_stats: Server_Async_Stats,
	_failure, _close_error: net.Connection_Error,
	_detail: Server_Async_Failure,
	_queued, _closing, _transport_closing, _transport_closed, _cleaned: bool,
	_notify_allowed, _notify_sent, _peer_closed: bool,
	_fatal_alert_allowed, _fatal_alert_sent: bool,
	_fatal_alert: u8,
	_handshake_op: ^Server_Async_Handshake_Operation,
	_handshake_deadline, _close_deadline: time.Time,
	_read_op, _write_op, _close_op: ^net.Async_Operation,
	_read_buffer, _write_buffer: []u8,
	_read_deadline, _write_deadline: time.Time,
	_read_cancel, _write_cancel: bool,
	_rx, _tx, _shutdown: net.Async_Operation,
	_rx_header: [5]u8,
	_rx_header_used, _rx_used, _rx_expected: int,
	_rx_into_header: bool,
	_rx_error: net.Connection_Error,
	_rx_wire, _rx_plain, _tx_wire, _key_grant: []u8,
	_read_keys, _write_keys: bool,
	_application_secrets: u8,
	_tx_kind: Server_Async_Send,
	_tx_size, _tx_plain_count: int,
	_tx_done: bool,
	_engine_event: u64,
	_plain_at, _plain_size: int,
	_handshake_records, _non_application_records: int,
	_ccs_allowed: bool,
	_post: [5]u8,
	_post_used: int,
	_key_update_pending, _key_update_request: bool,
	_alpn: [255]u8,
	_name: [253]u8,
	_alpn_size, _name_size: int,
}

@(private)
server_async_valid :: proc(s:^Server_Async_Conn) -> bool {return s!=nil && s._self==s}

server_async_server :: proc(s:^Server_Async_Conn, transport:net.Async_Connection, executor:net.Async_Executor, source:Server_Async_Config, allocator:mem.Allocator) -> Server_Async_Init_Error {
	if s==nil {return .Invalid_Owner}
	if s._self!=nil {return .Invalid_State}
	if transport.submit==nil || transport.cancel==nil || executor.schedule==nil {return .Invalid_Transport}
	config:=source
	if config.handshake_timeout==0 {config.handshake_timeout=10*time.Second}
	if config.close_timeout==0 {config.close_timeout=time.Second}
	if config.max_owned_bytes==0 {config.max_owned_bytes=SERVER_ASYNC_MAX_OWNED_BYTES}
	if config.max_handshake_records==0 {config.max_handshake_records=4096}
	if config.handshake==(Server_Handshake_Config{}) {config.handshake=SERVER_HANDSHAKE_DEFAULT_CONFIG}
	_,valid:=alpn_protocols_size(config.parameters.alpn_protocols)
	if allocator.procedure==nil || config.store==nil || !valid || config.parameters.mode!=.TCP ||
	   len(config.parameters.quic_transport_parameters)!=0 || config.handshake_timeout<0 || config.close_timeout<0 ||
	   config.max_owned_bytes<1024 || config.max_owned_bytes>SERVER_ASYNC_MAX_OWNED_BYTES ||
	   config.max_handshake_records<1 || config.max_handshake_records>65536 ||
	   config.parameters.require_alpn && len(config.parameters.alpn_protocols)==0 {return .Invalid_Config}
	for name,i in config.parameters.alpn_protocols {for old in config.parameters.alpn_protocols[:i] {if name==old {return .Invalid_Config}}}
	// Validate all engine limits without mutating the destination/transport.
	if config.handshake.max_client_hello_bytes<45 || config.handshake.max_client_hello_bytes>SERVER_CLIENT_HELLO_MAX_WIRE ||
	   config.handshake.max_extensions<1 || config.handshake.max_extensions>SERVER_CLIENT_HELLO_MAX_ENTRIES {return .Invalid_Config}
	s._self,s._transport,s._executor,s._allocator,s._config,s._phase=s,transport,executor,allocator,config,.Ready
	assert(server_handshake_init(&s._engine,config.handshake,{server_async_allocator,s})==.None)
	s._rx={callback=server_async_receive_done,user_data=s}
	s._tx={callback=server_async_send_done,user_data=s}
	s._shutdown={callback=server_async_shutdown_done,user_data=s}
	return .None
}

server_async_handshake :: proc(s:^Server_Async_Conn, op:^Server_Async_Handshake_Operation, deadline:=time.Time{}) -> net.Connection_Error {
	if !server_async_valid(s) {return {kind=.Invalid_Connection}}
	if op==nil || op.callback==nil {return {kind=.Invalid_Operation}}
	if s._closing || s._transport_closed {return {kind=.Closed}}
	if op.pending || s._handshake_op!=nil {return {kind=.Operation_Pending}}
	if s._failure.kind!=.None {return s._failure}
	if s._phase!=.Ready && s._phase!=.Established {return {kind=.Invalid_Connection}}
	op.pending,op.err,op.result=true,{},{}
	s._handshake_op=op
	if s._phase==.Ready {
		s._phase=.Handshaking
		s._handshake_deadline=time.time_add(time.now(),s._config.handshake_timeout)
		if deadline!=(time.Time{}) && time.diff(deadline,s._handshake_deadline)>0 {s._handshake_deadline=deadline}
	}
	server_async_queue(s);return {}
}
server_async_cancel_handshake :: proc(s:^Server_Async_Conn) -> net.Connection_Error {
	if !server_async_valid(s) {return {kind=.Invalid_Connection}}
	if s._handshake_op!=nil && s._phase!=.Established {server_async_fail(s,{kind=.Cancelled},{kind=.Handshake,engine=.Cancelled})}
	return {}
}
server_async_connection :: proc(s:^Server_Async_Conn) -> net.Async_Connection {
	if !server_async_valid(s) {return {}}
	return {data=s,submit=server_async_submit,cancel=server_async_cancel}
}
server_async_connection_state :: proc(s:^Server_Async_Conn) -> Connection_State {
	if !server_async_valid(s) || s._phase!=.Established || s._failure.kind!=.None || s._closing {return {}}
	return {handshake_complete=true,version=VERSION_TLS_1_3,cipher_suite=.AES_128_GCM_SHA256,
		server_name=string(s._name[:s._name_size]),negotiated_protocol=string(s._alpn[:s._alpn_size])}
}
server_async_failure :: proc(s:^Server_Async_Conn) -> Server_Async_Failure {
	if !server_async_valid(s) {return {kind=.Invalid_State}}
	return s._detail
}
server_async_stats :: proc(s:^Server_Async_Conn) -> Server_Async_Stats {
	if !server_async_valid(s) {return {}}
	result:=s._stats;result.engine,_=server_handshake_stats(&s._engine);return result
}
// Bounded control request, serialized with all record writes. Completion/error
// belongs to the connection; this does not borrow an operation or caller bytes.
server_async_key_update :: proc(s:^Server_Async_Conn, request_peer:=false) -> net.Connection_Error {
	if !server_async_valid(s) || s._phase!=.Established {return {kind=.Invalid_Connection}}
	if s._closing || s._transport_closed {return {kind=.Closed}}
	if s._failure.kind!=.None {return s._failure}
	if s._key_update_pending || s._tx_kind==.Key_Update {return {kind=.Operation_Pending}}
	s._key_update_pending,s._key_update_request=true,request_peer
	server_async_queue(s);return {}
}

@(private)
server_async_allocator :: proc(data:rawptr, mode:mem.Allocator_Mode, size,alignment:int, old:rawptr,old_size:int,loc:=#caller_location) -> ([]u8,mem.Allocator_Error) {
	s:=cast(^Server_Async_Conn)data
	#partial switch mode {
	case .Alloc:
		s._stats.allocation_attempts+=1;s._stats.requested_bytes+=size
		if size<0 || size>s._config.max_owned_bytes-s._stats.live_bytes {return nil,.Out_Of_Memory}
		grant,e:=s._allocator.procedure(s._allocator.data,mode,size,alignment,nil,0,loc)
		if e!=nil || len(grant)!=size || raw_data(grant)==nil {
			if raw_data(grant)!=nil {crypto.zero_explicit(raw_data(grant),len(grant));_,_=s._allocator.procedure(s._allocator.data,.Free,0,alignment,raw_data(grant),len(grant),loc)}
			return nil,.Out_Of_Memory
		}
		crypto.zero_explicit(raw_data(grant),len(grant))
		s._stats.live_bytes+=size;s._stats.peak_bytes=max(s._stats.peak_bytes,s._stats.live_bytes)
		return grant,nil
	case .Free:
		if old!=nil {crypto.zero_explicit(old,old_size);s._stats.live_bytes-=old_size}
		return s._allocator.procedure(s._allocator.data,mode,size,alignment,old,old_size,loc)
	case: return nil,.Mode_Not_Implemented
	}
}
@(private)
server_async_grant :: proc(s:^Server_Async_Conn,slot:^[]u8,size:int,alignment:=1) -> bool {
	if len(slot^)!=0 {return true}
	grant,e:=server_async_allocator(s,.Alloc,size,alignment,nil,0)
	if e!=nil {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Limit,engine=.Allocation_Failed});return false}
	slot^=grant;return true
}
@(private)
server_async_free :: proc(s:^Server_Async_Conn,slot:^[]u8,alignment:=1) {
	if raw_data(slot^)==nil {return}
	_,_=server_async_allocator(s,.Free,0,alignment,raw_data(slot^),len(slot^));slot^=nil
}
@(private)
server_async_keys :: proc(s:^Server_Async_Conn) -> ^Server_Async_Keys {return cast(^Server_Async_Keys)raw_data(s._key_grant)}
@(private)
server_async_queue :: proc(s:^Server_Async_Conn) {
	if !s._queued {s._queued=true;s._executor.schedule(s._executor.data,server_async_pump,s)}
}
@(private)
server_async_fail :: proc(s:^Server_Async_Conn,e:net.Connection_Error,detail:Server_Async_Failure) {
	if s._failure.kind==.None {
		s._failure,s._detail=e,detail
		if e.kind==.Protocol_Failed && detail.kind!=.Transport && detail.kind!=.Unexpected_EOF && detail.kind!=.Peer_Alert && !s._tx.pending && !s._tx_done {
			s._fatal_alert_allowed=true;s._fatal_alert=server_async_alert(detail)
			s._close_deadline=time.time_add(time.now(),s._config.close_timeout)
		}
	}
	server_async_queue(s)
}
@(private)
server_async_emit :: proc(s:^Server_Async_Conn,kind:net.Async_Operation_Kind,e:net.Connection_Error) {
	op:=s._read_op if kind==.Read else s._write_op;if op==nil {return}
	if kind==.Read {s._read_op=nil;s._read_buffer=nil} else {s._write_op=nil;s._write_buffer=nil}
	op.pending,op._owner,op.result.err=false,nil,e;op.callback(op)
}
@(private)
server_async_handshake_emit :: proc(s:^Server_Async_Conn,e:net.Connection_Error) {
	op:=s._handshake_op;if op==nil {return};s._handshake_op=nil
	op.pending,op.err,op.result=false,e,s._detail;op.callback(op)
}
@(private)
server_async_submit :: proc(data:rawptr,op:^net.Async_Operation,kind:net.Async_Operation_Kind,buffer:[]u8,deadline:time.Time) -> net.Connection_Error {
	s:=cast(^Server_Async_Conn)data
	if !server_async_valid(s) {return {kind=.Invalid_Connection}}
	if kind!=.Close {
		if s._closing || s._transport_closed {return {kind=.Closed}}
		if s._failure.kind!=.None {return s._failure}
		if s._phase!=.Established {return {kind=.Invalid_Connection}}
	}
	switch kind {
	case .Read:
		if s._read_op!=nil {return {kind=.Operation_Pending}}
		s._read_op,s._read_buffer,s._read_deadline,s._read_cancel=op,buffer,deadline,false
	case .Write:
		if s._write_op!=nil {return {kind=.Operation_Pending}}
		s._write_op,s._write_buffer,s._write_deadline,s._write_cancel=op,buffer,deadline,false
	case .Close:
		if s._close_op!=nil {return {kind=.Operation_Pending}}
		s._close_op,s._closing=op,true
		s._close_deadline=time.time_add(time.now(),s._config.close_timeout)
		s._notify_allowed=s._phase==.Established && s._failure.kind==.None && !s._tx.pending && !s._tx_done
	}
	op.kind,op.pending,op.result,op._owner=kind,true,{},s
	server_async_queue(s);return {}
}
@(private)
server_async_cancel :: proc(data:rawptr,op:^net.Async_Operation) -> net.Connection_Error {
	s:=cast(^Server_Async_Conn)data
	if !server_async_valid(s) {return {kind=.Invalid_Connection}}
	if !op.pending {return {}}
	if op._owner!=s || op.kind==.Close {return {kind=.Invalid_Operation}}
	if op==s._read_op {s._read_cancel=true;if s._rx.pending {_=net.async_cancel(s._transport,&s._rx)}} else if op==s._write_op {
		s._write_cancel=true;if s._tx.pending && s._tx_kind==.Data {_=net.async_cancel(s._transport,&s._tx)}
	} else {return {kind=.Invalid_Operation}}
	server_async_queue(s);return {}
}
@(private)
server_async_pump :: proc(data:rawptr) {
	s:=cast(^Server_Async_Conn)data;s._queued=false
	if s._tx_done {s._tx_done=false;server_async_send_process(s)}
	if s._closing || s._failure.kind!=.None {server_async_shutdown_drive(s);return}
	if s._phase==.Handshaking {server_async_handshake_drive(s);return}
	if s._phase==.Established {
		if s._handshake_op!=nil {server_async_handshake_emit(s,{});return}
		server_async_application_drive(s)
	}
}
@(private)
server_async_shutdown_done :: proc(op:^net.Async_Operation) {
	s:=cast(^Server_Async_Conn)op.user_data;s._transport_closed=true
	if s._close_error.kind==.None {s._close_error=op.result.err};server_async_queue(s)
}
@(private)
server_async_cleanup :: proc(s:^Server_Async_Conn) {
	if s._cleaned {return};s._cleaned=true
	_=server_handshake_destroy(&s._engine)
	server_async_free(s,&s._key_grant,align_of(Server_Async_Keys))
	server_async_free(s,&s._rx_wire);server_async_free(s,&s._rx_plain);server_async_free(s,&s._tx_wire)
	crypto.zero_explicit(&s._rx_header,size_of(s._rx_header));crypto.zero_explicit(&s._post,size_of(s._post))
	crypto.zero_explicit(&s._alpn,size_of(s._alpn));crypto.zero_explicit(&s._name,size_of(s._name))
	s._alpn_size,s._name_size,s._post_used,s._plain_at,s._plain_size=0,0,0,0,0
	s._read_keys,s._write_keys,s._key_update_pending,s._key_update_request=false,false,false,false
	s._config={};s._phase=.Closed
}
@(private)
server_async_shutdown_drive :: proc(s:^Server_Async_Conn) {
	if s._rx.pending {_=net.async_cancel(s._transport,&s._rx)}
	if s._tx.pending {if s._tx_kind!=.Notify && s._tx_kind!=.Fatal_Alert {_=net.async_cancel(s._transport,&s._tx)};return}
	if s._rx.pending {return}
	if s._fatal_alert_allowed && !s._fatal_alert_sent {
		s._fatal_alert_allowed=false
		if server_async_send_record(s,.Alert,[]u8{2,s._fatal_alert},.Fatal_Alert,s._close_deadline) {return}
	}
	if s._notify_allowed && !s._notify_sent && s._failure.kind==.None && time.diff(time.now(),s._close_deadline)>0 {
		s._notify_allowed=false
		if server_async_send_record(s,.Alert,[]u8{1,0},.Notify,s._close_deadline) {return}
	}
	if !s._transport_closing {
		s._transport_closing=true
		e:=net.async_close(s._transport,&s._shutdown)
		if e.kind!=.None {s._close_error=e;s._transport_closed=true}
	}
	if !s._transport_closed || s._queued {return}
	server_async_cleanup(s)
	e:=s._failure;if s._closing {e={kind=.Closed}}
	server_async_handshake_emit(s,e);server_async_emit(s,.Read,e);server_async_emit(s,.Write,e)
	if s._queued {return}
	if s._close_op!=nil {
		op:=s._close_op;s._close_op=nil
		op.pending,op._owner,op.result.err=false,nil,s._close_error;op.callback(op)
		return // close callback may free s and op.
	}
}

@(private)
server_async_alert :: proc(detail:Server_Async_Failure) -> u8 {
	if detail.kind==.Limit {return 80}
	if detail.kind==.Post_Handshake {return 10}
	if detail.kind==.Handshake {
		#partial switch detail.engine {
		case .No_Application_Protocol:return 120
		case .Finished_Failed:return 51
		case .Malformed:return 50
		case .Wrong_Level:return 10
		case .Unsupported:return 40
		case:return 80
		}
	}
	if detail.protection==.Authentication_Failed {return 20}
	if detail.protection==.Invalid_Legacy_Version {return 70}
	if detail.protection==.Record_Oversized || detail.record==.Record_Oversized {return 22}
	return 10
}
