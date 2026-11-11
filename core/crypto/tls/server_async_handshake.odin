package tls

import "core:crypto"
import "core:time"

@(private)
server_async_handshake_drive :: proc(s:^Server_Async_Conn) {
	if s._tx.pending || s._tx_done {return}
	for _ in 0..<32 {
		if time.diff(time.now(),s._handshake_deadline)<=0 {server_async_fail(s,{kind=.Timeout},{kind=.Handshake});return}
		event,event_error:=server_handshake_peek(&s._engine)
		if event_error!=.None {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=event_error});return}
		switch event.kind {
		case .Fatal: server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=event.error});return
		case .Peer_Parameters:
			s._ccs_allowed=true
			if s._engine._hello.early_data {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=.Unsupported});return}
			s._name_size=copy(s._name[:],event.peer.server_name)
			e:=server_handshake_select_parameters(&s._engine,event.id,s._config.parameters)
			if e!=.None {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=e});return}
			now:=s._config.credential_time;if now==(time.Time{}) {now=time.now()}
			e=server_handshake_start_flight(&s._engine,s._config.store,now)
			if e!=.None {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=e});return}
		case .Handshake_Bytes:
			// A stateful HRR can precede Peer_Parameters. Reject early-data
			// profiles explicitly; this TCP binding never skips/replays 0RTT.
			if s._engine._hello.early_data {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=.Unsupported});return}
			s._ccs_allowed=true
			if event.level!=.Application && (event.level==.Handshake)!=s._write_keys {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=.Wrong_Level});return}
			s._engine_event=event.id
			_=server_async_send_record(s,.Handshake,event.bytes,.Handshake,s._handshake_deadline)
			return
		case .Early_Traffic_Secret: server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=.Unsupported});return
		case .Traffic_Secret:
			if !server_async_grant(s,&s._key_grant,size_of(Server_Async_Keys),align_of(Server_Async_Keys)) {return}
			secret:[32]u8;copy(secret[:],event.secret)
			if event.level==.Handshake {server_async_install(s,event.direction,secret)} else if event.level==.Application {
				keys:=server_async_keys(s)
				if event.direction==.Read {keys.application_read=secret;s._application_secrets|=1} else {keys.application_write=secret;s._application_secrets|=2;server_async_install(s,.Write,secret)}
			} else {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=.Wrong_Level});return}
			// The secret event is wiped by acceptance; only active protections
			// and the two pending/current application secrets survive here. The
			// server write direction changes after its Finished, including alerts;
			// application API readiness still requires authenticated Complete.
			crypto.zero_explicit(&secret,size_of(secret))
			if e:=server_handshake_accept(&s._engine,event.id);e!=.None {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=e});return}
		case .Complete:
			if s._application_secrets!=3 {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=.Invalid_State});return}
			p,e:=server_handshake_parameters(&s._engine)
			if e!=.None || !p.authenticated {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=.Invalid_State});return}
			s._alpn_size=copy(s._alpn[:],p.alpn)
			s._peer_identity=server_handshake_peer_identity(&s._engine)
			s._resumed=server_handshake_resumed(&s._engine)
			if server_handshake_accept(&s._engine,event.id)!=.None {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=.Invalid_Event});return}
			keys:=server_async_keys(s)
			server_async_install(s,.Read,keys.application_read)
			_=server_handshake_destroy(&s._engine)
			s._phase=.Established;s._ccs_allowed=false;s._non_application_records=0
			server_async_handshake_emit(s,{})
			return
		case .None:
			header,ready:=server_async_receive_record(s,s._handshake_deadline);if !ready {return}
			s._handshake_records+=1
			if s._handshake_records>s._config.max_handshake_records {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Limit});return}
			kind:=header.content_type;body:=s._rx_wire[5:s._rx_expected]
			if kind==.Change_Cipher_Spec {
				if !s._ccs_allowed || len(body)!=1 || body[0]!=1 {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Record,record=.Unexpected_Content_Type});return}
				server_async_record_consumed(s);continue
			}
			level:=Server_Handshake_Level.Initial
			if kind==.Application_Data {
				k,b,ok:=server_async_open(s);if !ok {return};kind,body,level=k,b,.Handshake
			} else if s._read_keys {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Record,protection=.Unexpected_Outer_Content_Type});return}
			if kind==.Alert {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Peer_Alert,alert_level=body[0],alert_description=body[1]});return}
			if kind!=.Handshake {server_async_fail(s,{kind=.Protocol_Failed},{kind=.Record,record=.Unexpected_Content_Type});return}
			n,_,e:=server_handshake_feed(&s._engine,level,body)
			if e!=.None || n!=len(body) {
				if e==.None {e=.Malformed};server_async_fail(s,{kind=.Protocol_Failed},{kind=.Handshake,engine=e});return
			}
			server_async_record_consumed(s)
		}
	}
	server_async_queue(s) // Bound one pump's in-memory work without losing progress.
}
