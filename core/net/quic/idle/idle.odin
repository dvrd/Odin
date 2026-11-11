// Monotonic millisecond idle lifetime, independent of request and handshake budgets.
package idle

State :: struct {
 initialized:bool,
 local_ms,peer_ms:u64,
 last_activity:i64,
 sent_after_receive:bool,
}
configure :: proc(s:^State,local_ms,peer_ms:u64,now:i64)->bool {
 if s==nil||now<0 {return false}
 if !s.initialized {s.initialized=true;s.last_activity=now}
 s.local_ms=local_ms;s.peer_ms=peer_ms;return true
}
negotiated :: proc(s:^State)->u64 {
 if s==nil||!s.initialized {return 0}
 if s.local_ms==0 {return s.peer_ms};if s.peer_ms==0 {return s.local_ms};return min(s.local_ms,s.peer_ms)
}
saturating_add :: proc(a,b:i64)->i64 {if b<0||a>max(i64)-b {return max(i64)};return a+b}
period :: proc(s:^State,base_pto:i64)->i64 {
 value:=negotiated(s);if value==0 {return 0}
 floor:=max(i64) if base_pto>max(i64)/3 else 3*max(base_pto,0)
 return max(i64(min(value,u64(max(i64)))),floor)
}
deadline :: proc(s:^State,base_pto:i64)->(i64,bool) {
 delay:=period(s,base_pto);if delay==0 {return 0,false};return saturating_add(s.last_activity,delay),true
}
expired :: proc(s:^State,base_pto,now:i64)->bool {at,armed:=deadline(s,base_pto);return armed&&now>=at}
received :: proc(s:^State,now:i64) {
 if s==nil||!s.initialized||now<s.last_activity {return};s.last_activity=now;s.sent_after_receive=false
}
sent :: proc(s:^State,now:i64,ack_eliciting:bool) {
 if s==nil||!s.initialized||!ack_eliciting||s.sent_after_receive||now<s.last_activity {return}
 s.last_activity=now;s.sent_after_receive=true
}
