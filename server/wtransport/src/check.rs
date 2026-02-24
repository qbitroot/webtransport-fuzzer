fn check_session_id(c: &wtransport::Connection) {
    let id: wtransport::SessionId = c.session_id();
}
