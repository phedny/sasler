package sasler

// singleMessageClient is used for the client-side implementation of mechanisms
// that only send a single message from client to server, and don't expect a
// challenge as reply.
type singleMessageClient struct {
	name string
	ir   []byte
}

// Mech returns the mechanism name, and true for client-first.
func (m *singleMessageClient) Mech() (string, bool) {
	return m.name, true
}

// Data returns the initial response when first called, and returns the
// ErrInvalidState error on subsequents call.
func (m *singleMessageClient) Data(challenge []byte) ([]byte, error) {
	if m.ir == nil {
		return nil, ErrInvalidState
	}
	if len(challenge) > 0 {
		return nil, ErrInvalidMessage
	}
	ir := m.ir
	m.ir = nil
	return ir, nil
}

// singleMessageServer is used for the server-side implementation of mechanisms
// that only send a single message from client to server, and don't expect a
// challenge as reply.
type singleMessageServer struct {
	name  string
	authz string
	cb    func([]byte) (string, error)
}

// Mech returns the mechanism name, and true for client-first.
func (m *singleMessageServer) Mech() (string, bool) {
	return m.name, true
}

// Data accepts the initial response when first called, checking the data using
// the cb callback function, and returns the ErrInvalidState error on
// subsequent calls.
func (m *singleMessageServer) Data(ir []byte) ([]byte, error) {
	if m.cb == nil {
		return nil, ErrInvalidState
	}
	authz, err := m.cb(ir)
	if err == nil {
		m.authz = authz
	}
	m.cb = nil
	return nil, err
}

// HasCompleted returns true if Data has been called once, and if true, it also
// returns the authorized authz, if any.
func (m *singleMessageServer) HasCompleted() (bool, string) {
	if m.cb != nil {
		return false, ""
	}
	return true, m.authz
}
