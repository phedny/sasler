package sasler

// ExternalClient returns a ClientMech implementation for the EXTERNAL
// mechanism, as specified in [RFC 4422, appendix A].
//
// [RFC 4422, appendix A]: https://tools.ietf.org/html/rfc4422#appendix-A
func ExternalClient(authz string) ClientMech {
	if authz == "" {
		return &singleMessageClient{name: "EXTERNAL", ir: []byte{}}
	} else {
		return &singleMessageClient{name: "EXTERNAL", ir: []byte(authz)}
	}
}

// ExternalAuthenticator is supplied to [ExternalServer] to implement authz
// derivation and authorization checking.
type ExternalAuthenticator interface {
	// DeriveAuthz derives an authz from external sources. It is only called when
	// no authz has been requested by the client. Return the empty string if no
	// authz can be derived from external sources.
	DeriveAuthz() string
	// Authorize verifies whether an externally derived identity is authorized to
	// use the requested or derived authz. Return false to fail authorization.
	Authorize(authz string) bool
}

// ExternalServer returns a ServerMech implementation for the EXTERNAL
// mechanism, as specified in [RFC 4422, appendix A].
//
// [RFC 4422, appendix A]: https://tools.ietf.org/html/rfc4422#appendix-A
func ExternalServer(auth ExternalAuthenticator) ServerMech {
	cb := func(ir []byte) (string, error) {
		authz := string(ir)
		if authz == "" {
			authz = auth.DeriveAuthz()
			if authz == "" {
				return "", ErrAuthenticationFailed
			}
		}
		if !auth.Authorize(authz) {
			return "", ErrUnauthorized
		}
		return authz, nil
	}
	return &singleMessageServer{name: "EXTERNAL", cb: cb}
}
