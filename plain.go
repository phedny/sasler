package sasler

import (
	"bytes"

	"github.com/xdg-go/stringprep"
)

// PlainClient returns a ClientMech implementation for the PLAIN mechanism.
func PlainClient(authz, authn, passwd string) ClientMech {
	ir := make([]byte, len(authz)+len(authn)+len(passwd)+2)
	copy(ir, []byte(authz))
	copy(ir[len(authz)+1:], []byte(authn))
	copy(ir[len(authz)+len(authn)+2:], []byte(passwd))
	return &singleMessageClient{name: "PLAIN", ir: ir}
}

// PlainAuthenticator implements password verification, authz derivation and
// authorization checking for a server-side implementation of the PLAIN
// mechanism.
type PlainAuthenticator interface {
	// VerifyPasswd verifies whether the supplied combination of authn and passwd
	// is valid. Return false to fail authentication.
	VerifyPasswd(authn, passwd string) bool
	// DerivceAuthz derives an authz from an authn. It is only called when no
	// authz has been requested by the client. Return the empty string if no
	// authz can be derived from the supplied authn.
	DeriveAuthz(authn string) string
	// Authorize verifies whether an authn is authorized to use the requested or
	// derived authz. Return false to fail authorization.
	Authorize(authz, authn string) bool
}

// PlainServer returns a ServerMech implementation for the PLAIN mechanism.
func PlainServer(auth PlainAuthenticator) ServerMech {
	cb := func(ir []byte) (string, error) {
		delim := bytes.IndexByte(ir, 0)
		if delim == -1 {
			return "", ErrInvalidMessage
		}
		authz := string(ir[:delim])
		ir = ir[delim+1:]
		delim = bytes.IndexByte(ir, 0)
		if delim == -1 {
			return "", ErrInvalidMessage
		}
		authn, err := stringprep.SASLprep.Prepare(string(ir[:delim]))
		if err != nil {
			return "", ErrInvalidMessage
		}
		passwd, err := stringprep.SASLprep.Prepare(string(ir[delim+1:]))
		if err != nil {
			return "", ErrInvalidMessage
		}
		if !auth.VerifyPasswd(authn, passwd) {
			return "", ErrAuthenticationFailed
		}
		if authz == "" {
			authz = auth.DeriveAuthz(authn)
			if authz == "" {
				return "", ErrAuthenticationFailed
			}
		}
		if !auth.Authorize(authz, authn) {
			return "", ErrUnauthorized
		}
		return authz, nil
	}
	return &singleMessageServer{name: "PLAIN", cb: cb}
}
