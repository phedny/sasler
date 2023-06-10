package sasler

import (
	"bytes"
	"strconv"
)

// OAuthBearerClient returns a ClientMech implementation for the OAUTHBEARER
// mechanism, as specified in [RFC 7628].
//
// [RFC 7628]: https://tools.ietf.org/html/rfc7628.
func OAuthBearerClient(authz string, token []byte, host string, port int) ClientMech {
	var b bytes.Buffer
	b.WriteString("n,")
	if authz != "" {
		b.WriteString("a=")
		b.WriteString(authz)
	}
	b.WriteByte(',')
	if host != "" {
		b.WriteString("\x01host=")
		b.WriteString(host)
	}
	if port != 0 {
		b.WriteString("\x01port=")
		b.WriteString(strconv.Itoa(port))
	}
	b.WriteString("\x01auth=Bearer ")
	b.Write(token)
	b.WriteString("\x01\x01")
	return &singleMessageClient{name: "OAUTHBEARER", ir: b.Bytes()}
}

// OAuthBearerAuthenticator is supplied to [OAuthBearerServer] to implement
// token verification, authz derivation and authorization checking.
type OAuthBearerAuthenticator interface {
	// VerifyToken verifies whether the supplied token is valid. The host and/or
	// port values default to "" and 0 respectively, if not provided by the
	// client. Return false to fail authentication.
	VerifyToken(token []byte, host string, port int) bool
	// DeriveAuthz derives an authz from a token. It is only called when no authz
	// has been requested by the client. Return the empty string if no authz can
	// be derived from the supplied token.
	DeriveAuthz(token []byte) string
	// Authorize verifies whether the provided token is authorized to use the
	// requested or derived authz. Return false to fail authorization.
	Authorize(authz string, token []byte) bool
}

// OAuthBearerServer returns a ServerMech implementation for the OAUTHBEARER
// mechanism, as specified in [RFC 7628].
//
// [RFC 7628]: https://tools.ietf.org/html/rfc7628.
func OAuthBearerServer(auth OAuthBearerAuthenticator) ServerMech {
	cb := func(ir []byte) (string, error) {
		if len(ir) < 2 || ir[0] != 'n' || ir[1] != ',' {
			return "", ErrInvalidMessage
		}
		ir = ir[2:]
		if len(ir) < 6 {
			return "", ErrInvalidMessage
		}
		authz := ""
		if ir[0] == 'a' {
			if len(ir) < 2 || ir[1] != '=' {
				return "", ErrInvalidMessage
			}
			ir = ir[2:]
			comma := bytes.IndexByte(ir, ',')
			if comma == -1 {
				return "", ErrInvalidMessage
			}
			authz = string(ir[:comma])
			ir = ir[comma+1:]
			if len(ir) < 6 {
				return "", ErrInvalidMessage
			}
		}
		host := ""
		if string(ir[:6]) == "\x01host=" {
			ir = ir[6:]
			delim := bytes.IndexByte(ir, 1)
			if delim == -1 {
				return "", ErrInvalidMessage
			}
			host = string(ir[:delim])
			ir = ir[delim:]
			if len(ir) < 6 {
				return "", ErrInvalidMessage
			}
		}
		port := 0
		if string(ir[:6]) == "\x01port=" {
			ir = ir[6:]
			delim := bytes.IndexByte(ir, 1)
			if delim == -1 {
				return "", ErrInvalidMessage
			}
			portS := string(ir[:delim])
			portI, err := strconv.Atoi(portS)
			if err != nil {
				return "", ErrInvalidMessage
			}
			port = portI
			ir = ir[delim:]
			if len(ir) < 6 {
				return "", ErrInvalidMessage
			}
		}
		if string(ir[:6]) != "\x01auth=" {
			return "", ErrInvalidMessage
		}
		ir = ir[6:]
		if len(ir) < 7 || string(ir[:7]) != "Bearer " {
			return "", ErrWrongCurve
		}
		ir = ir[7:]
		delim := bytes.IndexByte(ir, 1)
		if delim == -1 {
			return "", ErrInvalidMessage
		}
		token := ir[:delim]
		ir = ir[delim:]
		if len(ir) != 2 || ir[0] != 1 || ir[1] != 1 {
			return "", ErrInvalidMessage
		}
		if !auth.VerifyToken(token, host, port) {
			return "", ErrAuthenticationFailed
		}
		if authz == "" {
			authz = auth.DeriveAuthz(token)
			if authz == "" {
				return "", ErrAuthenticationFailed
			}
		}
		if !auth.Authorize(authz, token) {
			return "", ErrUnauthorized
		}
		return authz, nil
	}
	return &singleMessageServer{name: "OAUTHBEARER", cb: cb}
}
