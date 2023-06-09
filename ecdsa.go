package sasler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
)

var ErrInvalidCurve = errors.New("sasler: invalid curve")

// ecdsaClientMech is an implementation of the ECDSA-NIST256P-CHALLENGE
// mechanisms.
type ecdsaClientMech struct {
	authz string
	authn string
	key   *ecdsa.PrivateKey
}

// EcdsaNist256pChallengeClient returns a SaslMech implementation for the
// ECDSA-NIST256P-CHALLENGE mechanism.
func EcdsaNist256pChallengeClient(authz, authn string, key *ecdsa.PrivateKey) (ClientMech, error) {
	if key.Curve != elliptic.P256() {
		return nil, ErrInvalidCurve
	}
	return &ecdsaClientMech{authz, authn, key}, nil
}

// Mech returns name ECDSA-NITS256P-CHALLENGE, and true for client-first.
func (*ecdsaClientMech) Mech() (string, bool) {
	return "ECDSA-NIST256P-CHALLENGE", true
}

// Data returns authcid, prefixed with authzid if present, on the first call;
// and returns a signature for the provided challenge on the second call.
func (m *ecdsaClientMech) Data(challenge []byte) ([]byte, error) {
	switch {
	case m.authn != "":
		if len(challenge) > 0 {
			m.authn = ""
			m.authn = ""
			m.key = nil
			return nil, ErrInvalidMessage
		}
		var ir bytes.Buffer
		if m.authz != "" {
			ir.Write([]byte(m.authz))
			m.authz = ""
			ir.WriteByte(0)
		}
		ir.Write([]byte(m.authn))
		m.authn = ""
		return ir.Bytes(), nil
	case m.key != nil:
		sig, err := ecdsa.SignASN1(rand.Reader, m.key, challenge)
		m.key = nil
		return sig, err
	}
	return nil, ErrInvalidState
}

// EcdsaAuthenticator implements retrieving the public key for an authn, authz
// derivation and authorization checking for a server-side implementation of
// the ECDSA-NIST256P-CHALLENGE mechanism.
type EcdsaAuthenticator interface {
	// GetPublicKey returns the public key for an authn, or an error if the
	// public key could not be retrieved.
	GetPublicKey(authn string) (*ecdsa.PublicKey, error)
	// DeriveAuthz derives an authz from an authn. It is only called when no
	// authz has been requested by the client. Return the empty string if no
	// authz can be derived from the supplied authn.
	DeriveAuthz(authn string) string
	// Authorize verifies whether an authn is authorized to use the requested or
	// derived authz. Return false to fail authorization.
	Authorize(authz, authn string) bool
}

// ecdsaServerMech is an implementation of the ECDSA-NIST256P-CHALLENGE
// mechanisms.
type ecdsaServerMech struct {
	authz     string
	authn     string
	challenge []byte
	key       *ecdsa.PublicKey
	auth      EcdsaAuthenticator
}

// EcdsaNist256pChallengeServer returns a SaslMech implementation for the
// ECDSA-NIST256P-CHALLENGE mechanism.
func EcdsaNist256pChallengeServer(auth EcdsaAuthenticator) ServerMech {
	return &ecdsaServerMech{auth: auth}
}

// Mech returns name ECDSA-NITS256P-CHALLENGE, and true for client-first.
func (*ecdsaServerMech) Mech() (string, bool) {
	return "ECDSA-NIST256P-CHALLENGE", true
}

// Data stores an authn and optional authz on first call and returns a
// challenge, and on second call verifies the response.
func (m *ecdsaServerMech) Data(data []byte) ([]byte, error) {
	switch {
	case m.authn == "":
		delim := bytes.IndexByte(data, 0)
		if delim == -1 {
			m.authn = string(data)
		} else {
			m.authz = string(data[:delim])
			m.authn = string(data[delim+1:])
		}
		publicKey, err := m.auth.GetPublicKey(m.authn)
		if err != nil {
			return nil, ErrAuthenticationFailed
		}
		if publicKey.Curve != elliptic.P256() {
			return nil, ErrInvalidCurve
		}
		m.key = publicKey
		m.challenge = make([]byte, 30)
		if _, err := rand.Read(m.challenge); err != nil {
			return nil, err
		}
		return m.challenge, nil
	case m.key != nil:
		key := m.key
		m.key = nil
		if !ecdsa.VerifyASN1(key, m.challenge, data) {
			return nil, ErrAuthenticationFailed
		}
		if m.authz == "" {
			m.authz = m.auth.DeriveAuthz(m.authn)
			if m.authz == "" {
				return nil, ErrAuthenticationFailed
			}
		}
		if !m.auth.Authorize(m.authz, m.authn) {
			m.authz = ""
			return nil, ErrUnauthorized
		}
		return nil, nil
	}
	return nil, ErrInvalidState
}

// HasCompleted returns true if authentication has completed, and if true, it
// also returns the authorized authz, if any.
func (m *ecdsaServerMech) HasCompleted() (bool, string) {
	if m.authn == "" || m.key != nil {
		return false, ""
	}
	return true, m.authz
}
