package sasler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/xdg-go/stringprep"
)

const (
	serverNonceLen = 24
)

// ScramAuthenticator is passed to [ScramSha1Server] or [ScramSha256Server] to
// implement credential retrieval, authz derivation and authorization checking.
type ScramAuthenticator interface {
	// GetCredentials returns the credentials for an authn, or an error if the
	// credentials could not be retrieved. The salt and iCount are parameters for
	// the SCRAM algorithm. If isSalted is true, passwd is salted using the salt
	// and iCount parameters. If isSalted is false, passwd is return plaintext.
	// It is advised to store salted passwords and therefore implementations
	// should always return a salted password and isSalted = true.
	GetCredentials(authn string) (passwd []byte, isSalted bool, salt []byte, iCount int, err error)
	// DeriveAuthz derives an authz from an authn. It is only called when no
	// authz has been requested by the client. Return the empty string if no
	// authz can be derived from the supplied authn.
	DeriveAuthz(authn string) string
	// Authorize verifies whether an authn is authorized to use the requested or
	// derived authz. Return false to fail authorization.
	Authorize(authz, authn string) bool
}

// scramServerMech is a ServerMech implementation of the SCRAM-* family of
// mechanisms.
type scramServerMech struct {
	scramMech
	authz     string
	authn     string
	completed bool
	succeeded bool
	auth      ScramAuthenticator
}

// ScramSha1Server returns a server-side SaslMech implementation for the
// SCRAM-SHA-1 mechanism, as specified in [RFC 5802]. Returns an error when
// generating a random server nonce failed.
//
// [RFC 5802]: https://tools.ietf.org/html/rfc5802
func ScramSha1Server(auth ScramAuthenticator) (ServerMech, error) {
	m := &scramServerMech{
		scramMech: scramMech{
			newHash:  sha1.New,
			hashName: "SHA-1"},
		auth: auth,
	}
	m.dataFn = m.createChallenge
	if err := m.generateNonce(); err != nil {
		return nil, err
	}
	return m, nil
}

// ScramSha256Server returns a server-side SaslMech implementation for the
// SCRAM-SHA-256 mechanism, as specified in [RFC 7677]. Returns an error when
// generating a random server nonce failed.
//
// [RFC 7677]: https://tools.ietf.org/html/rfc7677
func ScramSha256Server(auth ScramAuthenticator) (ServerMech, error) {
	m := &scramServerMech{
		scramMech: scramMech{
			newHash:  sha256.New,
			hashName: "SHA-256"},
		auth: auth,
	}
	m.dataFn = m.createChallenge
	if err := m.generateNonce(); err != nil {
		return nil, err
	}
	return m, nil
}

// generateNonce generates a random server nonce
func (m *scramServerMech) generateNonce() error {
	var rnd [serverNonceLen]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	m.serverNonce = make([]byte, serverNonceLen)
	for r, w := 0, 0; w < serverNonceLen; r++ {
		if r == serverNonceLen {
			if _, err := rand.Read(rnd[:]); err != nil {
				return err
			}
			r = 0
		}
		if rnd[r] > 0x20 && rnd[r] < 0x7f && rnd[r] != ',' {
			m.serverNonce[w] = rnd[r]
			w++
		}
	}
	return nil
}

// Mech returns the name of the mechanism, and true for client-first.
func (m *scramServerMech) Mech() (string, bool) {
	return "SCRAM-" + m.hashName, true
}

// Data create a challenge, or verifies a client proof, depending on the phase
// of the SCRAM authentication process. Returns ErrInvalidMessage if any of the
// expected values are incorrect, such as an incorrect nonce or client proof.
func (m *scramServerMech) Data(challenge []byte) ([]byte, error) {
	if m.dataFn == nil {
		return nil, ErrInvalidState
	}
	return m.dataFn(challenge)
}

// createChallenge return the challenge message to send to the client.
func (m *scramServerMech) createChallenge(ir []byte) ([]byte, error) {
	m.dataFn = m.failed
	m.completed = true
	if err := m.parseIR(ir); err != nil {
		return nil, err
	}
	passwd, isSalted, salt, iCount, err := m.auth.GetCredentials(m.authn)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	if isSalted {
		m.saltedPasswd = passwd
	} else {
		m.computeSaltedPassword(passwd, salt, iCount)
	}
	var challenge bytes.Buffer
	challenge.WriteString("r=")
	challenge.Write(m.clientNonce)
	challenge.Write(m.serverNonce)
	challenge.WriteString(",s=")
	encodedSalt := make([]byte, base64.StdEncoding.EncodedLen(len(salt)))
	base64.StdEncoding.Encode(encodedSalt, salt)
	challenge.Write(encodedSalt)
	challenge.WriteString(",i=")
	challenge.WriteString(strconv.Itoa(iCount))
	m.authMessage.WriteByte(',')
	m.authMessage.Write(challenge.Bytes())
	m.dataFn = m.verifyClientProof
	m.completed = false
	return challenge.Bytes(), nil
}

// parseIR parses the initial response from the client.
func (m *scramServerMech) parseIR(ir []byte) error {
	gs2Header := ir
	if len(ir) < 2 || ir[0] != 'n' || ir[1] != ',' {
		return ErrInvalidMessage
	}
	ir = ir[2:]
	if len(ir) < 2 {
		return ErrInvalidMessage
	}
	if ir[0] == 'a' && ir[1] == '=' {
		ir = ir[2:]
		comma := bytes.IndexByte(ir, ',')
		if comma == -1 {
			return ErrInvalidMessage
		}
		m.authz = string(ir[:comma])
		ir = ir[comma:]
		if len(ir) < 2 {
			return ErrInvalidMessage
		}
	}
	if ir[0] != ',' {
		return ErrInvalidMessage
	}
	ir = ir[1:]
	m.gs2Header = gs2Header[:len(gs2Header)-len(ir)]
	m.authMessage.Write(ir)
	if len(ir) < 2 || ir[0] != 'n' || ir[1] != '=' {
		return ErrInvalidMessage
	}
	ir = ir[2:]
	comma := bytes.IndexByte(ir, ',')
	if comma == -1 {
		return ErrInvalidMessage
	}
	authn, err := stringprep.SASLprep.Prepare(m.unescapeValue(string(ir[:comma])))
	if err != nil {
		return ErrInvalidMessage
	}
	m.authn = authn
	ir = ir[comma+1:]
	if len(ir) < 2 || ir[0] != 'r' || ir[1] != '=' {
		return ErrInvalidMessage
	}
	ir = ir[2:]
	m.clientNonce = ir
	return nil
}

// verifyClientProof verifies the provided client proof and returns a server
// signature if the client proof was correct.
func (m *scramServerMech) verifyClientProof(b []byte) ([]byte, error) {
	m.dataFn = m.failed
	m.completed = true
	clientProof, err := m.parseClientProof(b)
	if err != nil {
		return nil, ErrInvalidMessage
	}
	if !bytes.Equal(clientProof, m.clientProof()) {
		return nil, ErrAuthenticationFailed
	}
	if m.authz == "" {
		m.authz = m.auth.DeriveAuthz(m.authn)
		if m.authz == "" {
			return nil, ErrAuthenticationFailed
		}
	}
	if !m.auth.Authorize(m.authz, m.authn) {
		return nil, ErrUnauthorized
	}
	serverSignature := m.serverSignature()
	signatureMessage := make([]byte, 2+base64.StdEncoding.EncodedLen(len(serverSignature)))
	signatureMessage[0] = 'v'
	signatureMessage[1] = '='
	base64.StdEncoding.Encode(signatureMessage[2:], serverSignature)
	m.dataFn = m.ignoreOneMessage
	m.succeeded = true
	return signatureMessage, nil
}

func (m *scramServerMech) parseClientProof(b []byte) ([]byte, error) {
	withoutProof := b
	if len(b) < 2 || b[0] != 'c' || b[1] != '=' {
		return nil, ErrInvalidMessage
	}
	b = b[2:]
	comma := bytes.IndexByte(b, ',')
	if comma == -1 {
		return nil, ErrInvalidMessage
	}
	encodedGs2Header := b[:comma]
	b = b[comma+1:]
	decodedGs2Header := make([]byte, base64.StdEncoding.DecodedLen(len(encodedGs2Header)))
	n, err := base64.StdEncoding.Decode(decodedGs2Header, encodedGs2Header)
	if err != nil || !bytes.Equal(m.gs2Header, decodedGs2Header[:n]) {
		return nil, ErrInvalidMessage
	}
	if len(b) < 2 || b[0] != 'r' || b[1] != '=' {
		return nil, ErrInvalidMessage
	}
	b = b[2:]
	if len(b) < len(m.clientNonce) {
		return nil, ErrInvalidMessage
	}
	if !bytes.Equal(b[:len(m.clientNonce)], m.clientNonce) {
		return nil, ErrAuthenticationFailed
	}
	b = b[len(m.clientNonce):]
	if len(b) < len(m.serverNonce) {
		return nil, ErrInvalidMessage
	}
	if !bytes.Equal(b[:len(m.serverNonce)], m.serverNonce) {
		return nil, ErrAuthenticationFailed
	}
	b = b[len(m.serverNonce):]
	m.authMessage.WriteByte(',')
	m.authMessage.Write(withoutProof[:len(withoutProof)-len(b)])
	if len(b) < 3 || b[0] != ',' || b[1] != 'p' || b[2] != '=' {
		return nil, ErrInvalidMessage
	}
	b = b[3:]
	receivedClientProof := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err = base64.StdEncoding.Decode(receivedClientProof, b)
	if err != nil {
		return nil, ErrInvalidMessage
	}
	return receivedClientProof[:n], nil
}

func (m *scramServerMech) ignoreOneMessage(data []byte) ([]byte, error) {
	m.dataFn = m.failed
	if len(data) > 0 {
		return nil, ErrInvalidMessage
	}
	return nil, nil
}

// unescapeValue unescapes a string value after it was extracted from a
// comma-separated message.
func (m *scramServerMech) unescapeValue(s string) string {
	s = strings.ReplaceAll(s, "=2C", ",")
	s = strings.ReplaceAll(s, "=3D", "=")
	return s
}

// HasCompleted returns true if authentication has finished, and if true, it
// also returns the authorized authz, if any.
func (m *scramServerMech) HasCompleted() (bool, string) {
	switch {
	case !m.completed:
		return false, ""
	case !m.succeeded:
		return true, ""
	}
	return true, m.authz
}
