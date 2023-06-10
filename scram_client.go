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
	clientNonceLen = 24
)

// scramClientMech is a ClientMech implementation of the SCRAM-* family of
// mechanisms.
type scramClientMech struct {
	scramMech
	authz  string
	authn  string
	passwd string
}

// ScramSha1Client returns a ClientMech implementation for the SCRAM-SHA-1
// mechanism, as specified in [RFC 5802]. Returns an error if SASLprep on
// authn, or passwd fails, as described in [RFC 5802, section 5.1]. Also
// returns an error when generating a random client nonce failed.
//
// [RFC 5802]: https://tools.ietf.org/html/rfc5802
// [RFC 5802, section 5.1]: https://tools.ietf.org/html/rfc5802#section-5.1
func ScramSha1Client(authz, authn, passwd string) (ClientMech, error) {
	m := &scramClientMech{
		scramMech: scramMech{
			newHash:  sha1.New,
			hashName: "SHA-1"},
		authz:  authz,
		authn:  authn,
		passwd: passwd,
	}
	m.dataFn = m.initialResponse
	if err := m.prepare(); err != nil {
		return nil, err
	}
	if err := m.generateNonce(); err != nil {
		return nil, err
	}
	return m, nil
}

// ScramSha256Client returns a ClientMech implementation for the SCRAM-SHA-256
// mechanism, as specified in [RFC 7677]. Returns an error if SASLprep on
// authn, or passwd fails, as described in [RFC 5802, section 5.1]. Also
// returns an error when generating a random client nonce failed.
//
// [RFC 7677]: https://tools.ietf.org/html/rfc7677
// [RFC 5802, section 5.1]: https://tools.ietf.org/html/rfc5802#section-5.1
func ScramSha256Client(authz, authn, passwd string) (ClientMech, error) {
	m := &scramClientMech{
		scramMech: scramMech{
			newHash:  sha256.New,
			hashName: "SHA-256"},
		authz:  authz,
		authn:  authn,
		passwd: passwd,
	}
	m.dataFn = m.initialResponse
	if err := m.prepare(); err != nil {
		return nil, err
	}
	if err := m.generateNonce(); err != nil {
		return nil, err
	}
	return m, nil
}

// prepare runs stringprep with the SASLprep profile on the authzid, authcid,
// and passwd fields. Returns an error is any of the preparations fail.
func (m *scramClientMech) prepare() error {
	if m.authz != "" {
		authzid, err := stringprep.SASLprep.Prepare(m.authz)
		if err != nil {
			return err
		}
		m.authz = authzid
	}
	if m.authn != "" {
		authcid, err := stringprep.SASLprep.Prepare(m.authn)
		if err != nil {
			return err
		}
		m.authn = authcid
	}
	if m.passwd != "" {
		passwd, err := stringprep.SASLprep.Prepare(m.passwd)
		if err != nil {
			return err
		}
		m.passwd = passwd
	}
	return nil
}

// generateNonce generates a random client nonce
func (m *scramClientMech) generateNonce() error {
	var rnd [clientNonceLen]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	m.clientNonce = make([]byte, clientNonceLen)
	for r, w := 0, 0; w < clientNonceLen; r++ {
		if r == clientNonceLen {
			if _, err := rand.Read(rnd[:]); err != nil {
				return err
			}
			r = 0
		}
		if rnd[r] > 0x20 && rnd[r] < 0x7f && rnd[r] != ',' {
			m.clientNonce[w] = rnd[r]
			w++
		}
	}
	return nil
}

// Mech returns the name of the mechanism, and true for client-first.
func (m *scramClientMech) Mech() (string, bool) {
	return "SCRAM-" + m.hashName, true
}

// Data parses a challenge of server signature, depending on the phase of the
// SCRAM authentication process. Returns ErrInvalidMessage if any of the
// expected values are incorrect, such as a client nonce mismatch, or an
// incorrect server signature.
func (m *scramClientMech) Data(challenge []byte) ([]byte, error) {
	if m.dataFn == nil {
		return nil, ErrInvalidState
	}
	return m.dataFn(challenge)
}

// initialResponse returns the initial response to send to the server.
func (m *scramClientMech) initialResponse(challenge []byte) ([]byte, error) {
	if len(challenge) > 0 {
		m.dataFn = m.failed
		return nil, ErrInvalidMessage
	}
	m.dataFn = m.respondToChallenge
	var ir bytes.Buffer
	ir.WriteString("n,")
	if m.authz != "" {
		ir.WriteString("a=")
		ir.WriteString(m.escapeValue(m.authz))
	}
	ir.WriteByte(',')
	m.gs2Header = ir.Bytes()
	m.authMessage.WriteString("n=")
	m.authMessage.WriteString(m.escapeValue(m.authn))
	m.authMessage.WriteString(",r=")
	m.authMessage.Write(m.clientNonce)
	ir.Write(m.authMessage.Bytes())
	return ir.Bytes(), nil
}

// respondToChallenge parses the challenge from the server and returns the
// client proof to return to the server.
func (m *scramClientMech) respondToChallenge(challenge []byte) ([]byte, error) {
	salt, iCount, err := m.parseChallenge(challenge)
	if err != nil {
		m.dataFn = m.failed
		return nil, err
	}
	var resp bytes.Buffer
	resp.WriteString("c=")
	encodedGs2Header := make([]byte, base64.StdEncoding.EncodedLen(len(m.gs2Header)))
	base64.StdEncoding.Encode(encodedGs2Header, m.gs2Header)
	resp.Write(encodedGs2Header)
	resp.WriteString(",r=")
	resp.Write(m.clientNonce)
	resp.Write(m.serverNonce)
	m.authMessage.WriteByte(',')
	m.authMessage.Write(challenge)
	m.authMessage.WriteByte(',')
	m.authMessage.Write(resp.Bytes())
	m.computeSaltedPassword([]byte(m.passwd), salt, iCount)
	clientProof := m.clientProof()
	encodedClientProof := make([]byte, base64.StdEncoding.EncodedLen(len(clientProof)))
	base64.StdEncoding.Encode(encodedClientProof, clientProof)
	resp.WriteString(",p=")
	resp.Write(encodedClientProof)
	m.dataFn = m.verifyServerSignature
	return resp.Bytes(), nil
}

// parseChallenge parses the challenge from the server.
func (m *scramClientMech) parseChallenge(challenge []byte) ([]byte, int, error) {
	if len(challenge) < 2 || challenge[0] != 'r' || challenge[1] != '=' {
		return nil, 0, ErrInvalidMessage
	}
	challenge = challenge[2:]
	if len(challenge) < len(m.clientNonce) {
		return nil, 0, ErrInvalidMessage
	}
	if !bytes.Equal(challenge[:len(m.clientNonce)], m.clientNonce) {
		return nil, 0, ErrAuthenticationFailed
	}
	challenge = challenge[len(m.clientNonce):]
	comma := bytes.IndexByte(challenge, ',')
	if comma == -1 {
		return nil, 0, ErrInvalidMessage
	}
	m.serverNonce = make([]byte, comma)
	copy(m.serverNonce, challenge)
	challenge = challenge[comma+1:]
	if len(challenge) < 2 || challenge[0] != 's' || challenge[1] != '=' {
		return nil, 0, ErrInvalidMessage
	}
	challenge = challenge[2:]
	comma = bytes.IndexByte(challenge, ',')
	if comma == -1 {
		return nil, 0, ErrInvalidMessage
	}
	salt := make([]byte, base64.StdEncoding.DecodedLen(comma))
	saltLen, err := base64.StdEncoding.Decode(salt, challenge[:comma])
	if err != nil {
		return nil, 0, ErrInvalidMessage
	}
	salt = salt[:saltLen]
	challenge = challenge[comma+1:]
	if len(challenge) < 2 || challenge[0] != 'i' || challenge[1] != '=' {
		return nil, 0, ErrInvalidMessage
	}
	challenge = challenge[2:]
	i, err := strconv.Atoi(string(challenge))
	if err != nil {
		return nil, 0, ErrInvalidMessage
	}
	return salt, i, nil
}

// verifyServerSignature compares the received server signature with a locally
// computed one, and returns ErrInvalidMessage if they don't match.
func (m *scramClientMech) verifyServerSignature(challenge []byte) ([]byte, error) {
	m.dataFn = m.failed
	if len(challenge) < 2 || challenge[0] != 'v' || challenge[1] != '=' {
		return nil, ErrInvalidMessage
	}
	challenge = challenge[2:]
	serverSignature := make([]byte, base64.StdEncoding.DecodedLen(len(challenge)))
	n, err := base64.StdEncoding.Decode(serverSignature, challenge)
	if err != nil {
		return nil, ErrInvalidMessage
	}
	serverSignature = serverSignature[:n]
	if !bytes.Equal(m.serverSignature(), serverSignature) {
		return nil, ErrAuthenticationFailed
	}
	return nil, nil
}

// escapeValue escapes a string value, so it can be included in a
// comma-separated message.
func (m *scramClientMech) escapeValue(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}
