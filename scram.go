package sasler

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"hash"
)

// scramMech contains the fields that are common for scramClientMech and
// scramServerMech.
type scramMech struct {
	newHash      func() hash.Hash
	hashName     string
	clientNonce  []byte
	serverNonce  []byte
	gs2Header    []byte
	saltedPasswd []byte
	authMessage  bytes.Buffer
	dataFn       func([]byte) ([]byte, error)
}

// computeSaltedPassword computes the salted password, using the plaintext
// password, and the salt and iteration count.
func (m *scramMech) computeSaltedPassword(passwd, salt []byte, iCount int) {
	mac := hmac.New(m.newHash, passwd)
	ui := make([]byte, mac.Size())
	hi := make([]byte, mac.Size())
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	mac.Sum(ui[:0])
	subtle.XORBytes(hi, hi, ui)
	for i := 1; i < iCount; i++ {
		mac.Reset()
		mac.Write(ui)
		mac.Sum(ui[:0])
		subtle.XORBytes(hi, hi, ui)
	}
	m.saltedPasswd = hi
}

// clientProof returns the client proof.
func (m *scramMech) clientProof() []byte {
	mac := hmac.New(m.newHash, m.saltedPasswd)
	mac.Write([]byte("Client Key"))
	clientKey := mac.Sum(nil)
	h := m.newHash()
	h.Write(clientKey)
	mac = hmac.New(m.newHash, h.Sum(nil))
	mac.Write(m.authMessage.Bytes())
	clientProof := make([]byte, len(clientKey))
	subtle.XORBytes(clientProof, clientKey, mac.Sum(nil))
	return clientProof
}

// serverSignature computes the expected server signature.
func (m *scramMech) serverSignature() []byte {
	mac := hmac.New(m.newHash, m.saltedPasswd)
	mac.Write([]byte("Server Key"))
	serverKey := mac.Sum(nil)
	mac = hmac.New(m.newHash, serverKey)
	mac.Write(m.authMessage.Bytes())
	return mac.Sum(nil)
}

// failed always returns ErrInvalidState and is installed in scramMech after a
// failed or completed authentication.
func (m *scramMech) failed(challenge []byte) ([]byte, error) {
	return nil, ErrInvalidState
}
