// Package sasler contains client-side and server-side implementations for the
// following SASL mechanisms: ANONYMOUS, ECDSA-NIST256P-CHALLENGE, EXTERNAL,
// OAUTHBEARER, PLAIN, SCRAM-SHA-1, and SCRAM-SHA-256.
package sasler

import (
	"errors"
)

var (
	// ErrInvalidState is returned by a mechanism implementation if the function
	// is called at an inappropriate moment in the authentication process.
	ErrInvalidState = errors.New("sasler: mechanism in invalid state")
	// ErrInvalidMessage is returend by Date if the function is supplied with a
	// message that is syntactially invalid.
	ErrInvalidMessage = errors.New("sasler: invalid message")
	// ErrAuthenticationFailed can be returned by an implementation to indicate
	// that authentication has failed.
	ErrAuthenticationFailed = errors.New("sasler: authentication failed")
	// ErrUnauthorized can be returns by a server-side implementation to signal
	// that the authenticated authn is not authorized to use the requested authz.
	ErrUnauthorized = errors.New("sasler: unauthorized")
)

// ClientMech describes the functions that are implemented by the client-side
// implementation of a SASL mechanism.
type ClientMech interface {
	// Mech returns the full name of the mechanism as described in its
	// specification, and a bool that is true when this is a client-first
	// mechanism.
	Mech() (string, bool)
	// Data must be called each time SASL data arrived from the other party,
	// providing the bytes of the message. It returns the bytes of the message
	// that must be returned to the other party, or an error when authentication
	// failed and must be aborted. If the returned []byte is nil and no error is
	// returned, authentication has finished successfully.
	//
	// On a client-first mechanism, the first call to Data must be done with nil
	// or zero length slice. On a server-first mechanism, the first call to Data
	// must be done with the initial challenge received from the server.
	Data(data []byte) ([]byte, error)
}

// ServerMech describes the functions that are implemented by the server-side
// implementation of a SASL mechanism.
type ServerMech interface {
	// Mech returns the full name of the mechanism as described in its
	// specification, and a bool that is true when this is a client-first
	// mechanism.
	Mech() (string, bool)
	// Data must be called each time SASL data arrived from the other party,
	// providing the bytes of the message. It returns the bytes of the message
	// that must be returned to the other party, or an error when authentication
	// failed and must be aborted. If the returned []byte is nil and no error is
	// returned, authentication has finished successfully.
	//
	// On a client-first mechanism, the first call to Data must be done with the
	// initial response received from the client. On a server-first mechanism,
	// the first call to Data must be done with nil or a zero length slice.
	Data(data []byte) ([]byte, error)
	// HasCompleted returns (true, authz) if the authentication proccess has
	// completed successfully, or (true, "") if it has failed, or (false, "") if
	// it's still in progress.
	HasCompleted() (bool, string)
}
