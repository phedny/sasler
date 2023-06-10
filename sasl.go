// Package sasler contains client-side and server-side implementations for the
// following SASL mechanisms: ANONYMOUS, ECDSA-NIST256P-CHALLENGE, EXTERNAL,
// OAUTHBEARER, PLAIN, SCRAM-SHA-1, and SCRAM-SHA-256.
//
// # Client-side usage
//
//  1. Call one of the functions that returns a [ClientMech] implementation.
//  2. Send a message to the server to signal you want to start SASL
//     authentication, passing the mechanism name returned by calling Mech().
//  3. If the server acknowledges starting SASL authentication, relay messages
//     between the CientMech and the server, using appropriate encoding for the
//     protocol used with the server. Note that you can call Mech() to detect
//     whether the first message must be sent by the client, or will be sent by
//     the server.
//  4. When the server indicates authentication has finished, you're done.
//     However, when Data() returns an error, the authentication process has
//     failed and must be aborted.
//
// The [ClientMech] documentation contains an example that demonstrates the
// process described above.
//
// # Server-side usage
//
//  1. Implement the authenticator matching the desired mechanism, which is
//     by the [ServerMech] to hook up with any systems you have in place for
//     user and/or credential storage.
//  2. When a client request SASL authentication, call the appropriate function
//     that returns the [ServerMech] implementation requested by the client.
//  3. Send a message to the client to acknowledge SASL authentication has been
//     started.
//  4. Relay messages between the ServerMech and the client, using appropriate
//     encoding for the protocol used with the client. Note that you can call
//     Mech() to detect whether the first message must be sent by the server,
//     or will be sent by the client.
//  5. Whenever Data() returns an error, the authentication process has failed
//     and must be aborted. Send a message to the client notifying it about the
//     abortion.
//  6. After each call to Data(), call HasCompleted() to check whether the
//     authentication process has been completed. If it returned true, it also
//     returned the authorized identity.
//
// The [ServerMech] documentation contains an example that demonstrates the
// process described above. The documentation for each authenticator interface
// contains an example implementation.
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
