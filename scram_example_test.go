package sasler_test

import (
	"errors"
	"fmt"

	"github.com/phedny/sasler"
)

func ExampleScramAuthenticator() {
	// ScramClientConn() represents a function that returns a client that has
	// requested authentication using the SCRAM-SHA-1 mechanism.
	conn := ScramClientConn()
	auth := myScramAuthenticator{}
	mech, err := sasler.ScramSha1Server(&auth)
	if err != nil {
		fmt.Println(err)
		return
	}

	// SCRAM-* requires a couple of messages to be exchanged between client and
	// server.
	for {
		data, err := mech.Data(conn.Read())
		if err != nil {
			// Abort() represents a function that uses a protocol-specific way to
			// signal to the client that authentication has failed.
			conn.Abort()
			fmt.Println(err)
			return
		}
		// Relay data from mech to client
		if data != nil {
			conn.Write(data)
		}
		// Test if the conversation has completed and show the authz
		completed, authz := mech.HasCompleted()
		if completed {
			// Success() represents a function that uses a protocol-specific way to
			// signal to the client that authentication has succeeded.
			conn.Success()
			fmt.Println("Authorized identity:", authz)
			return
		}
	}

	// Output: Authorized identity: user
}

// myScramAuthenticator is an example ScramAuthenticator that accepts only a
// single username/password combination.
type myScramAuthenticator struct{}

// GetCredentials returns the credentials that belong to the requested authn.
func (a *myScramAuthenticator) GetCredentials(authn string) (passwd []byte, isSalted bool, salt []byte, iCount int, err error) {
	if authn != "user" {
		return nil, false, nil, 0, errors.New("unknown authn")
	}
	// passwd is stored in a database in salted form, which is recommended.
	passwd = []byte("\x1d\x96\xee:R\x9bZ_\x9eG\xc0\x1f\"\x9a,\xb8\xa6\xe1_}")
	// If a plaintext password is returned, return isSalted = false.
	isSalted = true
	// Both salt and iCount must be retrieved from database if isSalted = true,
	// otherwise they might be random. If salts are stored in the database, it is
	// recommended to use a different salt for every entry.
	salt = []byte("A%\xc2G\xe4:\xb1\xe9<m\xffv")
	iCount = 4096
	return
}

// DeriveAuthz derives an authz from an authn.
func (a *myScramAuthenticator) DeriveAuthz(authn string) string {
	return authn
}

// Authorize checks whether the authn is authorized to act on behalf of the
// authz. This implementation also allows anyone authenticated as Admin to be
// authorized for any identity.
func (a *myScramAuthenticator) Authorize(authz, authn string) bool {
	return authz == authn || authn == "Admin"
}
