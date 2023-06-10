package sasler_test

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/phedny/sasler"
)

func ExampleEcdsaAuthenticator() {
	// EcdsaClientConn() represents a function that returns a client that has
	// requested authentication using the ECDSA-NIST256P-CHALLENGE mechanism.
	conn := EcdsaClientConn()
	auth := myEcdsaAuthenticator{}
	mech := sasler.EcdsaNist256pChallengeServer(&auth)

	// ECDSA-NIST256P-CHALLENGE requires a couple of messages to be exchanged
	// between client and server.
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

// myEcdsaAuthenticator is an example EcdsaAuthenticator that accepts only a
// single username.
type myEcdsaAuthenticator struct{}

// GetPublicKey retrieves the public key, if authn is "user".
func (a *myEcdsaAuthenticator) GetPublicKey(authn string) (*ecdsa.PublicKey, error) {
	if authn != "user" {
		return nil, errors.New("unknown authn")
	}
	return RetrievePublicKey(authn), nil
}

// DeriveAuthz derives an authz from an authn.
func (a *myEcdsaAuthenticator) DeriveAuthz(authn string) string {
	return authn
}

// Authorize checks whether the authn is authorized to act on behalf of the
// authz. This implementation also allows anyone authenticated as Admin to be
// authorized for any identity.
func (a *myEcdsaAuthenticator) Authorize(authz, authn string) bool {
	return authz == authn || authn == "Admin"
}
