package sasler_test

import (
	"bytes"
	"fmt"

	"github.com/phedny/sasler"
)

func ExamplePlainAuthenticator() {
	auth := myPlainAuthenticator{
		user:   "user",
		passwd: []byte("pencil"),
	}
	mech := sasler.PlainServer(&auth)

	// PLAIN expects one message from the client
	_, err := mech.Data([]byte("\x00user\x00pencil"))
	if err != nil {
		fmt.Println(err)
	}

	// Retrieve authorized identity
	completed, authz := mech.HasCompleted()
	if completed {
		fmt.Println("Authorized identity:", authz)
	}

	// Output: Authorized identity: user
}

// myPlainAuthenticator is an example PlainAuthenticator that accepts only a
// single username/password combination.
type myPlainAuthenticator struct {
	user   string
	passwd []byte
}

// VerifyPasswd verifies the username and password.
func (a *myPlainAuthenticator) VerifyPasswd(authn string, passwd []byte) bool {
	return authn == a.user && bytes.Equal(passwd, a.passwd)
}

// DeriveAuthz derives an authz from an authn.
func (a *myPlainAuthenticator) DeriveAuthz(authn string) string {
	return authn
}

// Authorize checks whether the authn is authorized to act on behalf of the
// authz. This implementation also allows anyone authenticatd as Admin to be
// authorized for any identity.
func (a *myPlainAuthenticator) Authorize(authz, authn string) bool {
	return authz == authn || authn == "Admin"
}
