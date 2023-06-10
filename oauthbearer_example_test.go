package sasler_test

import (
	"fmt"
	"strings"

	"github.com/phedny/sasler"
)

func ExampleOAuthBearerAuthenticator() {
	auth := myOAuthBearerAuthenticator{
		host:      "example.com",
		port:      143,
		signature: "SiGNeD_By_auTHoRiTy",
	}
	mech := sasler.OAuthBearerServer(&auth)

	// OAUTHBEARER expects one message from the client
	_, err := mech.Data([]byte("n,\x01host=example.com\x01port=143\x01auth=Bearer username,SiGNeD_By_auTHoRiTy\x01\x01"))
	if err != nil {
		fmt.Println(err)
	}

	// Retrieve authorized identity
	completed, authz := mech.HasCompleted()
	if completed {
		fmt.Println("Authorized identity:", authz)
	}

	// Output: Authorized identity: username
}

// myOAuthBearerAuthentication is an example OAuthBearerAuthentication that
// accepts only authentication requets for a specific host and port, signed by
// a static signature.
type myOAuthBearerAuthenticator struct {
	host      string
	port      int
	signature string
}

// VerifyToken verifies the host, port and signature of the provided token.
func (a *myOAuthBearerAuthenticator) VerifyToken(token, host string, port int) bool {
	return host == a.host && port == a.port && strings.Split(token, ",")[1] == a.signature
}

// DeriveAuthz derives an authz from the token.
func (a *myOAuthBearerAuthenticator) DeriveAuthz(token string) string {
	return strings.Split(token, ",")[0]
}

// Authorize checks whether the authn in the token matches the authz. This
// implementation also allows anyone authenticated as Admin to be authorized
// for any identity.
func (a *myOAuthBearerAuthenticator) Authorize(authz, token string) bool {
	authn := strings.Split(token, ",")[0]
	return authz == authn || authn == "Admin"
}
