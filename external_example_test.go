package sasler_test

import (
	"crypto/x509"
	"fmt"

	"github.com/phedny/sasler"
)

func ExampleExternalAuthenticator() {
	// TLSConn() represents a function that returns a *tls.Conn with a client
	// that has presented a client certificate and has requested authentication
	// using the EXTERNAL mechanism.
	certs := TLSConn().ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Println("No client TLS certificate.")
		return
	}
	auth := myExternalAuthenticator{certs[0]}
	mech := sasler.ExternalServer(&auth)

	// EXTERNAL expects one message from the client
	_, err := mech.Data([]byte(""))
	if err != nil {
		fmt.Println(err)
	}

	// Retrieve authorized identity
	completed, authz := mech.HasCompleted()
	if completed {
		fmt.Println("Authorized identity:", authz)
	}

	// Output: Authorized identity: cn=user@example.com
}

// myExternalAuthenticator is an example ExternalAuthenticator that accepts
// any authentication request when a certificate is present, because it assumes
// that connections to clients that present invalid or untrusted certificates
// have been denied.
type myExternalAuthenticator struct {
	cert *x509.Certificate
}

// DeriveAuthz derives an authz from the common name of the certificate.
func (a *myExternalAuthenticator) DeriveAuthz() string {
	return "cn=" + a.cert.Subject.CommonName
}

// Authorize checks whether the authz matches the common name of the
// certificate. This implementation also allows anyone authenticated as
// admin@example.com to be authorized for any identity.
func (a *myExternalAuthenticator) Authorize(authz string) bool {
	cn := a.cert.Subject.CommonName
	return authz == "cn="+cn || authz == "cn=admin@example.com"
}
