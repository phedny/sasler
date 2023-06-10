package sasler_test

import (
	"fmt"

	"github.com/phedny/sasler"
)

func ExampleAnonymousAuthenticator() {
	auth := myAnonymousAuthenticator{}
	mech := sasler.AnonymousServer("anonymous-user", &auth)

	// ANONYMOUS expects one message from the client
	_, err := mech.Data([]byte("user@example.com"))
	if err != nil {
		fmt.Println(err)
	}

	// Retrieve authorized identity
	completed, authz := mech.HasCompleted()
	if completed {
		fmt.Println("Authorized identity:", authz)
		fmt.Println("Stored trace:", auth.trace)
	}

	// Output:
	// Authorized identity: anonymous-user
	// Stored trace: user@example.com
}

// myAnonymousAuthenciator is an example AnonymousAuthenticator that just
// stores the latest retrieve trace information in a field.
type myAnonymousAuthenticator struct {
	trace string
}

// StoreTrace stores the received trace information in a field of a.
func (a *myAnonymousAuthenticator) StoreTrace(trace string) {
	a.trace = trace
}
