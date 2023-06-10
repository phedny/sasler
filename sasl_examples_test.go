package sasler_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/phedny/sasler"
)

func ExampleClientMech() {
	// SelectClientMech() represents a function that returns a ClientMech
	mech := SelectClientMech()
	mechName, clientFirst := mech.Mech()

	// AuthenticateToServer() and all calls to Read() and Write() represent a
	// protocol-specific communication channel.
	server := AuthenticateToServer(mechName)

	// For client-first mechanisms, send the first message
	if clientFirst {
		data, err := mech.Data(nil)
		if err != nil {
			fmt.Println("Authentication aborted.", err)
			return
		}
		server.Write(data)
	}

	// Relay authentication data until error, Success or Failure
	for {
		command, data := server.Read()
		switch command {
		case Success:
			fmt.Println("Authentication succeeded.")
			return
		case Failure:
			fmt.Println("Authentication failed.")
			return
		case Data:
			data, err := mech.Data(data)
			if err != nil {
				fmt.Println("Authentication aborted.", err)
				return
			}
			server.Write(data)
		}
	}

	// Output: Authentication succeeded.
}

func SelectClientMech() sasler.ClientMech { return sasler.ExternalClient("") }

type exampleServer struct{}

func AuthenticateToServer(mechName string) exampleServer { return exampleServer{} }

func (*exampleServer) Write(data []byte) {}

const (
	Data = iota
	Success
	Failure
)

func (*exampleServer) Read() (int, []byte) { return Success, nil }

func ExampleServerMech() {
	// ClientConn() represents retrieving a connection with a client that
	// initiated SASL authentication, including the mechanism name it requested.
	mechName, conn := ClientConn()

	// CreateMechanism() represents a function that returns a ServerMech based on
	// the requested mechanism name.
	mech := CreateMechanism(mechName)
	_, clientFirst := mech.Mech()

	// For server-first mechanisms, send the first message
	if !clientFirst {
		data, err := mech.Data(nil)
		if err != nil {
			fmt.Println("Authentication aborted.")
			return
		}
		conn.Write(Data, data)
	}

	// Relay authentication data until error or completion
	for {
		data := conn.Read()
		data, err := mech.Data(data)
		if err != nil {
			conn.Write(Failure, nil)
			switch err {
			case sasler.ErrAuthenticationFailed:
				fmt.Println("Authentication failed.")
			case sasler.ErrUnauthorized:
				fmt.Println("Unauthorized.")
			default:
				fmt.Println("Authentication aborted.", err)
			}
			return
		}
		if data != nil {
			conn.Write(Data, data)
		}
		completed, authz := mech.HasCompleted()
		if completed {
			conn.Write(Success, nil)
			fmt.Println("Authentication succeeded, authorised id:", authz)
			return
		}
	}

	// Output: Authentication succeeded, authorised id: username
}

type exampleClient struct{}

func (*exampleClient) Write(command int, data []byte) {}

func (*exampleClient) Read() []byte { return nil }

func ClientConn() (string, exampleClient) { return "", exampleClient{} }

func CreateMechanism(mech string) sasler.ServerMech {
	return sasler.AnonymousServer("username", &myAnonymousAuthenticator{})
}

// Below are used by external_example_test.go

func TLSConn() *fakeTLSConn {
	return &fakeTLSConn{}
}

type fakeTLSConn struct{}

func (*fakeTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: "user@example.com",
				},
			},
		},
	}
}

// Below is used by scram_example_test.go and ecdsa_example_test.go

type exampleClient2 struct {
	mech sasler.ClientMech
	data []byte
}

func (c *exampleClient2) Write(data []byte) {
	c.data, _ = c.mech.Data(data)
}

func (c *exampleClient2) Read() []byte {
	return c.data
}

func (*exampleClient2) Abort() {}

func (*exampleClient2) Success() {}

func ScramClientConn() exampleClient2 {
	mech, _ := sasler.ScramSha1Client("", "user", "pencil")
	data, _ := mech.Data(nil)
	return exampleClient2{mech, data}
}

var privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

func RetrievePublicKey(authn string) *ecdsa.PublicKey {
	return &privateKey.PublicKey
}

func EcdsaClientConn() exampleClient2 {
	mech, _ := sasler.EcdsaNist256pChallengeClient("", "user", privateKey)
	data, _ := mech.Data(nil)
	return exampleClient2{mech, data}
}
