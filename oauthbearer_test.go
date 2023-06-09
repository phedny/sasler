package sasler_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/phedny/sasler"
)

func TestOAuthBearerClient(t *testing.T) {
	auth := sasler.OAuthBearerClient("LetMeBe", "ThisIsTheTokenDude", "example.com", 143)

	gotName, gotClientFirst := auth.Mech()
	expectedName := "OAUTHBEARER"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("n,a=LetMeBe,\x01host=example.com\x01port=143\x01auth=Bearer ThisIsTheTokenDude\x01\x01")
	if err != nil {
		t.Fatalf(`Data(nil) returned error: %v`, err)
	}
	if !bytes.Equal(gotIR, expectedIR) {
		t.Fatalf(`Data(nil) returned %s; expected %s`, gotIR, expectedIR)
	}

	_, err = auth.Data(nil)
	if err != sasler.ErrInvalidState {
		t.Fatalf(`Data(nil) returned error: %v; expected ErrInvalidState`, err)
	}
}

func TestOAuthBearerServer_DeriveAuthzNoHostNoPort(t *testing.T) {
	auth := sasler.OAuthBearerServer(&FakeOAuthBearerAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "OAUTHBEARER"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("n,\x01auth=Bearer NoHost,NoPort,Derive:the-authz,Authz:the-authz/req-authz\x01\x01")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "the-authz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestOAuthBearerServer_DeriveAuthzYesHostYesPort(t *testing.T) {
	auth := sasler.OAuthBearerServer(&FakeOAuthBearerAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "OAUTHBEARER"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("n,\x01host=example.com\x01port=143\x01auth=Bearer YesHost,YesPort,Derive:the-authz,Authz:the-authz/req-authz\x01\x01")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "the-authz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestOAuthBearerServer_DeriveAuthzYesHostYesPortWrongHost(t *testing.T) {
	auth := sasler.OAuthBearerServer(&FakeOAuthBearerAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "OAUTHBEARER"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("n,\x01host=example.net\x01port=143\x01auth=Bearer YesHost,YesPort,Derive:the-authz,Authz:the-authz/req-authz\x01\x01")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || !errors.Is(err, sasler.ErrAuthenticationFailed) {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, ErrAuthenticationFailed)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestOAuthBearerServer_InvalidToken(t *testing.T) {
	auth := sasler.OAuthBearerServer(&FakeOAuthBearerAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "OAUTHBEARER"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("n,\x01auth=Bearer Invalid,NoHost,NoPort,Derive:the-authz,Authz:the-authz/req-authz\x01\x01")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || !errors.Is(err, sasler.ErrAuthenticationFailed) {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, ErrAuthenticationFailed)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestOAuthBearerServer_RequestedAuthz(t *testing.T) {
	auth := sasler.OAuthBearerServer(&FakeOAuthBearerAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "OAUTHBEARER"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("n,a=req-authz,\x01auth=Bearer NoHost,NoPort,Derive:the-authz,Authz:the-authz/req-authz\x01\x01")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "req-authz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestOAuthBearerServer_Unauthorized(t *testing.T) {
	auth := sasler.OAuthBearerServer(&FakeOAuthBearerAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "OAUTHBEARER"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("n,a=req-other-authz,\x01auth=Bearer NoHost,NoPort,Derive:the-authz,Authz:the-authz/req-authz\x01\x01")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || !errors.Is(err, sasler.ErrUnauthorized) {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, ErrUnauthorized)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

type FakeOAuthBearerAuthenticator struct{}

func (*FakeOAuthBearerAuthenticator) VerifyToken(token, host string, port int) bool {
	switch {
	case strings.Contains(token, "Invalid"):
		return false
	case strings.Contains(token, "NoHost,NoPort") && host == "" && port == 0:
		return true
	case strings.Contains(token, "YesHost,YesPort") && host == "example.com" && port == 143:
		return true
	}
	return false
}

func (*FakeOAuthBearerAuthenticator) DeriveAuthz(token string) string {
	n := strings.Index(token, "Derive:")
	if n == -1 {
		return ""
	}
	token = token[n+7:]
	n = strings.IndexByte(token, ',')
	if n == -1 {
		return token
	}
	return token[:n]
}

func (*FakeOAuthBearerAuthenticator) Authorize(authz, token string) bool {
	n := strings.Index(token, "Authz:")
	if n == -1 {
		return false
	}
	token = token[n+6:]
	n = strings.IndexByte(token, ',')
	if n != -1 {
		token = token[:n]
	}
	for _, ok := range strings.Split(token, "/") {
		if authz == ok {
			return true
		}
	}
	return false
}
