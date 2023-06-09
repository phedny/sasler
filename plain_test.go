package sasler_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/phedny/sasler"
)

func TestPlainClient(t *testing.T) {
	auth := sasler.PlainClient("LetMeBe", "WhoIAm", "AndTrustMe")

	gotName, gotClientFirst := auth.Mech()
	expectedName := "PLAIN"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("LetMeBe\x00WhoIAm\x00AndTrustMe")
	if err != nil {
		t.Fatalf(`Data(nil) returned error: %v`, err)
	}
	if !bytes.Equal(gotIR, expectedIR) {
		t.Fatalf(`Data(nil) returned %s; expected %s`, gotIR, expectedIR)
	}

	_, err = auth.Data(nil)
	if err != sasler.ErrInvalidState {
		t.Fatalf(`Data returned error: %v; expected ErrInvalidState`, err)
	}
}

func TestPlainServer_DeriveAuthz(t *testing.T) {
	auth := sasler.PlainServer(&FakePlainAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "PLAIN"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("\x00user\x00password")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "userZ"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestPlainServer_WrongPasswd(t *testing.T) {
	auth := sasler.PlainServer(&FakePlainAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "PLAIN"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("\x00user\x00wrong-password")
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

func TestPlainServer_RequestedAuthz(t *testing.T) {
	auth := sasler.PlainServer(&FakePlainAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "PLAIN"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("someUser\x00admin\x00VeryDifficultPassword")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "someUser"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestPlainServer_Unauthorized(t *testing.T) {
	auth := sasler.PlainServer(&FakePlainAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "PLAIN"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("someUser\x00user\x00password")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || !errors.Is(err, sasler.ErrUnauthorized) {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, ErrAuthenticationFailed)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

type FakePlainAuthenticator struct{}

func (*FakePlainAuthenticator) VerifyPasswd(authn, passwd string) bool {
	switch {
	case authn == "user" && passwd == "password":
		return true
	case authn == "admin" && passwd == "VeryDifficultPassword":
		return true
	}
	return false
}

func (*FakePlainAuthenticator) DeriveAuthz(authn string) string {
	return authn + "Z"
}

func (*FakePlainAuthenticator) Authorize(authz, authn string) bool {
	return authn == "admin" || authn+"Z" == authz
}
