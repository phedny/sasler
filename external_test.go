package sasler_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/phedny/sasler"
)

func TestExternalClient(t *testing.T) {
	auth := sasler.ExternalClient("")

	gotName, gotClientFirst := auth.Mech()
	expectedName := "EXTERNAL"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("")
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

func TestExternalServer_DerivedAuthz(t *testing.T) {
	auth := sasler.ExternalServer(&FakeExternalAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "EXTERNAL"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "derived-authz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestExternalServer_RequestedAuthz(t *testing.T) {
	auth := sasler.ExternalServer(&FakeExternalAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "EXTERNAL"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("requested-authz")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "requested-authz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestExternalServer_Unauthorized(t *testing.T) {
	auth := sasler.ExternalServer(&FakeExternalAuthenticator{})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "EXTERNAL"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("invalid-authz")
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

type FakeExternalAuthenticator struct{}

func (*FakeExternalAuthenticator) DeriveAuthz() string {
	return "derived-authz"
}

func (*FakeExternalAuthenticator) Authorize(authz string) bool {
	return authz == "derived-authz" || authz == "requested-authz"
}
