package sasler_test

import (
	"bytes"
	"testing"

	"github.com/phedny/sasler"
)

func TestAnonymousClient(t *testing.T) {
	auth, err := sasler.AnonymousClient("user@example.com")
	if err != nil {
		t.Fatalf(`AnonymousClient("user@example.com") returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "ANONYMOUS"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("user@example.com")
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

func TestAnonymousServer_WithTrace(t *testing.T) {
	f := FakeAnonymousAuthenticator{gotTrace: "-not-called-"}
	auth := sasler.AnonymousServer("the-authz", &f)

	gotName, gotClientFirst := auth.Mech()
	expectedName := "ANONYMOUS"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("user@example.com")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, nil)`, ir, gotChallenge, err)
	}
	expectedTrace := "user@example.com"
	if f.gotTrace != expectedTrace {
		t.Fatalf(`Data("%s") did not call StoreTrace("%s"); gotTrace = "%s"`, ir, expectedTrace, f.gotTrace)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "the-authz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestAnonymousServer_WithoutTrace(t *testing.T) {
	f := FakeAnonymousAuthenticator{gotTrace: "-not-called-"}
	auth := sasler.AnonymousServer("the-authz", &f)

	gotName, gotClientFirst := auth.Mech()
	expectedName := "ANONYMOUS"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("")
	gotChallenge, err := auth.Data(ir)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned (%s, %v); expected (nil, nil)`, ir, gotChallenge, err)
	}
	expectedTrace := "-not-called-"
	if f.gotTrace != expectedTrace {
		t.Fatalf(`Data("%s") did not call StoreTrace("%s"); gotTrace = "%s"`, ir, expectedTrace, f.gotTrace)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "the-authz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

type FakeAnonymousAuthenticator struct {
	gotTrace string
}

func (f *FakeAnonymousAuthenticator) StoreTrace(trace string) {
	f.gotTrace = trace
}
