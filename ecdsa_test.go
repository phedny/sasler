package sasler_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/phedny/sasler"
)

func TestEcdsaClient(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(`GenerateKey(elliptic.P256(), rand.Reader) returned error: %v`, err)
	}
	publicKey := &privateKey.PublicKey

	auth, err := sasler.EcdsaNist256pChallengeClient("", "user", privateKey)
	if err != nil {
		t.Fatalf(`EcdsaNist256pChallengeClint("", "user", privateKey) returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "ECDSA-NIST256P-CHALLENGE"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("user")
	if err != nil {
		t.Fatalf(`Data(nil) returned error: %v`, err)
	}
	if !bytes.Equal(gotIR, expectedIR) {
		t.Fatalf(`Data(nil) returned %s; expected %s`, gotIR, expectedIR)
	}

	challenge := make([]byte, 24)
	rand.Read(challenge)
	gotResponse, err := auth.Data(challenge)
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}
	if !ecdsa.VerifyASN1(publicKey, challenge, gotResponse) {
		t.Fatalf(`Data(challenge) returned signature that failed verification`)
	}
}

func TestEcdsaServer_DeriveAuthz(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(`GenerateKey(elliptic.P256(), rand.Reader) returned error: %v`, err)
	}

	auth := sasler.EcdsaNist256pChallengeServer(&fakeEcdsaAuthenticator{key: &privateKey.PublicKey})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "ECDSA-NIST256P-CHALLENGE"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("user")
	challenge, err := auth.Data(ir)
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, challenge)
	if err != nil {
		t.Fatalf(`SignASN1() returned error: %v`, err)
	}
	gotChallenge, err := auth.Data(sig)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "userZ"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestEcdsaServer_RequestedAuthz(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(`GenerateKey(elliptic.P256(), rand.Reader) returned error: %v`, err)
	}

	auth := sasler.EcdsaNist256pChallengeServer(&fakeEcdsaAuthenticator{key: &privateKey.PublicKey})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "ECDSA-NIST256P-CHALLENGE"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("RequestedAuthz\x00user")
	challenge, err := auth.Data(ir)
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, challenge)
	if err != nil {
		t.Fatalf(`SignASN1() returned error: %v`, err)
	}
	gotChallenge, err := auth.Data(sig)
	if gotChallenge != nil || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, nil)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "RequestedAuthz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestEcdsaServer_Unauthorized(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(`GenerateKey(elliptic.P256(), rand.Reader) returned error: %v`, err)
	}

	auth := sasler.EcdsaNist256pChallengeServer(&fakeEcdsaAuthenticator{key: &privateKey.PublicKey})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "ECDSA-NIST256P-CHALLENGE"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("InvalidAuthz\x00user")
	challenge, err := auth.Data(ir)
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, challenge)
	if err != nil {
		t.Fatalf(`SignASN1() returned error: %v`, err)
	}
	gotChallenge, err := auth.Data(sig)
	if gotChallenge != nil || err != sasler.ErrUnauthorized {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, ErrUnauthorized)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestEcdsaServer_InvalidSignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf(`GenerateKey(elliptic.P256(), rand.Reader) returned error: %v`, err)
	}

	auth := sasler.EcdsaNist256pChallengeServer(&fakeEcdsaAuthenticator{key: &privateKey.PublicKey})

	gotName, gotClientFirst := auth.Mech()
	expectedName := "ECDSA-NIST256P-CHALLENGE"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	ir := []byte("user")
	challenge, err := auth.Data(ir)
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, challenge)
	if err != nil {
		t.Fatalf(`SignASN1() returned error: %v`, err)
	}
	sig[0] += 1
	gotChallenge, err := auth.Data(sig)
	if gotChallenge != nil || err != sasler.ErrAuthenticationFailed {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, ErrAuthenticationFailed)`, ir, gotChallenge, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

type fakeEcdsaAuthenticator struct {
	key *ecdsa.PublicKey
}

func (f *fakeEcdsaAuthenticator) GetPublicKey(authn string) (*ecdsa.PublicKey, error) {
	return f.key, nil
}

func (*fakeEcdsaAuthenticator) DeriveAuthz(authn string) string {
	return authn + "Z"
}

func (*fakeEcdsaAuthenticator) Authorize(authz, authn string) bool {
	return authz == authn+"Z" || authz == "RequestedAuthz"
}
