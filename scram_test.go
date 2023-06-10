package sasler

import (
	"bytes"
	"errors"
	"testing"
)

func TestScramSha1Client(t *testing.T) {
	auth, err := ScramSha1Client("", "user", []byte("pencil"))
	if err != nil {
		t.Fatalf(`ScramSha1Client("", "user", "pencil") returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramClientMech).clientNonce = []byte("fyko+d2lbbFgONRv9qkxdawL")

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	if err != nil {
		t.Fatalf(`Data(nil) returned error: %v`, err)
	}
	if !bytes.Equal(gotIR, expectedIR) {
		t.Fatalf(`Data(nil) returned %s; expected %s`, gotIR, expectedIR)
	}

	challenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	gotResponse, err := auth.Data(challenge)
	expectedResponse := []byte("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}
	if !bytes.Equal(gotResponse, expectedResponse) {
		t.Fatalf(`Data("%s") returned %s; expected %s`, challenge, gotResponse, expectedResponse)
	}

	challenge = []byte("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=")
	gotResponse, err = auth.Data(challenge)
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}
	if gotResponse != nil {
		t.Fatalf(`Data("%s") returned %s; expected nil`, challenge, gotResponse)
	}
}

func TestScramSha1Client_RequestedAuthz(t *testing.T) {
	auth, err := ScramSha1Client("RequestedAuthz", "user", []byte("pencil"))
	if err != nil {
		t.Fatalf(`ScramSha1Client("RequestedAuthz", "user", "pencil") returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramClientMech).clientNonce = []byte("fyko+d2lbbFgONRv9qkxdawL")

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("n,a=RequestedAuthz,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	if err != nil {
		t.Fatalf(`Data(nil) returned error: %v`, err)
	}
	if !bytes.Equal(gotIR, expectedIR) {
		t.Fatalf(`Data(nil) returned %s; expected %s`, gotIR, expectedIR)
	}

	challenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	gotResponse, err := auth.Data(challenge)
	expectedResponse := []byte("c=bixhPVJlcXVlc3RlZEF1dGh6LA==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=Y1CrAXpRtiwzxkxa33oLCr6ShzY=")
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}
	if !bytes.Equal(gotResponse, expectedResponse) {
		t.Fatalf(`Data("%s") returned %s; expected %s`, challenge, gotResponse, expectedResponse)
	}

	challenge = []byte("v=DLwvoqxRReuaVe1fCmOZJaEMJ6s=")
	gotResponse, err = auth.Data(challenge)
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}
	if gotResponse != nil {
		t.Fatalf(`Data("%s") returned %s; expected nil`, challenge, gotResponse)
	}
}

func TestScramSha1Client_ModifiedClientNonce(t *testing.T) {
	auth, err := ScramSha1Client("", "user", []byte("pencil"))
	if err != nil {
		t.Fatalf(`ScramSha1Client("", "user", "pencil") returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramClientMech).clientNonce = []byte("fyko+d2lbbFgONRv9qkxdawL")

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	if err != nil {
		t.Fatalf(`Data(nil) returned error: %v`, err)
	}
	if !bytes.Equal(gotIR, expectedIR) {
		t.Fatalf(`Data(nil) returned %s; expected %s`, gotIR, expectedIR)
	}

	challenge := []byte("r=FYko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	gotResponse, err := auth.Data(challenge)
	expectedResponse := []byte("")
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf(`Data("%s") returned error: %v; expected ErrAuthenticationFailed`, challenge, err)
	}
	if !bytes.Equal(gotResponse, expectedResponse) {
		t.Fatalf(`Data("%s") returned %s; expected %s`, challenge, gotResponse, expectedResponse)
	}
}

func TestScramSha1Client_InvalidServerSignature(t *testing.T) {
	auth, err := ScramSha1Client("", "user", []byte("pencil"))
	if err != nil {
		t.Fatalf(`ScramSha1Client("", "user", "pencil") returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramClientMech).clientNonce = []byte("fyko+d2lbbFgONRv9qkxdawL")

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	if err != nil {
		t.Fatalf(`Data(nil) returned error: %v`, err)
	}
	if !bytes.Equal(gotIR, expectedIR) {
		t.Fatalf(`Data(nil) returned %s; expected %s`, gotIR, expectedIR)
	}

	challenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	gotResponse, err := auth.Data(challenge)
	expectedResponse := []byte("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}
	if !bytes.Equal(gotResponse, expectedResponse) {
		t.Fatalf(`Data("%s") returned %s; expected %s`, challenge, gotResponse, expectedResponse)
	}

	challenge = []byte("v=RMF9pqV8S7suAoZWja4dJRkFsKQ=")
	gotResponse, err = auth.Data(challenge)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf(`Data("%s") returned error: %v; expected ErrAuthenticationFailed`, challenge, err)
	}
	if gotResponse != nil {
		t.Fatalf(`Data("%s") returned %s; expected nil`, challenge, gotResponse)
	}
}

func TestScramSha256Client(t *testing.T) {
	auth, err := ScramSha256Client("", "user", []byte("pencil"))
	if err != nil {
		t.Fatalf(`ScramSha256Client("", "user", "pencil") returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-256"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramClientMech).clientNonce = []byte("rOprNGfwEbeRWgbNEkqO")

	gotIR, err := auth.Data(nil)
	expectedIR := []byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
	if err != nil {
		t.Fatalf(`Data(nil) returned error: %v`, err)
	}
	if !bytes.Equal(gotIR, expectedIR) {
		t.Fatalf(`Data(nil) returned %s; expected %s`, gotIR, expectedIR)
	}

	challenge := []byte("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
	gotResponse, err := auth.Data(challenge)
	expectedResponse := []byte("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}
	if !bytes.Equal(gotResponse, expectedResponse) {
		t.Fatalf(`Data("%s") returned %s; expected %s`, challenge, gotResponse, expectedResponse)
	}

	challenge = []byte("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
	gotResponse, err = auth.Data(challenge)
	if err != nil {
		t.Fatalf(`Data("%s") returned error: %v`, challenge, err)
	}
	if gotResponse != nil {
		t.Fatalf(`Data("%s") returned %s; expected nil`, challenge, gotResponse)
	}
}
func TestScramSha1Server_DeriveAuthz(t *testing.T) {
	auth, err := ScramSha1Server(&FakeScramAuthenticator{false, false})
	if err != nil {
		t.Fatalf(`ScramSha1Server(...) returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramServerMech).serverNonce = []byte("3rfcNHYJY1ZVvWVs7j")

	ir := []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	gotChallenge, err := auth.Data(ir)
	expectedChallenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	if !bytes.Equal(gotChallenge, expectedChallenge) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, ir, gotChallenge, err, expectedChallenge)
	}

	response := []byte("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	gotServerSignature, err := auth.Data(response)
	expectedServerSignature := []byte("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=")
	if !bytes.Equal(gotServerSignature, expectedServerSignature) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, response, gotServerSignature, err, expectedServerSignature)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "userZ"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestScramSha1Server_DeriveAuthzSaltedPasswd(t *testing.T) {
	auth, err := ScramSha1Server(&FakeScramAuthenticator{false, true})
	if err != nil {
		t.Fatalf(`ScramSha1Server(...) returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramServerMech).serverNonce = []byte("3rfcNHYJY1ZVvWVs7j")

	ir := []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	gotChallenge, err := auth.Data(ir)
	expectedChallenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	if !bytes.Equal(gotChallenge, expectedChallenge) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, ir, gotChallenge, err, expectedChallenge)
	}

	response := []byte("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	gotServerSignature, err := auth.Data(response)
	expectedServerSignature := []byte("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=")
	if !bytes.Equal(gotServerSignature, expectedServerSignature) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, response, gotServerSignature, err, expectedServerSignature)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "userZ"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestScramSha1Server_RequestedAuthz(t *testing.T) {
	auth, err := ScramSha1Server(&FakeScramAuthenticator{false, false})
	if err != nil {
		t.Fatalf(`ScramSha1Server(...) returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramServerMech).serverNonce = []byte("3rfcNHYJY1ZVvWVs7j")

	ir := []byte("n,a=RequestedAuthz,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	gotChallenge, err := auth.Data(ir)
	expectedChallenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	if !bytes.Equal(gotChallenge, expectedChallenge) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, ir, gotChallenge, err, expectedChallenge)
	}

	response := []byte("c=bixhPVJlcXVlc3RlZEF1dGh6LA==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=Y1CrAXpRtiwzxkxa33oLCr6ShzY=")
	gotServerSignature, err := auth.Data(response)
	expectedServerSignature := []byte("v=DLwvoqxRReuaVe1fCmOZJaEMJ6s=")
	if !bytes.Equal(gotServerSignature, expectedServerSignature) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, response, gotServerSignature, err, expectedServerSignature)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "RequestedAuthz"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestScramSha1Server_InvalidClientProof(t *testing.T) {
	auth, err := ScramSha1Server(&FakeScramAuthenticator{false, false})
	if err != nil {
		t.Fatalf(`ScramSha1Server(...) returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramServerMech).serverNonce = []byte("3rfcNHYJY1ZVvWVs7j")

	ir := []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	gotChallenge, err := auth.Data(ir)
	expectedChallenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	if !bytes.Equal(gotChallenge, expectedChallenge) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, ir, gotChallenge, err, expectedChallenge)
	}

	response := []byte("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=V0x8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	gotServerSignature, err := auth.Data(response)
	if gotServerSignature != nil || err != ErrAuthenticationFailed {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, ErrAuthenticationFailed)`, response, gotServerSignature, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestScramSha1Server_ModifiedClientNonce(t *testing.T) {
	auth, err := ScramSha1Server(&FakeScramAuthenticator{false, false})
	if err != nil {
		t.Fatalf(`ScramSha1Server(...) returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramServerMech).serverNonce = []byte("3rfcNHYJY1ZVvWVs7j")

	ir := []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	gotChallenge, err := auth.Data(ir)
	expectedChallenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	if !bytes.Equal(gotChallenge, expectedChallenge) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, ir, gotChallenge, err, expectedChallenge)
	}

	response := []byte("c=biws,r=FYko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	gotServerSignature, err := auth.Data(response)
	if gotServerSignature != nil || err != ErrInvalidMessage {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, ErrInvalidMessage)`, response, gotServerSignature, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestScramSha1Server_ModifiedServerNonce(t *testing.T) {
	auth, err := ScramSha1Server(&FakeScramAuthenticator{false, false})
	if err != nil {
		t.Fatalf(`ScramSha1Server(...) returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-1"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramServerMech).serverNonce = []byte("3rfcNHYJY1ZVvWVs7j")

	ir := []byte("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
	gotChallenge, err := auth.Data(ir)
	expectedChallenge := []byte("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
	if !bytes.Equal(gotChallenge, expectedChallenge) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, ir, gotChallenge, err, expectedChallenge)
	}

	response := []byte("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3RFcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	gotServerSignature, err := auth.Data(response)
	if gotServerSignature != nil || err != ErrInvalidMessage {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected (nil, ErrInvalidMessage)`, response, gotServerSignature, err)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := ""
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

func TestScramSha256Server_DeriveAuthz(t *testing.T) {
	auth, err := ScramSha256Server(&FakeScramAuthenticator{true, false})
	if err != nil {
		t.Fatalf(`ScramSha256Server(...) returned error: %v`, err)
	}

	gotName, gotClientFirst := auth.Mech()
	expectedName := "SCRAM-SHA-256"
	if gotName != expectedName || !gotClientFirst {
		t.Fatalf(`Name() returned ("%s", %v); expected ("%s", true)`, gotName, gotClientFirst, expectedName)
	}

	// overwrite generated nonce to make the test deterministic
	auth.(*scramServerMech).serverNonce = []byte("%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")

	ir := []byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
	gotChallenge, err := auth.Data(ir)
	expectedChallenge := []byte("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
	if !bytes.Equal(gotChallenge, expectedChallenge) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, ir, gotChallenge, err, expectedChallenge)
	}

	response := []byte("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	gotServerSignature, err := auth.Data(response)
	expectedServerSignature := []byte("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
	if !bytes.Equal(gotServerSignature, expectedServerSignature) || err != nil {
		t.Fatalf(`Data("%s") returned ("%s", %v); expected ("%s", nil)`, response, gotServerSignature, err, expectedServerSignature)
	}

	gotCompleted, gotAuthz := auth.HasCompleted()
	expectedAuthz := "userZ"
	if !gotCompleted || gotAuthz != expectedAuthz {
		t.Fatalf(`HasCompleted() returned (%v, "%s"); expected (true, "%s")`, gotCompleted, gotAuthz, expectedAuthz)
	}
}

type FakeScramAuthenticator struct {
	otherSalt bool
	salted    bool
}

func (f *FakeScramAuthenticator) GetCredentials(authn string) (passwd []byte, isSalted bool, salt []byte, iCount int, err error) {
	salt = []byte("A%\xc2G\xe4:\xb1\xe9<m\xffv")
	if f.otherSalt {
		salt = []byte("[m\x99h\x9d\x125\x8e\xec\xa0K\x14\x126\xfa\x81")
	}
	iCount = 4096
	isSalted = f.salted
	passwd = []byte("pencil")
	if isSalted {
		passwd = []byte("\x1d\x96\xee:R\x9bZ_\x9eG\xc0\x1f\"\x9a,\xb8\xa6\xe1_}")
	}
	return
}

func (*FakeScramAuthenticator) DeriveAuthz(authn string) string {
	return authn + "Z"
}

func (*FakeScramAuthenticator) Authorize(authz, authn string) bool {
	return authz == authn+"Z" || authz == "RequestedAuthz"
}
