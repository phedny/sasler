package sasler

import "github.com/xdg-go/stringprep"

// AnonymousClient returns a ClientMech implementation for the ANONYMOUS
// mechanism.
func AnonymousClient(trace string) (ClientMech, error) {
	preppedTrace, err := tracePrep.Prepare(trace)
	if err != nil {
		return nil, err
	}
	ir := []byte(preppedTrace)
	return &singleMessageClient{name: "ANONYMOUS", ir: ir}, nil
}

// AnonymousAuthenticator implements storing trace data.
type AnonymousAuthenticator interface {
	// StoreTrace is called to store trace information provided by the client.
	// Will not be called if the client didn't provide trace information.
	StoreTrace(trace string)
}

// AnonymousServer returns a ServerMech implementation for the ANONYMOUS
// mechanism.
func AnonymousServer(authz string, auth AnonymousAuthenticator) ServerMech {
	cb := func(ir []byte) (string, error) {
		preppedTrace, err := tracePrep.Prepare(string(ir))
		if err != nil {
			return "", err
		}
		if preppedTrace != "" {
			auth.StoreTrace(preppedTrace)
		}
		return authz, nil
	}
	return &singleMessageServer{name: "ANONYMOUS", cb: cb}
}

// tracePrep implements the "trace" stringprep profile.
var tracePrep stringprep.Profile = stringprep.Profile{
	Prohibits: []stringprep.Set{
		stringprep.TableC2_1,
		stringprep.TableC2_2,
		stringprep.TableC3,
		stringprep.TableC4,
		stringprep.TableC5,
		stringprep.TableC6,
		stringprep.TableC8,
		stringprep.TableC9,
	},
	CheckBiDi: true,
}
