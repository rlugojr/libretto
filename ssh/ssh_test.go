// Copyright 2015 Apcera Inc. All rights reserved.

package ssh

import (
	"errors"
	"net"
	"testing"

	cssh "github.com/apcera/libretto/Godeps/_workspace/src/golang.org/x/crypto/ssh"
)

func requireMockedClient() SSHClient {
	c := SSHClient{}
	c.Creds = &Credentials{}
	dial = func(p string, a string, c *cssh.ClientConfig) (*cssh.Client, error) {
		return nil, nil
	}
	readPrivateKey = func(path string) (cssh.AuthMethod, error) {
		return nil, nil
	}
	return c
}

// TestConnectNoUsername tests that an error is returned if no username is provided.
func TestConnectNoUsername(t *testing.T) {
	c := requireMockedClient()
	err := c.Connect()
	if err != ErrInvalidUsername {
		t.Logf("Invalid error type returned %s", err)
		t.Fail()
	}
}

// TestConnectNoPassword tests that an error is returned if no password or key is provided.
func TestConnectNoPassword(t *testing.T) {
	c := requireMockedClient()
	c.Creds.SSHUser = "foo"
	err := c.Connect()
	if err != ErrInvalidAuth {
		t.Logf("Invalid error type returned %s", err)
		t.Fail()
	}
}

// TestConnectAuthPrecedence tests that key based auth takes precedence over password based auth
func TestConnectAuthPrecedence(t *testing.T) {
	c := requireMockedClient()
	count := 0

	c.Creds = &Credentials{
		SSHUser:       "test",
		SSHPassword:   "test",
		SSHPrivateKey: "/foo",
	}

	readPrivateKey = func(path string) (cssh.AuthMethod, error) {
		count++
		return nil, nil
	}
	err := c.Connect()
	if err != nil {
		t.Logf("Expected nil error, got %s", err)
		t.Fail()
	}
	if count != 1 {
		t.Logf("Should have called the password key method %d times", count)
		t.Fail()
	}
}

// TestIsTooManyColonsErr tests that IsTooManyColonsErr() only returns true when
// "too many colons in address" OpError is returned from net.SplitHostPort().
// This error is important because we're catching it and rewriting it to also
// include a message that the error may have been cause by IPv4 address
// exhaustion.
func TestIsTooManyColonsErr(t *testing.T) {
	cases := []struct {
		input error
		want  bool
	}{
		{&net.OpError{Op: "dial", Err: errors.New("too many colons in address")}, true},
		{&net.OpError{Op: "wrong op", Err: errors.New("should return false")}, false},
	}

	for _, testCase := range cases {
		if got := IsTooManyColonsErr(testCase.input); got != testCase.want {
			t.Fatalf("IsTooManyColons(%v)\n\tgot:  %v\n\twant: %v", testCase.input, got, testCase.want)
		}
	}
}
