package goauth2client

type ClientConfig struct {
	AuthServerURL       string
	AuthServerAuthPath  string
	AuthServerTokenPath string

	LocalServerURL          string
	LocalServerRedirectPath string

	Scope string
	State string
}

func (c *ClientConfig) IsValid() bool {
	if c.AuthServerURL == "" {
		return false
	}
	if c.AuthServerAuthPath == "" {
		return false
	}
	if c.AuthServerTokenPath == "" {
		return false
	}

	if c.LocalServerURL == "" {
		return false
	}
	if c.LocalServerRedirectPath == "" {
		return false
	}

	if c.Scope == "" {
		return false
	}
}
