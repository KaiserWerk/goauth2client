package goauth2client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Response struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        uint64 `json:"expires_in"`
	Scope            string `json:"scope"`
	RefreshToken     string `json:"refresh_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type Client struct {
	Config       *ClientConfig
	Auth         *AuthConfig
	httpClient   *http.Client
	AuthCallback AuthCallbackFunc
}

type AuthCallbackFunc func(*Response, error)

func New(clientConfig *ClientConfig, authConfig *AuthConfig, authCallback AuthCallbackFunc, httpClient *http.Client) *Client {
	if clientConfig == nil {
		panic("goauth2client: clientConfig is nil")
	}

	if clientConfig.State == "" {
		clientConfig.State = GenerateState()
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		Config:       clientConfig,
		Auth:         authConfig,
		httpClient:   httpClient,
		AuthCallback: authCallback,
	}
}

// BuildAuthURL builds the URL to navigate to in order to initialize the auth process.
func (cl *Client) BuildAuthURL() string {
	values := url.Values{}
	values.Add("response_type", "code")
	values.Add("client_id", cl.Auth.ClientID)
	values.Add("redirect_uri", cl.Config.LocalServerURL+cl.Config.LocalServerRedirectPath)
	values.Add("scope", cl.Config.Scope)
	values.Add("state", cl.Config.State)

	return fmt.Sprintf(`%s%s?%s`, cl.Config.AuthServerURL, cl.Config.AuthServerAuthPath, values.Encode())
}

// HandleAuthInit shows a very barebone page with a link to start the authentication process.
// Alternatively, use auth URL from cl.BuildAuthURL() and redirect to it programmatically.
func (cl *Client) HandleAuthInit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprint(w, "Please click here to authorize:<br><br>")
	fmt.Fprintf(w, `<a href="%s">Authorize</a>`, cl.BuildAuthURL())
}

// HandleCallback handles the returning *http.Request from the Auth server.
// it will call the AuthCallbackFunc initially supplied with the response data, once validated.
func (cl *Client) HandleCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	queryState := r.URL.Query().Get("state")
	queryCode := r.URL.Query().Get("code")
	if queryState == "" || queryCode == "" {
		cl.AuthCallback(nil, fmt.Errorf("callback: missing state and/or code parameter"))
		return
	}

	if queryState != cl.Config.State {
		cl.AuthCallback(nil, fmt.Errorf("callback: state parameter doesnt match"))
		return
	}

	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", cl.Auth.ClientID)
	values.Add("client_secret", cl.Auth.ClientSecret)
	values.Add("code", queryCode)
	values.Add("redirect_uri", cl.Config.LocalServerURL+cl.Config.LocalServerRedirectPath)

	resp, err := cl.httpClient.PostForm(cl.Config.AuthServerURL+cl.Config.AuthServerTokenPath, values)
	if err != nil {
		cl.AuthCallback(nil, fmt.Errorf("callback: failed to send code exchange request: %s", err.Error()))
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(r.Body)
	if err != nil {
		cl.AuthCallback(nil, fmt.Errorf("callback: failed to read response body"))
		return
	}

	fmt.Println("Raw response:", string(data))

	var res *Response
	if err = json.Unmarshal(data, &res); err != nil {
		cl.AuthCallback(nil, fmt.Errorf("callback: failed to unmarshal JSON response:", err.Error()))
		return
	}

	cl.AuthCallback(res, nil)
}
