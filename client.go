package auth0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2/clientcredentials"
)

type Client struct {
	BaseURL string

	httpClient *http.Client
}

// https://auth0.com/docs/api/management/v2#!/Clients/post_clients
type CreateClientBody struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	GrantTypes  []string `json:"grant_types"`
}

type CreateClientGrantBody struct {
	ClientID string   `json:"client_id"`
	Audience string   `json:"audience"`
	Scopes   []string `json:"scope"`
}

type ClientGrantResponse struct {
	ID       string   `json:"id"`
	ClientID string   `json:"client_id"`
	Audience string   `json:"audience"`
	Scopes   []string `json:"scope"`
}

// https://auth0.com/docs/api/management/v2#!/Clients/post_rotate_secret
// TODO: verify if this works also with create client
type ClientResponse struct {
	Tenant                         string `json:"tenant"`
	Global                         bool   `json:"global"`
	IsTokenEndpointIPHeaderTrusted bool   `json:"is_token_endpoint_ip_header_trusted"`
	Name                           string `json:"name"`
	IsFirstParty                   bool   `json:"is_first_party"`
	OIDCConformant                 bool   `json:"oidc_conformant"`
	SSODisabled                    bool   `json:"sso_disabled"`
	CrossOriginAuth                bool   `json:"cross_origin_auth"`
	// RefreshToken
	// SigningKeys
	ClientID            string `json:"client_id"`
	CallbackURLTemplate bool   `json:"callback_url_template"`
	ClientSecret        string `json:"client_secret"`
	// JWTConfiguration
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	AppType                 string   `json:"app_type"`
	GrantTypes              []string `json:"grant_types"`
	CustomLoginPageOn       bool     `json:"custom_login_page_on"`
}

type Auth0Error struct {
	StatusCode int    `json:"statusCode"`
	ErrorType  string `json:"error"`
	Message    string `json:"message"`
	ErrorCode  string `json:"errorCode"`
}

func (e Auth0Error) Error() string {
	return fmt.Sprintf("%#v", e)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errwrap.Wrapf("error attempting request: {{err}}", err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 204 {
		defer resp.Body.Close()
		var apiError Auth0Error
		err = json.NewDecoder(resp.Body).Decode(&apiError)
		if err != nil {
			return nil, errwrap.Wrapf("error decoding error response from grafana cloud: {{err}}", err)
		}

		return nil, apiError
	}

	return resp, nil
}

func (c *Client) rotateSecret(clientID string) (*ClientResponse, error) {
	url := fmt.Sprintf("%s/api/v2/clients/%s/rotate-secret", c.BaseURL, clientID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to create rotate-secret request. err %s", err))
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var decodedResponse ClientResponse
	err = json.NewDecoder(resp.Body).Decode(&decodedResponse)
	if err != nil {
		return nil, errwrap.Wrapf("fail to decode rotate secret response body: {{err}}", err)
	}

	return &decodedResponse, nil
}

func (c *Client) deleteClient(clientID string) error {
	url := fmt.Sprintf("%s/api/v2/clients/%s", c.BaseURL, clientID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errors.New(fmt.Sprintf("failed to create 'delete client' request. err %s", err))
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (c *Client) createClientGrant(requestBody CreateClientGrantBody) (*ClientGrantResponse, error) {
	url := fmt.Sprintf("%s/api/v2/client-grants", c.BaseURL)
	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to create 'create grant' request. err %s", err))
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var decodedResponse ClientGrantResponse
	err = json.NewDecoder(resp.Body).Decode(&decodedResponse)
	if err != nil {
		return nil, errwrap.Wrapf("fail to decode response body: {{err}}", err)
	}

	return &decodedResponse, nil
}

func (c *Client) deleteClientGrant(ID string) error {
	url := fmt.Sprintf("%s/api/v2/client-grants", c.BaseURL)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errors.New(fmt.Sprintf("failed to create 'delete grant' request. err %s", err))
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var decodedResponse ClientGrantResponse
	err = json.NewDecoder(resp.Body).Decode(&decodedResponse)
	if err != nil {
		return errwrap.Wrapf("fail to decode response body: {{err}}", err)
	}

	return nil

}

func (c *Client) createClient(requestBody CreateClientBody) (*ClientResponse, error) {
	url := fmt.Sprintf("%s/api/v2/clients", c.BaseURL)
	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to create 'create client' request. err %s", err))
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var decodedResponse ClientResponse
	err = json.NewDecoder(resp.Body).Decode(&decodedResponse)
	if err != nil {
		return nil, errwrap.Wrapf("fail to decode rotate secret response body: {{err}}", err)
	}

	return &decodedResponse, nil
}

func createClientWithAuth0Client(ctx context.Context, domain string, clientID string, clientSecret string) (*Client, error) {
	config := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		// TODO: change to using .well-known/openid-configuration?
		TokenURL:       fmt.Sprintf("%s/oauth/token", domain),
		EndpointParams: url.Values{"audience": {fmt.Sprintf("%s/api/v2/", domain)}},
	}

	// TODO: validate token
	// https://github.com/golang/oauth2/issues/128
	_, err := config.Token(ctx)
	if err != nil {
		return nil, err
	}

	return &Client{
		BaseURL:    domain,
		httpClient: config.Client(ctx)}, nil
}

func (b *backend) client(ctx context.Context, s logical.Storage) (*Client, error) {
	conf, err := b.readConfigRoot(ctx, s)
	if err != nil {
		return nil, err
	}

	return createClientWithAuth0Client(ctx, conf.Domain, conf.ClientID, conf.ClientSecret)
}

type withHeader struct {
	http.Header
	rt http.RoundTripper
}

func WithHeader(rt http.RoundTripper) withHeader {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return withHeader{Header: make(http.Header), rt: rt}
}

func (h withHeader) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.Header {
		req.Header[k] = v
	}

	return h.rt.RoundTrip(req)
}

func createClientWithAccessToken(ctx context.Context, domain string, accessToken string) (*Client, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	rt := WithHeader(client.Transport)
	rt.Set("Authorization", "Bearer "+accessToken)
	client.Transport = rt

	return &Client{
		BaseURL:    domain,
		httpClient: client,
	}, nil
}
