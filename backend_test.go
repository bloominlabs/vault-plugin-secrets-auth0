package auth0

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

func (c *Client) testCreateClient(t *testing.T) (*ClientResponse, func()) {
	resp, err := c.createClient(
		CreateClientBody{
			Name:        fmt.Sprintf("vault-integration-rotate-root-%d", time.Now().UnixNano()),
			Description: "Client used in auth0 vault secret plugin integration test. Feel free to delete.",
			GrantTypes:  []string{"client_credentials"},
		},
	)

	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		err := c.deleteClient(resp.ClientID)

		if err != nil {
			t.Errorf("failed to delete '%s' ('%s'). please manually delete. err: %s", resp.Name, resp.ClientID, err)
		}
	}

	return resp, cleanup
}

func TestBackend_config_root(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name                  string
		configData            *rootTokenConfig
		expectedWriteResponse map[string]interface{}
		expectedReadResponse  map[string]interface{}
	}{
		{
			"errorsWithEmptyRequest",
			nil,
			map[string]interface{}{"error": "Missing client_secret, client_id, domain in configuration request"},
			map[string]interface{}{"error": "configuration does not exist. did you configure 'config/root'?"},
		},
		{
			"succeedsWithValidRequest",
			&rootTokenConfig{ClientID: "test", ClientSecret: "test", Domain: "test"},
			nil,
			map[string]interface{}{"client_id": "test", "domain": "test"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			confReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/root",
				Storage:   config.StorageView,
				Data:      nil,
			}

			if testCase.configData != nil {
				confReq.Data = map[string]interface{}{
					"client_id":     testCase.configData.ClientID,
					"client_secret": testCase.configData.ClientSecret,
					"domain":        testCase.configData.Domain,
				}
			}

			resp, err := b.HandleRequest(context.Background(), confReq)
			if err != nil {
				t.Fatal(err)
			}

			if testCase.expectedWriteResponse == nil {
				assert.Nil(t, resp)
			} else {
				assert.Equal(t, testCase.expectedWriteResponse, resp.Data)
			}

			confReq.Operation = logical.ReadOperation
			resp, err = b.HandleRequest(context.Background(), confReq)

			assert.Equal(t, testCase.expectedReadResponse, resp.Data)
		})
	}
}

type expectedResponseGenerator func(int) string

func TestBackend_rotate_root(t *testing.T) {
	DOMAIN := os.Getenv("TEST_AUTH0_DOMAIN")
	ACCESS_TOKEN := os.Getenv("TEST_AUTH0_ACCESS_TOKEN")

	if DOMAIN == "" || ACCESS_TOKEN == "" {
		t.Skip("missing 'TEST_AUTH0_DOMAIN' or 'TEST_AUTH0_ACCESS_TOKEN'. skipping...")
	}

	client, err := createClientWithAccessToken(context.Background(), DOMAIN, ACCESS_TOKEN)
	if err != nil {
		t.Fatal(err)
	}

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		// Name of the testcase
		name string

		// scopes to provide on the Auth0 Management API for the create client. See
		// APIs > Auth 0 Management API > Permissions in your auth0 dashboard for
		// list of available values
		scopes []string

		// the expected resp.Data from the config/rotate-root update operation
		expectedResponse map[string]interface{}

		// expectedResponseFactory can be used instead of expectResponse to
		// generate a response based on the created client.
		expectedResponseFactory func(*ClientResponse) map[string]interface{}
	}{
		{
			"failsWithInvalidGrants",
			nil,
			map[string]interface{}{"error": fmt.Sprintf("failed to create the auth0 client. err: oauth2: cannot fetch token: 403 Forbidden\nResponse: {\"error\":\"access_denied\",\"error_description\":\"Client is not authorized to access \\\"%s/api/v2/\\\". You might probably want to create a \\\"client-grant\\\" associated to this API. See: https://auth0.com/docs/api/v2#!/Client_Grants/post_client_grants\"}", DOMAIN)},
			nil,
		},
		{
			"succeedsWithRequest",
			[]string{"update:client_keys"},
			nil,
			func(resp *ClientResponse) map[string]interface{} {
				return map[string]interface{}{"id": resp.ClientID, "domain": DOMAIN}
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			confReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/root",
				Storage:   config.StorageView,
				Data:      nil,
			}

			createClientResponse, cleanup := client.testCreateClient(t)
			defer cleanup()
			confReq.Data = map[string]interface{}{
				"client_id":     createClientResponse.ClientID,
				"client_secret": createClientResponse.ClientSecret,
				"domain":        DOMAIN,
			}

			if testCase.scopes != nil {
				// Delete the client will automatically delete this so we dont need to
				// worry about cleanup
				_, err := client.createClientGrant(
					CreateClientGrantBody{
						ClientID: createClientResponse.ClientID,
						Audience: fmt.Sprintf("%s/api/v2/", DOMAIN),
						Scopes:   testCase.scopes,
					},
				)

				if err != nil {
					t.Fatal(err)
				}
			}

			resp, err := b.HandleRequest(context.Background(), confReq)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("failed to configure root: resp:%#v err:%s", resp, err)
			}

			confReq = &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/rotate-root",
				Storage:   config.StorageView,
				Data:      map[string]interface{}{},
			}

			resp, err = b.HandleRequest(context.Background(), confReq)

			if testCase.expectedResponseFactory != nil {
				assert.Equal(t, testCase.expectedResponseFactory(createClientResponse), resp.Data)
			} else {
				assert.Equal(t, testCase.expectedResponse, resp.Data)
			}

			// If there is an error, we cannot verify the new client secret
			if err != nil || (resp != nil && resp.IsError()) {
				return
			}

			conf, err := b.(*backend).readConfigRoot(context.Background(), config.StorageView)
			if err != nil {
				t.Fatal(err)
			}

			// TODO: try to generate a new token with the rotate client secret and
			// validate that token
			assert.Equal(t, createClientResponse.ClientID, conf.ClientID)
			assert.NotEqual(t, createClientResponse.ClientSecret, conf.ClientSecret)
		})
	}
}

func TestBackend_roles(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name                  string
		roleConfig            *auth0RoleEntry
		expectedWriteResponse map[string]interface{}
		expectedReadResponse  map[string]interface{}
	}{
		{
			"succeedsWithNilScopes",
			nil,
			map[string]interface{}{"scopes": "[]"},
			map[string]interface{}{"scopes": "[]"},
		},
		{
			"succeedsWithEmptyScopes",
			&auth0RoleEntry{Scopes: []string{}},
			map[string]interface{}{"scopes": "[]"},
			map[string]interface{}{"scopes": "[]"},
		},
		{
			"succeedsWithScopes",
			&auth0RoleEntry{Scopes: []string{"test1", "test2"}},
			map[string]interface{}{"scopes": "[\"test1\",\"test2\"]"},
			map[string]interface{}{"scopes": "[\"test1\",\"test2\"]"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			confReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      fmt.Sprintf("roles/%s", testCase.name),
				Storage:   config.StorageView,
				Data:      nil,
			}

			if testCase.roleConfig != nil {
				scopes, err := json.Marshal(testCase.roleConfig.Scopes)
				if err != nil {
					t.Fatal(err)
				}
				confReq.Data = map[string]interface{}{
					"scopes": scopes,
				}
			}

			resp, err := b.HandleRequest(context.Background(), confReq)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, testCase.expectedWriteResponse, resp.Data)

			confReq = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("roles/%s", testCase.name),
				Storage:   config.StorageView,
				Data:      nil,
			}
			resp, err = b.HandleRequest(context.Background(), confReq)
			if err != nil {
				t.Fatal(err)
			}

			var respData map[string]interface{} = nil
			if testCase.expectedReadResponse != nil {
				respData = resp.Data
			}
			assert.Equal(t, testCase.expectedReadResponse, respData)
		})
	}
}

func TestBackend_creds_create(t *testing.T) {
	DOMAIN := os.Getenv("TEST_AUTH0_DOMAIN")
	ACCESS_TOKEN := os.Getenv("TEST_AUTH0_ACCESS_TOKEN")

	if DOMAIN == "" || ACCESS_TOKEN == "" {
		t.Skip("missing 'TEST_AUTH0_DOMAIN' or 'TEST_AUTH0_ACCESS_TOKEN'. skipping...")
	}

	client, err := createClientWithAccessToken(context.Background(), DOMAIN, ACCESS_TOKEN)
	if err != nil {
		t.Fatal(err)
	}

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name            string
		clientScopes    []string
		requestedScopes []string
	}{
		{
			"succeedsWithScopes",
			[]string{"test"},
			[]string{"test"},
		},
		{
			"succeedsWithValidScopes",
			[]string{"read:clients", "read:client_summary"},
			[]string{"read:client_summary"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			confReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config/root",
				Storage:   config.StorageView,
				Data:      nil,
			}

			createClientResponse, cleanup := client.testCreateClient(t)
			defer cleanup()
			confReq.Data = map[string]interface{}{
				"client_id":     createClientResponse.ClientID,
				"client_secret": createClientResponse.ClientSecret,
				"domain":        DOMAIN,
			}

			if testCase.clientScopes != nil {
				// Delete the client will automatically delete this so we dont need to
				// worry about cleanup
				_, err := client.createClientGrant(
					CreateClientGrantBody{
						ClientID: createClientResponse.ClientID,
						Audience: fmt.Sprintf("%s/api/v2/", DOMAIN),
						Scopes:   testCase.clientScopes,
					},
				)

				if err != nil {
					t.Fatal(err)
				}
			}

			resp, err := b.HandleRequest(context.Background(), confReq)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("failed to configure root: resp:%#v err:%s", resp, err)
			}

			scopes, err := json.Marshal(testCase.requestedScopes)
			if err != nil {
				t.Fatal(err)
			}
			confReq = &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      fmt.Sprintf("roles/%s", testCase.name),
				Storage:   config.StorageView,
				Data:      map[string]interface{}{"scopes": scopes},
			}

			resp, err = b.HandleRequest(context.Background(), confReq)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("failed to configure role: resp:%#v err:%s", resp, err)
			}

			confReq = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("creds/%s", testCase.name),
				Storage:   config.StorageView,
				Data:      nil,
			}

			resp, err = b.HandleRequest(context.Background(), confReq)
			if err != nil || (resp != nil && resp.IsError()) {
				t.Fatalf("failed to create access token: resp:%#v err:%s", resp, err)
			}

			assert.Equal(t, resp.Data["token_type"], "Bearer")
			assert.NotEmpty(t, resp.Data["token"])

			tok, err := jwt.ParseSigned(resp.Data["token"].(string))
			if err != nil {
				t.Fatal(err)
			}

			// TODO: add JWT verification using JWKS
			var claims jwt.Claims
			var jwtScopes struct{ Scopes []string }
			if err := tok.UnsafeClaimsWithoutVerification(&claims, &jwtScopes); err != nil {
				t.Fatal(err)
			}

			var out []string
			err = json.Unmarshal(scopes, &out)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, testCase.requestedScopes, out)
		})
	}
}
