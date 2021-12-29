package auth0

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2/clientcredentials"
)

func pathCredsCreate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Create a auth0 management token from a Vault role",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsRead,
		},
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role := d.Get("role").(string)
	conf, err := b.readConfigRoot(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("err while getting root configuration for '%s'. err: %s", role, err)), nil
	}

	roleEntry, err := b.roleRead(ctx, req.Storage, role)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("err while getting role configuration for '%s'. err: %s", role, err)), nil
	}
	if roleEntry == nil {
		return logical.ErrorResponse(fmt.Sprintf("could not find entry for role '%s', did you configure it?", role)), nil
	}

	config := clientcredentials.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		// TODO: change to using .well-known/openid-configuration?
		TokenURL:       fmt.Sprintf("%s/oauth/token", conf.Domain),
		Scopes:         roleEntry.Scopes,
		EndpointParams: url.Values{"audience": {fmt.Sprintf("%s/api/v2/", conf.Domain)}},
	}

	// TODO: validate token
	// https://github.com/golang/oauth2/issues/128
	token, err := config.Token(ctx)

	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to create the access token. err: %s", err)), nil
	}

	// Use the helper to create the secret
	resp := b.Secret(SecretTokenType).Response(map[string]interface{}{
		"token":      token.AccessToken,
		"token_type": token.TokenType,
	}, map[string]interface{}{
		"token": token.AccessToken,
	})

	// Access tokens are valid for 24 hours (https://auth0.com/docs/tokens/management-api-access-tokens/get-management-api-access-tokens-for-production#get-access-tokens)
	duration := token.Expiry.UTC().Sub(time.Now().UTC())
	resp.Secret.TTL = duration
	resp.Secret.MaxTTL = duration

	return resp, nil
}
