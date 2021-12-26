package auth0

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfigRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigRotateRootUpdate,
			},
		},

		HelpSynopsis:    pathConfigRotateRootHelpSyn,
		HelpDescription: pathConfigRotateRootHelpDesc,
	}
}

func (b *backend) pathConfigRotateRootUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.readConfigRoot(ctx, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error reading root configuration: {{err}}", err)
	}

	client, err := b.client(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to create the auth0 client. err: %s", err)), nil
	}
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}

	resp, err := client.rotateSecret(config.ClientID)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to rotate client secret. err: %s", err)), nil
	}

	config.ClientSecret = resp.ClientSecret

	newEntry, err := logical.StorageEntryJSON(configTokenKey, config)
	if err != nil {
		return nil, errwrap.Wrapf("error generating new config/root JSON: {{err}}", err)
	}
	if err := req.Storage.Put(ctx, newEntry); err != nil {
		return nil, errwrap.Wrapf("error saving new config/root: {{err}}", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"id":     config.ClientID,
			"domain": config.Domain,
		},
	}, nil
}

const pathConfigRotateRootHelpSyn = `
Request to rotate the root cloudflare token used by Vault
`

const pathConfigRotateRootHelpDesc = `
This path attempts to rotate the cloudflare credentials used by Vault for
this mount. It is only valid if Vault has been configured to use cloudflare
token via the config/token endpoint.`
