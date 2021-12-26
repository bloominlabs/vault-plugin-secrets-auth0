package auth0

import (
	"context"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configTokenKey = "config/root"

func pathConfigRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			"client_secret": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Secret for auth0 Machine-To-Machine application authorized with *:client_keys and *:clients scopes",
			},
			"client_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "ID for auth0 Machine-To-Machine application authorized to Auth0 Management API for your domain",
			},
			"domain": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Auth0 domain the client id/secret is registered under",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRootRead,
			logical.CreateOperation: b.pathConfigRootWrite,
			logical.UpdateOperation: b.pathConfigRootWrite,
			logical.DeleteOperation: b.pathConfigRootDelete,
		},

		ExistenceCheck: b.configTokenExistenceCheck,
	}
}

func (b *backend) configTokenExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.readConfigRoot(ctx, req.Storage)
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

func (b *backend) readConfigRoot(ctx context.Context, storage logical.Storage) (*rootTokenConfig, error) {
	entry, err := storage.Get(ctx, configTokenKey)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	conf := &rootTokenConfig{}
	if err := entry.DecodeJSON(conf); err != nil {
		return nil, errwrap.Wrapf("error reading configuration: {{err}}", err)
	}

	return conf, nil
}

func (b *backend) pathConfigRootRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	conf, err := b.readConfigRoot(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if conf == nil {
		return logical.ErrorResponse("configuration does not exist. did you configure 'config/root'?"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"domain":    conf.Domain,
			"client_id": conf.ClientID,
		},
	}, nil
}

func (b *backend) pathConfigRootWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	conf, err := b.readConfigRoot(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if conf == nil {
		conf = &rootTokenConfig{}
	}

	var missingOptions []string
	clientSecret, ok := data.GetOk("client_secret")
	if !ok {
		missingOptions = append(missingOptions, "client_secret")
	} else {
		conf.ClientSecret = clientSecret.(string)
	}

	clientID, ok := data.GetOk("client_id")
	if !ok {
		missingOptions = append(missingOptions, "client_id")
	} else {
		conf.ClientID = clientID.(string)
	}

	domain, ok := data.GetOk("domain")
	if !ok {
		missingOptions = append(missingOptions, "domain")
	} else {
		conf.Domain = domain.(string)
	}

	if len(missingOptions) > 0 {
		return logical.ErrorResponse("Missing %s in configuration request", strings.Join(missingOptions, ", ")), nil
	}

	entry, err := logical.StorageEntryJSON(configTokenKey, conf)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRootDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configTokenKey); err != nil {
		return nil, err
	}
	return nil, nil
}

type rootTokenConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Domain       string `json:"domain"`
}

const pathConfigRootHelpSyn = `
Configure auth0 client credentials used by vault
`

const pathConfigRootHelpDesc = `
Will confugre this mount with a oauth client used by Vault for all auth0
operations on this mount. Must be configured with: TODO.

For instructions on how to setup a Machine-to-Machine Application for
Management API, see auth0's documentation
(https://auth0.com/docs/tokens/management-api-access-tokens/create-and-authorize-a-machine-to-machine-application).
`
