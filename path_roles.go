package auth0

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameWithAtRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the policy",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Policy Name",
				},
			},

			"scopes": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `List of Auth0 Management API scopes to grant the access
				token generated with this role. See Auth0 Dashboard > APIs > Auth0
				Management API > Permissions for latest list of values`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathRolesDelete,
			logical.ReadOperation:   b.pathRolesRead,
			logical.UpdateOperation: b.pathRolesWrite,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.roleRead(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	scopes, err := json.Marshal(entry.Scopes)
	compactedScopes, err := compactJSON(string(scopes))
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("cannot parse compact scopes into json. err: %s", err)), nil
	}

	var resp logical.Response
	resp.Data = map[string]interface{}{"scopes": compactedScopes}

	return &resp, nil
}

func (b *backend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var resp logical.Response

	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.roleRead(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		roleEntry = &auth0RoleEntry{}
	}

	if scopesRaw, ok := d.GetOk("scopes"); ok {
		var scopes []string
		err := json.Unmarshal([]byte(scopesRaw.(string)), &scopes)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("cannot parse scopes: %q", scopesRaw.(string))), nil
		}
		roleEntry.Scopes = scopes
	}

	if roleEntry.Scopes == nil {
		roleEntry.Scopes = []string{}
	}
	scopes, err := json.Marshal(roleEntry.Scopes)
	compactedScopes, err := compactJSON(string(scopes))
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("cannot parse compact scopes into json. err: %s", err)), nil
	}

	resp.Data = map[string]interface{}{"scopes": compactedScopes}

	entry, err := logical.StorageEntryJSON("role/"+roleName, roleEntry)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("nil result when writing to storage")
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (b *backend) roleRead(ctx context.Context, s logical.Storage, roleName string) (*auth0RoleEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}
	entry, err := s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}
	var roleEntry auth0RoleEntry
	if entry != nil {
		if err := entry.DecodeJSON(&roleEntry); err != nil {
			return nil, err
		}
		return &roleEntry, nil
	}

	return nil, nil
}

type auth0RoleEntry struct {
	Scopes []string `json:"scopes"`
}

func compactJSON(input string) (string, error) {
	var compacted bytes.Buffer
	err := json.Compact(&compacted, []byte(input))
	return compacted.String(), err
}

const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRolesHelpSyn = `
Read, write and reference cloudflare policies that toekn can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create cloudflare tokens. These roles are associated with cloudflare polices that
map directly to the route to read the access keys. For example, if the
backend is mounted at "cloudflare" and you create a role at "cloudflare/roles/deploy"
then a user could request access credentials at "cloudflare/creds/deploy".

You can submit policies inline using a policy on disk (see Vault
documentation for more information
(https://www.vaultproject.io/docs/commands/write#examples)) or by submitting
a compact JSON as a value. Policies are only syntatically validated on write.
To validate the keys, attempt to read token after writing the policy.
`
