# Vault Secrets Plugin - Auth0

[Vault][vault] secrets plugins to simplying creation, management, and
revocation of [auth0 management API tokens][auth0-management-api-tokens].

## Usage

### Setup Endpoint

1. Download and enable plugin locally (TODO)

2. Configure the plugin

   ```
   vault write /auth0/config/root domain=<token> client_id=<client-id> client_secret=<client-secret>
   ```

3. Add one or more policies

### Configure Policies

```
vault write /auth0/roles/<role-name> scopes=["test"]
```

you can then read from the role using

```
vault read /auth0/creds/<role-name>
```

### Rotating the Root Token

The plugin supports rotating the configured admin token to seamlessly improve
security.

To rotate the token, perform a 'write' operation on the
`config/rotate-root` endpoint

```bash
> export VAULT_ADDR="http://localhost:8200"
> vault write -f config/rotate-root
vault write -f auth0/config/rotate-root
Key       Value
---       -----
domain    <domain>
id        <client_id>
```

### Generate a new Token

To generate a new token:

[Create a new auth0 policy](#configure-policies) and perform a 'read' operation on the `creds/<role-name>` endpoint.

```bash
# To read data using the api
$ vault read auth0/role/create-user
Key                Value
---                -----
lease_id           auth0/creds/test/arwU5tYDdw05Vwa306AOfjeP
lease_duration     24h
lease_renewable    false
token              <token>
token_type         Bearer
```

## Development

The provided [Earthfile] ([think makefile, but using
docker](https://earthly.dev)) is used to build, test, and publish the plugin.
See the build targets for more information. Common targets include

```bash
# build a local version of the plugin
$ earthly +build

# execute integration tests
#
# use https://developers.auth0.com/api/tokens/create to create a token
# with 'User:API Tokens:Edit' permissions
$ TEST_auth0_TOKEN=<YOUR_auth0_TOKEN> earthly --secret TEST_auth0_TOKEN +test

# start vault and enable the plugin locally
earthly +dev
```

[vault]: https://www.vaultproject.io/
[auth0-management-api-tokens]: https://auth0.com/docs/security/tokens/access-tokens/management-api-access-tokens
[earthfile]: ./Earthfile
