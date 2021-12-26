VERSION 0.6
FROM golang:1.16
WORKDIR /vault-plugin-secrets-auth0

deps:
    COPY go.mod go.sum ./
    RUN go mod download
    SAVE ARTIFACT go.mod AS LOCAL go.mod
    SAVE ARTIFACT go.sum AS LOCAL go.sum

build:
    FROM +deps
    COPY *.go .
    COPY --dir ./cmd .
    RUN CGO_ENABLED=0 go build -o bin/vault-plugin-secrets-auth0 cmd/auth0/main.go
    SAVE ARTIFACT bin/vault-plugin-secrets-auth0 /auth0 AS LOCAL bin/vault-plugin-secrets-auth0

test:
    FROM +deps
    COPY *.go .
    ARG TEST_AUTH0_DOMAIN=https://test-stratos-host.us.auth0.com
    RUN --secret TEST_AUTH0_ACCESS_TOKEN TEST_AUTH0_DOMAIN=$TEST_AUTH0_DOMAIN CGO_ENABLED=0 go test github.com/bloominlabs/vault-plugin-secrets-auth0

dev:
  BUILD +build
  LOCALLY
  RUN bash ./scripts/dev.sh

all:
  BUILD +build
  BUILD +test
