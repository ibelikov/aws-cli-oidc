package lib

import (
	"os"

	"github.com/mitchellh/go-homedir"
)

const OIDC_PROVIDER_METADATA_URL = "oidc_provider_metadata_url"
const CLIENT_ID = "client_id"
const CLIENT_SECRET = "client_secret"
const MAX_SESSION_DURATION_SECONDS = "max_session_duration_seconds"
const DEFAULT_IAM_ROLE_ARN = "default_iam_role_arn"

// OIDC config
const AWS_FEDERATION_ROLE_SESSION_NAME = "aws_federation_role_session_name"

// OAuth 2.0 Token Exchange
const TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
const TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"

var configdir string

func ConfigPath() string {
	if configdir != "" {
		return configdir
	}
	path := os.Getenv("AWS_CLI_OIDC_CONFIG")
	if path == "" {
		home, err := homedir.Dir()
		if err != nil {
			Exit(err)
		}
		path = home + "/.aws-cli-oidc"
	}
	return path
}
