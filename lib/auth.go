package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
)

func Authenticate(client *OIDCClient, roleArn string, maxSessionDurationSeconds int64, useSecret, asJson bool) {
	// Resolve target IAM Role ARN
	defaultIAMRoleArn := client.config.GetString(DEFAULT_IAM_ROLE_ARN)
	if roleArn == "" {
		roleArn = defaultIAMRoleArn
	}

	var awsCreds *AWSCredentials
	var err error

	// Try to reuse stored credential in secret
	if useSecret {
		awsCreds, err = AWSCredential(roleArn)
	}

	if !isValid(awsCreds) || err != nil {
		tokenResponse, err := doLogin(client)
		if err != nil {
			Writeln("Failed to login the OIDC provider")
			Exit(err)
		}

		Writeln("Login successful!")
		Traceln("ID token: %s", tokenResponse.IDToken)

		// Resolve max duration
		if maxSessionDurationSeconds <= 0 {
			maxSessionDurationSecondsString := client.config.GetString(MAX_SESSION_DURATION_SECONDS)
			maxSessionDurationSeconds, err = strconv.ParseInt(maxSessionDurationSecondsString, 10, 64)
			if err != nil {
				maxSessionDurationSeconds = 3600
			}
		}

		awsCreds, err = GetCredentialsWithOIDC(client, tokenResponse.IDToken, roleArn, maxSessionDurationSeconds)
		if err != nil {
			Writeln("Failed to get aws credentials with OIDC")
			Exit(err)
		}

		if useSecret {
			// Store into secret
			SaveAWSCredential(roleArn, awsCreds)
			Write("The AWS credentials has been saved in OS secret store")
		}
	}

	if asJson {
		awsCreds.Version = 1

		jsonBytes, err := json.Marshal(awsCreds)
		if err != nil {
			Writeln("Unexpected AWS credential response")
			Exit(err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		Writeln("")

		Export("AWS_ACCESS_KEY_ID", awsCreds.AWSAccessKey)
		Export("AWS_SECRET_ACCESS_KEY", awsCreds.AWSSecretKey)
		Export("AWS_SESSION_TOKEN", awsCreds.AWSSessionToken)
	}
}

func isValid(cred *AWSCredentials) bool {
	if cred == nil {
		return false
	}

	sess, err := session.NewSession()
	if err != nil {
		Writeln("Failed to create aws client session")
		Exit(err)
	}

	creds := credentials.NewStaticCredentialsFromCreds(credentials.Value{
		AccessKeyID:     cred.AWSAccessKey,
		SecretAccessKey: cred.AWSSecretKey,
		SessionToken:    cred.AWSSessionToken,
	})

	svc := sts.New(sess, aws.NewConfig().WithCredentials(creds))

	input := &sts.GetCallerIdentityInput{}

	_, err = svc.GetCallerIdentity(input)

	if err != nil {
		Writeln("The previous credential isn't valid")
	}

	return err == nil
}

func doLogin(client *OIDCClient) (*TokenResponse, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:8118")
	if err != nil {
		return nil, errors.Wrap(err, "Cannot start local http server to handle login redirect")
	}

	clientId := client.config.GetString(CLIENT_ID)
	redirect := "http://localhost:8118"
	v, err := pkce.CreateCodeVerifierWithLength(pkce.MaxLength)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot generate OAuth2 PKCE code_challenge")
	}
	challenge := v.CodeChallengeS256()
	verifier := v.String()

	authReq := client.Authorization().
		QueryParam("response_type", "code").
		QueryParam("client_id", clientId).
		QueryParam("redirect_uri", redirect).
		QueryParam("code_challenge", challenge).
		QueryParam("code_challenge_method", "S256").
		QueryParam("scope", "openid")

	url := authReq.Url()

	code := launch(client, url.String(), listener)
	if code != "" {
		return codeToToken(client, verifier, code, redirect)
	} else {
		return nil, errors.New("Login failed, can't retrieve authorization code")
	}
}

func launch(client *OIDCClient, url string, listener net.Listener) string {
	c := make(chan string)

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		url := req.URL
		q := url.Query()
		code := q.Get("code")

		res.Header().Set("Content-Type", "text/html")

		// Response result page
		message := "Login "
		if code != "" {
			message += "successful"
		} else {
			message += "failed"
		}
		res.Header().Set("Cache-Control", "no-store")
		res.Header().Set("Pragma", "no-cache")
		res.WriteHeader(200)
		res.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<body>
%s
</body>
</html>
`, message)))

		if f, ok := res.(http.Flusher); ok {
			f.Flush()
		}

		time.Sleep(100 * time.Millisecond)

		c <- code
	})

	srv := &http.Server{}
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	defer srv.Shutdown(ctx)

	go func() {
		if err := srv.Serve(listener); err != nil {
			// cannot panic, because this probably is an intentional close
		}
	}()

	var code string
	if err := browser.OpenURL(url); err == nil {
		code = <-c
	}

	return code
}

func codeToToken(client *OIDCClient, verifier string, code string, redirect string) (*TokenResponse, error) {
	form := client.ClientForm()
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirect)

	Traceln("code2token params:", form)

	res, err := client.Token().Request().Form(form).Post()

	if err != nil {
		return nil, errors.Wrap(err, "Failed to turn code into token")
	}

	if res.Status() != 200 {
		if res.MediaType() != "" {
			var json map[string]interface{}
			err := res.ReadJson(&json)
			if err == nil {
				return nil, errors.Errorf("Failed to turn code into token, error: %s error_description: %s",
					json["error"], json["error_description"])
			}
		}
		return nil, errors.Errorf("Failed to turn code into token")
	}

	var tokenResponse TokenResponse
	res.ReadJson(&tokenResponse)
	return &tokenResponse, nil
}
