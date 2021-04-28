package oauth2

import (
	"net/http/httputil"
	"testing"
	"time"

	"github.com/consensys/quorum-security-plugin-enterprise/internal/config"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	testifyassert "github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestIntrospectionResponse_GrantedAuthorities_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	l := (&IntrospectionResponse{
		Scope: "rpc://eth_blockNumber rpc://debug",
	}).GrantedAuthorities()

	assert.Len(l, 2)
	assert.Contains(l, &proto.GrantedAuthority{Service: "eth", Method: "blockNumber", Raw: "rpc://eth_blockNumber"})
	assert.Contains(l, &proto.GrantedAuthority{Service: "debug", Method: "*", Raw: "rpc://debug"})
}

func TestIntrospectionResponse_Verify_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	err := (&IntrospectionResponse{
		Active:   true,
		Audience: jwt.Audience{"node1"},
		Issuer:   "arbitrary issuer",
	}).Verify("node1", []string{"some issuer", "arbitrary issuer"})

	assert.NoError(err)
}

func TestIntrospectionResponse_VerifyExpiration_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	err := (&IntrospectionResponse{
		Active:     true,
		Expiration: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}).VerifyExpiration()

	assert.NoError(err)
}

func TestIntrospectionResponse_Verify_whenInvalidIssuer(t *testing.T) {
	assert := testifyassert.New(t)
	expectedAud := "arbitraryAud"
	expectedIssuer := "arbitraryIssuer"

	err := (&IntrospectionResponse{
		Active:     true,
		Audience:   jwt.Audience{expectedAud},
		Issuer:     "invalidIssuer",
		Expiration: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}).Verify(expectedAud, []string{expectedIssuer})

	assert.Error(err)
}

func TestIntrospectionResponse_Verify_whenInvalidAud(t *testing.T) {
	assert := testifyassert.New(t)
	expectedAud := "arbitraryAud"
	expectedIssuer := "arbitraryIssuer"

	err := (&IntrospectionResponse{
		Active:     true,
		Audience:   jwt.Audience{"invalidAud"},
		Issuer:     expectedAud,
		Expiration: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}).Verify(expectedAud, []string{expectedIssuer})

	assert.Error(err)
}

func TestBuildIntrospectionRequest_whenBasicAuth(t *testing.T) {
	assert := testifyassert.New(t)

	req, err := buildIntrospectionRequest("1234", &config.IntrospectionConfiguration{
		Endpoint: "http://abtiraryhost/introspect",
		AuthenticationConfig: &config.AuthenticationConfiguration{
			Method: config.AMClientSecretBasic,
			Credentials: config.EnvironmentAwareCredentials{
				config.AMClientSecretBasicClientId:     "foo",
				config.AMClientSecretBasicClientSecret: "bar",
			},
		},
	})

	assert.NoError(err)

	raw, _ := httputil.DumpRequest(req, true)

	t.Log(string(raw))

	req.Body, err = req.GetBody()
	assert.NoError(err, "get body")
	err = req.ParseForm()
	assert.NoError(err, "parsing form data")

	assert.Equal("1234", req.FormValue("token"))
	assert.Equal("access_token", req.FormValue("token_hint"))

	username, pwd, ok := req.BasicAuth()
	assert.True(ok, "basic auth header")
	assert.Equal("foo", username)
	assert.Equal("bar", pwd)
}

func TestBuildIntrospectionRequest_whenFormAuth(t *testing.T) {
	assert := testifyassert.New(t)

	req, err := buildIntrospectionRequest("1234", &config.IntrospectionConfiguration{
		Endpoint: "http://abtiraryhost/introspect",
		AuthenticationConfig: &config.AuthenticationConfiguration{
			Method: config.AMClientSecretForm,
			Credentials: config.EnvironmentAwareCredentials{
				config.AMClientSecretFormClientId:     "foo",
				config.AMClientSecretFormClientSecret: "bar",
			},
		},
	})

	assert.NoError(err)

	raw, _ := httputil.DumpRequest(req, true)

	t.Log(string(raw))
	req.Body, err = req.GetBody()
	assert.NoError(err, "get body")
	err = req.ParseForm()
	assert.NoError(err, "parsing form data")

	assert.Equal("foo", req.FormValue("client_id"))
	assert.Equal("bar", req.FormValue("client_secret"))
}
