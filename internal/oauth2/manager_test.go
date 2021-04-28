package oauth2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/consensys/quorum-security-plugin-enterprise/internal/config"
	"github.com/golang/protobuf/ptypes"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	testifyassert "github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	arbitraryNode   = "node1"
	arbitraryIssuer = "arbitraryIssuer"
)

func TestManager_Authenticate_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	config := newTypicalTokenValidationConfiguration()
	config.JWTConfig.PreferIntrospection = true
	testObject, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	rawAccessToken := "xyz"
	arbitraryIntrospectionResponse, arbitraryClaims := IntrospectionResponse{
		Active:     true,
		Audience:   jwt.Audience{arbitraryNode},
		Expiration: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		Issuer:     arbitraryIssuer,
		Scope:      "rpc://admin_*   rpc://web3_clientVersion",
	}, CustomClaims{}
	// caching so we don't need to stub the http client
	testObject.cache.AddExpiryAwareItem("introspection-"+rawAccessToken, arbitraryIntrospectionResponse)
	testObject.cache.AddExpiryAwareItem("jws-"+rawAccessToken, arbitraryClaims)

	response, err := testObject.Authenticate(context.Background(), &proto.AuthenticationToken{
		RawToken: []byte("Bearer " + rawAccessToken),
	})

	assert.NoError(err)
	timestamp, err := ptypes.Timestamp(response.ExpiredAt)
	assert.NoError(err, "proto timestamp must be valid")
	assert.True(arbitraryIntrospectionResponse.Expiration.Time().Equal(timestamp))
	assert.Equal(2, len(response.Authorities))
	assert.Contains(response.Authorities, &proto.GrantedAuthority{
		Service: "admin",
		Method:  "*",
		Raw:     "rpc://admin_*",
	})
	assert.Contains(response.Authorities, &proto.GrantedAuthority{
		Service: "web3",
		Method:  "clientVersion",
		Raw:     "rpc://web3_clientVersion",
	})
}

func TestManager_introspect_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	testObject, err := NewManager(newTypicalTokenValidationConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	// stub the client to test
	validIntrospectionResponse := &IntrospectionResponse{
		Active:     true,
		Issuer:     arbitraryIssuer,
		Audience:   jwt.Audience{arbitraryNode},
		IssuedAt:   jwt.NewNumericDate(time.Now()),
		Expiration: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		Scope:      "admin:*",
	}
	testObject.introspectionClient = newStubClient(func(req *http.Request) (*http.Response, error) {
		pr, pw := io.Pipe()
		resp := &http.Response{
			Body: ioutil.NopCloser(pr),
		}
		go func() {
			_ = json.NewEncoder(pw).Encode(validIntrospectionResponse)
			defer func() {
				_ = pw.Close()
			}()
		}()
		return resp, nil
	})
	testObject.jwsClient = nil

	authToken, err := testObject.introspect("arbitrary token")

	assert.NoError(err)

	assert.Equal(validIntrospectionResponse, authToken)
}

func TestManager_Validate_whenUseCachedIntrospection(t *testing.T) {
	assert := testifyassert.New(t)

	testObject, err := NewManager(newTypicalTokenValidationConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	// stub the client to test
	validIntrospectionResponse := &IntrospectionResponse{
		Active:     true,
		Issuer:     arbitraryIssuer,
		Audience:   jwt.Audience{arbitraryNode},
		IssuedAt:   jwt.NewNumericDate(time.Now()),
		Expiration: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		Scope:      "admin:*",
	}
	testObject.introspectionClient = newStubClient(func(req *http.Request) (*http.Response, error) {
		pr, pw := io.Pipe()
		resp := &http.Response{
			Body: ioutil.NopCloser(pr),
		}
		go func() {
			_ = json.NewEncoder(pw).Encode(validIntrospectionResponse)
			defer func() {
				_ = pw.Close()
			}()
		}()
		return resp, nil
	})
	testObject.jwsClient = nil

	authToken, err := testObject.introspect("arbitrary token")

	assert.NoError(err)

	// test cached instrospection
	testObject.introspectionClient = newStubClient(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("not supposed to be called")
	})
	cachedAuthToken, err := testObject.introspect("arbitrary token")
	assert.NoError(err)

	assert.Equal(authToken, cachedAuthToken)
}

func TestManager_Validate_JWT_whenUseJWS(t *testing.T) {
	assert := testifyassert.New(t)

	testObject, err := NewManager(newTypicalTokenValidationConfiguration())
	if err != nil {
		t.Fatal(err)
	}

	cc := &CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   arbitraryIssuer,
			Audience: jwt.Audience{arbitraryNode},
			Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		extra: map[string]interface{}{
			"scope": "admin:*",
		},
	}
	token, jws, err := signJWTToken(cc)
	assert.NoError(err, "signing JWT token")
	// stub the client to test
	testObject.introspectionClient = nil
	testObject.jwsClient = newStubClient(func(req *http.Request) (*http.Response, error) {
		resp := &http.Response{
			Body: ioutil.NopCloser(bytes.NewReader(jws)),
		}
		return resp, nil
	})

	authToken, err := testObject.claim(token)

	assert.NoError(err, "validating")

	assert.Equal(cc.Issuer, authToken.Issuer)
}

func TestManager_Validate_JWT_whenUseCachedJWS(t *testing.T) {
	assert := testifyassert.New(t)

	testObject, err := NewManager(newTypicalTokenValidationConfiguration())
	if err != nil {
		t.Fatal(err)
	}

	cc := &CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   arbitraryIssuer,
			Audience: jwt.Audience{arbitraryNode},
			Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		extra: map[string]interface{}{
			"scope": "admin.*",
		},
	}
	token, jws, err := signJWTToken(cc)
	assert.NoError(err, "signing JWT token")
	// stub the client to test
	testObject.introspectionClient = nil
	testObject.jwsClient = newStubClient(func(req *http.Request) (*http.Response, error) {
		resp := &http.Response{
			Body: ioutil.NopCloser(bytes.NewReader(jws)),
		}
		return resp, nil
	})

	authToken, err := testObject.claim(token)

	assert.NoError(err, "validating")

	// test cached instrospection
	testObject.jwsClient = newStubClient(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("not supposed to be called")
	})
	cachedAuthToken, err := testObject.claim(token)
	assert.NoError(err)

	assert.Equal(authToken, cachedAuthToken)
}

func TestManager_authorize_whenPreferIntrospection(t *testing.T) {
	assert := testifyassert.New(t)

	config := newTypicalTokenValidationConfiguration()
	config.JWTConfig.PreferIntrospection = true
	testObject, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	rawAccessToken := "raw access token"
	arbitraryIntrospectionResponse, arbitraryClaims := IntrospectionResponse{}, CustomClaims{}
	// caching so we don't need to stub the http client
	testObject.cache.AddExpiryAwareItem("introspection-"+rawAccessToken, arbitraryIntrospectionResponse)
	testObject.cache.AddExpiryAwareItem("jws-"+rawAccessToken, arbitraryClaims)

	helper, err := testObject.authorize(rawAccessToken)

	assert.NoError(err)
	assert.IsType(&IntrospectionResponse{}, helper)
}

// even when preferIntrospection flag is set, if introspection fails
// then fallback to use JWT with signature validation
func TestManager_authorize_whenPreferIntrospectionButError(t *testing.T) {
	assert := testifyassert.New(t)

	config := newTypicalTokenValidationConfiguration()
	config.JWTConfig.PreferIntrospection = true
	testObject, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	arbitraryClaims := CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   arbitraryIssuer,
			Audience: jwt.Audience{arbitraryNode},
			Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		extra: map[string]interface{}{
			"scope": "admin.*",
		},
	}
	token, _, err := signJWTToken(&arbitraryClaims)
	// caching so we don't need to stub the http client
	testObject.cache.AddExpiryAwareItem("jws-"+token, arbitraryClaims)

	helper, err := testObject.authorize(token)

	assert.NoError(err)
	assert.IsType(&claimsAdapter{}, helper)
}

// even when preferIntrospection flag is false,
// introspection response is overriden by JWT
func TestManager_authorize_whenUseJWTOverridingIntrospection(t *testing.T) {
	assert := testifyassert.New(t)

	config := newTypicalTokenValidationConfiguration()
	config.JWTConfig.PreferIntrospection = false
	testObject, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	arbitraryClaims := CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   arbitraryIssuer,
			Audience: jwt.Audience{arbitraryNode},
			Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		extra: map[string]interface{}{
			"scope": "admin.*",
		},
	}
	rawAccessToken, _, err := signJWTToken(&arbitraryClaims)
	assert.NoError(err)
	arbitraryIntrospectionResponse := IntrospectionResponse{}
	// caching so we don't need to stub the http client
	testObject.cache.AddExpiryAwareItem("introspection-"+rawAccessToken, arbitraryIntrospectionResponse)
	testObject.cache.AddExpiryAwareItem("jws-"+rawAccessToken, arbitraryClaims)

	helper, err := testObject.authorize(rawAccessToken)

	assert.NoError(err)
	assert.IsType(&claimsAdapter{}, helper)
}

// even when preferIntrospection flag is false,
// introspection response is used when JWT fails
func TestManager_authorize_whenJWTFails(t *testing.T) {
	assert := testifyassert.New(t)

	config := newTypicalTokenValidationConfiguration()
	config.JWTConfig.PreferIntrospection = false
	testObject, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	rawAccessToken := "raw access token"
	arbitraryIntrospectionResponse, arbitraryClaims := IntrospectionResponse{}, CustomClaims{}
	// caching so we don't need to stub the http client
	testObject.cache.AddExpiryAwareItem("introspection-"+rawAccessToken, arbitraryIntrospectionResponse)
	testObject.cache.AddExpiryAwareItem("jws-"+rawAccessToken, arbitraryClaims)

	helper, err := testObject.authorize(rawAccessToken)

	assert.NoError(err)
	assert.IsType(&IntrospectionResponse{}, helper)
}

// both introspection and jwt fails
func TestManager_authorize_whenError(t *testing.T) {
	assert := testifyassert.New(t)

	config := newTypicalTokenValidationConfiguration()
	config.JWTConfig.PreferIntrospection = true
	testObject, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	rawAccessToken := "raw access token"

	_, err = testObject.authorize(rawAccessToken)

	assert.Error(err)
}

func signJWTToken(cc *CustomClaims) (string, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, err
	}
	arbitraryKeyId := "arbitrary-key-id"
	var sig jose.Signer
	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key: &jose.JSONWebKey{
			KeyID: arbitraryKeyId,
			Key:   privKey,
		},
	}
	sig, err = jose.NewSigner(key, (&jose.SignerOptions{EmbedJWK: false}).WithType("JWT").WithContentType("JWT"))
	if err != nil {
		return "", nil, err
	}
	token, err := jwt.Signed(sig).
		Claims(cc.Claims).
		Claims(cc.extra).
		CompactSerialize()
	if err != nil {
		return "", nil, err
	}
	jws, err := json.Marshal(&jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &privKey.PublicKey,
				KeyID:     arbitraryKeyId,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
		},
	})
	if err != nil {
		return "", nil, err
	}
	return token, jws, nil
}

func newStubClient(f StubHttpResponse) *http.Client {
	return &http.Client{
		Transport: f,
	}
}

type StubHttpResponse func(req *http.Request) (*http.Response, error)

func (f StubHttpResponse) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTypicalTokenValidationConfiguration() *config.TokenValidationConfiguration {
	conf := &config.SecurityConfiguration{
		TokenValidationConfig: &config.TokenValidationConfiguration{
			Aud:     arbitraryNode,
			Issuers: []string{arbitraryIssuer},
			IntrospectionConfig: &config.IntrospectionConfiguration{
				Endpoint: "http://abitraryendpoint",
				AuthenticationConfig: &config.AuthenticationConfiguration{
					Method: config.AMClientSecretForm,
					Credentials: config.EnvironmentAwareCredentials{
						config.AMClientSecretFormClientId:     "foo",
						config.AMClientSecretFormClientSecret: "bar",
					},
				},
			},
			JWSConfig: &config.JWSConfiguration{
				Endpoint: "http://abitraryendpoint",
			},
			JWTConfig: &config.JWTConfiguration{
				PreferIntrospection: true,
			},
		},
	}
	conf.SetDefaults()
	return conf.TokenValidationConfig
}

func TestExtractToken_WhenTyical(t *testing.T) {
	assert := testifyassert.New(t)

	tokenType, tokenValue, err := extractToken("Bearer    x y z   ")

	assert.NoError(err)
	assert.Equal("Bearer", tokenType)
	assert.Equal("x y z", tokenValue)
}

func TestExtractToken_WhenInvalidTokeFormat(t *testing.T) {
	assert := testifyassert.New(t)

	_, _, err := extractToken("xyz")

	assert.Error(err)
}
