package config

import (
	"crypto/tls"
	"encoding/json"
	"os"
	"testing"

	testifyassert "github.com/stretchr/testify/assert"
)

func TestConfiguration_WhenParsing(t *testing.T) {
	assert := testifyassert.New(t)

	var c SecurityConfiguration
	err := json.Unmarshal([]byte(arbitraryConfiguration), &c)

	if !assert.NoError(err, "parsing configuration from json") {
		return
	}

	assert.Equal(false, c.TLSConfig.AutoGenerate, "tls.auto")
	assert.Equal("cert.pem", c.TLSConfig.CertFile.String(), "tls.certFile")
	assert.Equal("key.pem", c.TLSConfig.KeyFile.String(), "tls.keyFile")
	assert.Equal(CipherSuiteList{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}, c.TLSConfig.AdvancedConfig.CipherSuites, "tls.advanced")

	assert.Equal("", c.TokenValidationConfig.Aud, "tokenValidation.aud")
	assert.Contains(c.TokenValidationConfig.Issuers, "http://goquorum.com/oauth", "tokenValidation.issuer")
	assert.Equal("https://localhost:5000/oauth/introspect", c.TokenValidationConfig.IntrospectionConfig.Endpoint, "tokenValidation.introspect.endpoint")
	assert.Equal(AuthenticationMethod("client_secret_basic"), c.TokenValidationConfig.IntrospectionConfig.AuthenticationConfig.Method, "tokenValidation.introspect.authentication.method")
	assert.Equal("quorum", c.TokenValidationConfig.IntrospectionConfig.AuthenticationConfig.Credentials[AMClientSecretBasicClientId].String(), "tokenValidation.introspect.authentication.credentials.clientId")
	assert.Equal("admin", c.TokenValidationConfig.IntrospectionConfig.AuthenticationConfig.Credentials[AMClientSecretBasicClientSecret].String(), "tokenValidation.introspect.authentication.credentials.clientSecret")
	assert.Equal(80, c.TokenValidationConfig.CacheConfig.Limit, "tokenValidation.cache.limit")
	assert.Equal(false, c.TokenValidationConfig.IntrospectionConfig.TLSConnectionConfig.InsecureSkipVerify, "tokenValidation.introspect.tlsConnection.insecureSkipVerify")
	assert.Equal("server.crt", c.TokenValidationConfig.IntrospectionConfig.TLSConnectionConfig.CertFile.String(), "tokenValidation.introspect.tlsConnection.certFile")
	assert.Equal("server.ca.crt", c.TokenValidationConfig.IntrospectionConfig.TLSConnectionConfig.CaFile.String(), "tokenValidation.introspect.tlsConnection.caFile")
	assert.Equal("https://localhost:5000/keys", c.TokenValidationConfig.JWSConfig.Endpoint, "tokenValidation.jws.endpoint")
	assert.Equal(false, c.TokenValidationConfig.JWSConfig.TLSConnectionConfig.InsecureSkipVerify, "tokenValidation.jws.tlsConnection.insecureSkipVerify")
	assert.Equal("server.crt", c.TokenValidationConfig.JWSConfig.TLSConnectionConfig.CertFile.String(), "tokenValidation.jws.tlsConnection.certFile")
	assert.Equal("server.ca.crt", c.TokenValidationConfig.JWSConfig.TLSConnectionConfig.CaFile.String(), "tokenValidation.jws.tlsConnection.caFile")
	assert.Equal("scope", c.TokenValidationConfig.JWTConfig.AuthorizationField, "tokenValidation.jwt.authorizationField")
	assert.True(c.TokenValidationConfig.JWTConfig.PreferIntrospection, "tokenValidation.jwt.preferIntrospection")
}

func TestConfiguration_Validate_whenInvalid(t *testing.T) {
	assert := testifyassert.New(t)

	var c SecurityConfiguration
	err := json.Unmarshal([]byte(arbitraryConfiguration), &c)

	assert.NoError(err, "parsing configuration from json")

	err = c.validate()

	assert.Error(err, "validating configuration")
}

func TestConfiguration_Validate_whenValid(t *testing.T) {
	assert := testifyassert.New(t)

	var c SecurityConfiguration
	err := json.Unmarshal([]byte(arbitraryConfiguration), &c)

	assert.NoError(err, "parsing configuration from json")

	c.TLSConfig.AutoGenerate = true
	c.TokenValidationConfig.IntrospectionConfig.TLSConnectionConfig.InsecureSkipVerify = true
	c.TokenValidationConfig.JWSConfig.TLSConnectionConfig.InsecureSkipVerify = true

	err = c.validate()

	assert.NoError(err, "validating configuration")
}

func TestConfiguration_Validate_whenNoConfigurationFound(t *testing.T) {
	assert := testifyassert.New(t)

	var c SecurityConfiguration

	assert.Error(c.validate())
}

func TestTokenValidationConfiguration_SetDefaults(t *testing.T) {
	assert := testifyassert.New(t)

	var c TokenValidationConfiguration
	c.setDefaults()

	assert.Contains(c.Issuers, defaultIssuer)
	assert.Equal(defaultAuthorizationField, c.JWTConfig.AuthorizationField)
	assert.Equal(defaultCacheLimit, c.CacheConfig.Limit)
}

func TestTLSConfiguration_SetDefaults(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &TLSConfiguration{}
	testObject.setDefaults()

	assert.Equal("cert.pem", testObject.CertFile.String())
	assert.Equal("key.pem", testObject.KeyFile.String())
	assert.Equal(defaultCipherSuites, testObject.AdvancedConfig.CipherSuites)
	assert.False(testObject.AutoGenerate)
}

func TestAuthenticationConfiguration_Validate_whenUsingForm(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &AuthenticationConfiguration{
		Method: AMClientSecretForm,
		Credentials: EnvironmentAwareCredentials{
			AMClientSecretFormClientId:     "foo",
			AMClientSecretFormClientSecret: "bar",
		},
	}

	assert.NoError(testObject.validate())
}

func TestAuthenticationConfiguration_Validate_whenUsingFormButMisingCredentials(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &AuthenticationConfiguration{
		Method: AMClientSecretForm,
		Credentials: EnvironmentAwareCredentials{
			AMClientSecretFormClientId: "foo",
		},
	}

	assert.Error(testObject.validate())
}

func TestAuthenticationConfiguration_Validate_whenUsingBasic(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &AuthenticationConfiguration{
		Method: AMClientSecretBasic,
		Credentials: EnvironmentAwareCredentials{
			AMClientSecretBasicClientId:     "foo",
			AMClientSecretBasicClientSecret: "bar",
		},
	}

	assert.NoError(testObject.validate())
}

func TestAuthenticationConfiguration_Validate_whenUsingBasicButMisingCredentials(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &AuthenticationConfiguration{
		Method:      AMClientSecretBasic,
		Credentials: EnvironmentAwareCredentials{},
	}

	assert.Error(testObject.validate())
}

func TestAuthenticationConfiguration_Validate_whenUsingPrivateKey(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &AuthenticationConfiguration{
		Method: AMPrivateKey,
		Credentials: EnvironmentAwareCredentials{
			AMPrivateKeyCertFile: "foo",
			AMPrivateKeyKeyFile:  "bar",
		},
	}

	assert.NoError(testObject.validate())
}

func TestAuthenticationConfiguration_Validate_whenUsingPrivateKeyButMisingCredentials(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &AuthenticationConfiguration{
		Method: AMPrivateKey,
		Credentials: EnvironmentAwareCredentials{
			AMPrivateKeyKeyFile: "bar",
		},
	}

	assert.Error(testObject.validate())
}

func TestDefaultCipherSuites_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	a, err := defaultCipherSuites.ToUint16Array()

	assert.NoError(err)

	assert.Equal([]uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}, a)
}

func TestCipherSuiteList_whenNotSupported(t *testing.T) {
	assert := testifyassert.New(t)

	_, err := CipherSuiteList{"xxx"}.ToUint16Array()

	assert.Errorf(err, "not supported cipher suite xxx")
}

func TestEnvironmentAwareValue_UnmarshalJSON_whenValueFromEnvVariable(t *testing.T) {
	assert := testifyassert.New(t)

	if err := os.Setenv("KEY1", "foo"); err != nil {
		t.Fatal(err)
	}

	var value struct {
		Vinstance EnvironmentAwareValue
		Vpointer  *EnvironmentAwareValue
	}
	assert.NoError(json.Unmarshal([]byte(`{"Vinstance": "env://KEY1", "Vpointer": "env://KEY1"}`), &value))
	assert.Equal("foo", value.Vinstance.String())
	assert.Equal("foo", value.Vpointer.String())
}

func TestEnvironmentAwareValue_UnmarshalJSON_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	var value struct {
		Vinstance EnvironmentAwareValue
		Vpointer  *EnvironmentAwareValue
	}
	assert.NoError(json.Unmarshal([]byte(`{"Vinstance": "foo", "Vpointer": "bar"}`), &value))
	assert.Equal("foo", value.Vinstance.String())
	assert.Equal("bar", value.Vpointer.String())
}

func TestNewSecurityConfiguration_whenInvalid(t *testing.T) {
	assert := testifyassert.New(t)

	_, err := NewSecurityConfiguration([]byte(arbitraryConfiguration))

	assert.Error(err)
}

func TestNewSecurityConfiguration_whenValid(t *testing.T) {
	assert := testifyassert.New(t)

	_, err := NewSecurityConfiguration([]byte(minimumValidConfiguration))

	assert.NoError(err)
}

const minimumValidConfiguration = `
{
  "tls": {
    "auto": true
  },
  "tokenValidation": {
    "jws": {
      "endpoint": "https://localhost:5000/keys",
      "tlsConnection": {
        "insecureSkipVerify": true
      }
    }
  }
}
`

const arbitraryConfiguration = `
{
  "tls": {
    "auto": false,
    "certFile": "cert.pem",
    "keyFile": "key.pem",
    "advanced": {
      "cipherSuites": [
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      ]
    }
  },
  "tokenValidation": {
    "issuers": ["http://goquorum.com/oauth"],
    "cache": {
      "limit": 80,
      "expirationInSeconds": 3600
    },
    "introspect": {
      "endpoint": "https://localhost:5000/oauth/introspect",
      "authentication": {
        "method": "client_secret_basic",
        "credentials": {
          "clientId": "quorum",
          "clientSecret": "admin"
        }
      },
      "tlsConnection": {
        "insecureSkipVerify": false,
        "certFile": "server.crt",
        "caFile": "server.ca.crt"
      }
    },
    "jws": {
      "endpoint": "https://localhost:5000/keys",
      "tlsConnection": {
        "insecureSkipVerify": false,
        "certFile": "server.crt",
        "caFile": "server.ca.crt"
      }
    },
    "jwt": {
      "authorizationField": "scope",
	  "preferIntrospection": true
    }
  }
}
`
