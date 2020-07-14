package oauth2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jpmorganchase/quorum-security-plugin-enterprise/internal/config"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	testifyassert "github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestCustomClaims_UnmarshalJSON(t *testing.T) {
	assert := testifyassert.New(t)

	var c CustomClaims
	err := json.Unmarshal([]byte(jwtToken), &c)

	assert.NoError(err, "parsing json")

	assert.Equal("http://goquorum.com/oauth", c.Issuer)
	assert.Equal("quorum", c.Subject)
	assert.Equal(jwt.Audience{"node1"}, c.Audience)
	assert.Equal(jwt.NumericDate(123456789), *c.Expiry)
	assert.Equal(jwt.NumericDate(123456789), *c.NotBefore)
	assert.Equal(jwt.NumericDate(123456789), *c.IssuedAt)
	assert.Equal("tokenid", c.ID)

	assert.Equal("admin.* eth.*", c.extra["scope"])
	assert.Equal([]interface{}{"admin.*", "eth.*"}, c.extra["roles"])

	orgMap, ok := c.extra["org"].(map[string]interface{})
	assert.True(ok, "unmarshal struct")
	assert.Equal("org_name", orgMap["name"])
	assert.Equal("org_value", orgMap["value"])
}

func TestCustomClaims_UnmarshalJSON_whenAudIsSingle(t *testing.T) {
	assert := testifyassert.New(t)

	var c CustomClaims
	err := json.Unmarshal([]byte(jwtTokenWeak), &c)

	assert.NoError(err, "parsing json")

	assert.Equal(jwt.Audience{"node1"}, c.Audience)
}

func TestCustomClaims_Verify_whenInvalidAud(t *testing.T) {
	assert := testifyassert.New(t)
	expectedAud := "arbitraryAud"
	expectedIssuer := "arbitraryIssuer"

	testObject := &CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   "invalidIssuer",
			Audience: jwt.Audience{expectedAud},
			Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	assert.Error(testObject.Verify(expectedAud, []string{expectedIssuer}))
}

func TestCustomClaims_Verify_whenInvalidIssuer(t *testing.T) {
	assert := testifyassert.New(t)
	expectedAud := "arbitraryAud"
	expectedIssuer := "arbitraryIssuer"

	testObject := &CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   expectedIssuer,
			Audience: jwt.Audience{"invalidAud"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	assert.Error(testObject.Verify(expectedAud, []string{expectedIssuer}))
}

func TestClaimsAdapter_Verify(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &claimsAdapter{claims: &CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   "iss1",
			Audience: jwt.Audience{"aud1", "aud2"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}}

	assert.NoError(testObject.Verify("aud2", []string{"iss2", "iss1"}))
}

func TestClaimsAdapter_Verify_whenExpired(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &claimsAdapter{claims: &CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   "iss1",
			Audience: jwt.Audience{"aud1", "aud2"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}}

	assert.EqualError(testObject.VerifyExpiration(), jwt.ErrExpired.Error())
}

func TestClaimsAdapter_GrantedAuthorities_whenClaimIsAString(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &claimsAdapter{
		claims: &CustomClaims{
			extra: map[string]interface{}{
				"scp": "rpc://admin_* rpc://eth.blockNumber  ",
			},
		},
		config: &config.JWTConfiguration{
			AuthorizationField: "scp",
		},
	}

	grantedAuthorities := testObject.GrantedAuthorities()

	assert.Equal(2, len(grantedAuthorities))
	assert.Contains(grantedAuthorities, &proto.GrantedAuthority{
		Service: "admin",
		Method:  "*",
		Raw:     "rpc://admin_*",
	})
	assert.Contains(grantedAuthorities, &proto.GrantedAuthority{
		Service: "eth",
		Method:  "blockNumber",
		Raw:     "rpc://eth.blockNumber",
	})
}

func TestClaimsAdapter_GrantedAuthorities_whenClaimIsAnArray(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &claimsAdapter{
		claims: &CustomClaims{
			extra: map[string]interface{}{
				"scp": []string{
					" rpc://admin_*",
					"rpc://eth.blockNumber  ",
				},
			},
		},
		config: &config.JWTConfiguration{
			AuthorizationField: "scp",
		},
	}

	grantedAuthorities := testObject.GrantedAuthorities()

	assert.Equal(2, len(grantedAuthorities))
	assert.Contains(grantedAuthorities, &proto.GrantedAuthority{
		Service: "admin",
		Method:  "*",
		Raw:     "rpc://admin_*",
	})
	assert.Contains(grantedAuthorities, &proto.GrantedAuthority{
		Service: "eth",
		Method:  "blockNumber",
		Raw:     "rpc://eth.blockNumber",
	})
}

func TestClaimsAdapter_GrantedAuthorities_whenClaimIsNotConfigured(t *testing.T) {
	assert := testifyassert.New(t)

	testObject := &claimsAdapter{
		claims: &CustomClaims{
			extra: map[string]interface{}{
				"scp": "admin_*",
			},
		},
		config: &config.JWTConfiguration{},
	}

	grantedAuthorities := testObject.GrantedAuthorities()

	assert.Equal(0, len(grantedAuthorities))
}

// scope, roles and org are customized fields
const jwtToken = `
{
	"iss": "http://goquorum.com/oauth",
	"sub": "quorum",
	"aud": ["node1"],
	"exp": 123456789,
	"nbf": 123456789,
	"iat": 123456789,
	"jti": "tokenid",

 	"scope": "admin.* eth.*",
	"roles": ["admin.*", "eth.*"],
	"org": {
		"name" : "org_name",
		"value" : "org_value"
	}
}
`

// aud is a single value instead of an array
const jwtTokenWeak = `
{
	"iss": "http://goquorum.com/oauth",
	"sub": "quorum",
	"aud": "node1",
	"exp": 123456789,
	"nbf": 123456789,
	"iat": 123456789,
	"jti": "tokenid"
}
`
