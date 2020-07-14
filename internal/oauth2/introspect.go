package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jpmorganchase/quorum-security-plugin-enterprise/internal/config"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"gopkg.in/square/go-jose.v2/jwt"
)

// implements https://tools.ietf.org/html/rfc7662 with limitted support for authentication
type IntrospectionResponse struct {
	Active     bool             `json:"active"`
	Scope      string           `json:"scope,omitempty"`
	ClientID   string           `json:"client_id,omitempty"`
	Username   string           `json:"username,omitempty"`
	TokenType  string           `json:"token_type,omitempty"`
	Expiration *jwt.NumericDate `json:"exp,omitempty"`
	IssuedAt   *jwt.NumericDate `json:"iat,omitempty"`
	NotBefore  *jwt.NumericDate `json:"nbf,omitempty"`
	Subject    string           `json:"sub,omitempty"`
	Audience   jwt.Audience     `json:"aud,omitempty"`
	Issuer     string           `json:"iss,omitempty"`
	JwtID      string           `json:"jti,omitempty"`
}

// include verify time-related fields
func (ir *IntrospectionResponse) Verify(aud string, issuers []string) error {
	if !ir.Active {
		return fmt.Errorf("token is not active")
	}
	// borrow jwt.Claims to perform explicit validation
	c := jwt.Claims{
		Issuer:   ir.Issuer,
		Audience: ir.Audience,
	}
	var issuerErr error
	for _, issuer := range issuers {
		if issuerErr = c.Validate(jwt.Expected{
			Issuer:   issuer,
			Audience: jwt.Audience{aud},
		}); issuerErr == nil {
			break
		}
	}
	if issuerErr != nil {
		return issuerErr
	}
	return ir.VerifyExpiration()
}

func (ir *IntrospectionResponse) VerifyExpiration() error {
	// borrow jwt.Claims to perform explicit validation
	return jwt.Claims{
		IssuedAt:  ir.IssuedAt,
		Expiry:    ir.Expiration,
		NotBefore: ir.NotBefore,
	}.Validate(jwt.Expected{
		Time: time.Now(),
	})
}

func (ir *IntrospectionResponse) ExpiredAt() time.Time {
	return ir.Expiration.Time()
}

func (ir *IntrospectionResponse) GrantedAuthorities() []*proto.GrantedAuthority {
	return toAuthorities(ir.Scope)
}

func buildIntrospectionRequest(token string, conf *config.IntrospectionConfiguration) (*http.Request, error) {
	form := &url.Values{}
	form.Set("token", token)
	form.Set("token_hint", "access_token")
	authConfig := conf.AuthenticationConfig
	if authConfig != nil && authConfig.Method == config.AMClientSecretForm {
		form.Set("client_id", authConfig.Credentials[config.AMClientSecretFormClientId].String())
		form.Set("client_secret", authConfig.Credentials[config.AMClientSecretFormClientSecret].String())
	}
	body := form.Encode()
	req, err := http.NewRequest("POST", conf.Endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authConfig != nil && authConfig.Method == config.AMClientSecretBasic {
		req.SetBasicAuth(authConfig.Credentials[config.AMClientSecretBasicClientId].String(), authConfig.Credentials[config.AMClientSecretBasicClientSecret].String())
	}
	return req, err
}
