package oauth2

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/consensys/quorum-security-plugin-enterprise/internal/config"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/square/go-jose.v2/jwt"
)

type CustomClaims struct {
	*jwt.Claims
	// additional claims apart from standard claims
	extra map[string]interface{}
}

func (cc *CustomClaims) UnmarshalJSON(b []byte) error {
	var rawClaims map[string]interface{}
	if err := json.Unmarshal(b, &rawClaims); err != nil {
		return nil
	}
	var claims jwt.Claims
	var decoderResult mapstructure.Metadata
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &claims,
		Metadata:         &decoderResult,
		TagName:          "json",
		WeaklyTypedInput: true,
	})
	if err != nil {
		return err
	}
	if err := decoder.Decode(rawClaims); err != nil {
		return err
	}
	cc.Claims = &claims
	cc.extra = make(map[string]interface{})
	for _, k := range decoderResult.Unused {
		cc.extra[k] = rawClaims[k]
	}
	return nil
}

func (cc *CustomClaims) Verify(aud string, issuers []string) error {
	var issuerErr error
	for _, issuer := range issuers {
		if issuerErr = cc.Validate(jwt.Expected{
			Issuer:   issuer,
			Audience: jwt.Audience{aud},
			Time:     time.Now(),
		}); issuerErr == nil {
			break
		}
	}
	if issuerErr != nil {
		return issuerErr
	}
	return cc.VerifyExpiration()
}

func (cc *CustomClaims) VerifyExpiration() error {
	return cc.Validate(jwt.Expected{
		Time: time.Now(),
	})
}

type claimsAdapter struct {
	claims *CustomClaims
	config *config.JWTConfiguration
}

// include verify time-related fields
func (ce *claimsAdapter) Verify(aud string, issuers []string) error {
	return ce.claims.Verify(aud, issuers)
}

func (ce *claimsAdapter) VerifyExpiration() error {
	return ce.claims.VerifyExpiration()
}

func (ce *claimsAdapter) ExpiredAt() time.Time {
	return ce.claims.Expiry.Time()
}

func (ce *claimsAdapter) GrantedAuthorities() []*proto.GrantedAuthority {
	if rawAuthorityValue, ok := ce.claims.extra[ce.config.AuthorizationField]; ok {
		switch reflect.TypeOf(rawAuthorityValue).Kind() {
		case reflect.Slice:
			s := reflect.ValueOf(rawAuthorityValue)
			authorities := make([]*proto.GrantedAuthority, s.Len())
			for i := 0; i < s.Len(); i++ {
				authorities[i] = toAuthority(strings.TrimSpace(fmt.Sprintf("%v", s.Index(i).Interface())))
			}
			return authorities
		default:
			v := reflect.ValueOf(rawAuthorityValue)
			return toAuthorities(v.String())
		}
	}
	return nil
}
