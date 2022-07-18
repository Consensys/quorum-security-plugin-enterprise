package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/consensys/quorum-security-plugin-enterprise/internal/config"
	"github.com/consensys/quorum-security-plugin-enterprise/internal/tls"
	"github.com/golang/protobuf/ptypes"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Manager struct {
	config *config.TokenValidationConfiguration

	cache               *expirationAwareLRUCache // for caching token and introspection response
	introspectionClient *http.Client             // for introspection API call
	jwsClient           *http.Client             // for JKS API call
}

func NewManager(conf *config.TokenValidationConfiguration) (*Manager, error) {
	if conf == nil {
		return nil, nil
	}
	m := &Manager{
		config: conf,
	}
	var err error
	if introspectionConfig := conf.IntrospectionConfig; introspectionConfig != nil {
		if m.introspectionClient, err = tls.NewHttpClient(
			introspectionConfig.Endpoint,
			introspectionConfig.TLSConnectionConfig,
			introspectionConfig.AuthenticationConfig); err != nil {
			return nil, err
		}
	}
	if jwsConfig := conf.JWSConfig; jwsConfig != nil {
		if m.jwsClient, err = tls.NewHttpClient(
			jwsConfig.Endpoint,
			jwsConfig.TLSConnectionConfig,
			nil); err != nil {
			return nil, err
		}
	}
	m.cache, err = newExpirationAwareLRUCache(conf.CacheConfig)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Authenticate(ctx context.Context, req *proto.AuthenticationToken) (*proto.PreAuthenticatedAuthenticationToken, error) {
	fullTokenText := string(req.RawToken)
	tokenType, tokenValue, err := extractToken(fullTokenText)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// validate token type
	if strings.ToLower(tokenType) != "bearer" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid token type [%s], expected BEARER token", tokenType)
	}
	// as this is preauthenticated token we just need to authorize it
	helper, err := m.authorize(tokenValue)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}
	expiredAt, err := ptypes.TimestampProto(helper.ExpiredAt())
	if err != nil {
		return nil, status.Error(codes.Unknown, "invalid timestamp in token")
	}
	if err := helper.Verify(m.config.Aud, m.config.Issuers); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if err := helper.VerifyExpiration(); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return &proto.PreAuthenticatedAuthenticationToken{
		RawToken:    req.RawToken,
		ExpiredAt:   expiredAt,
		Authorities: helper.GrantedAuthorities(),
	}, nil
}

func (m *Manager) authorize(rawAccessToken string) (preauthenticatedAuthenticationTokenHelper, error) {
	verifiedIntrospection, introspectErr := m.introspect(rawAccessToken)
	if introspectErr == nil && m.config.JWTConfig.PreferIntrospection {
		return verifiedIntrospection, nil
	}
	verifiedClaims, claimErr := m.claim(rawAccessToken)
	if introspectErr == nil {
		if claimErr != nil {
			return verifiedIntrospection, nil
		} else {
			// select claims over introspection
			return &claimsAdapter{verifiedClaims, m.config.JWTConfig}, nil
		}
	} else {
		// fall back to claims
		if claimErr == nil {
			return &claimsAdapter{verifiedClaims, m.config.JWTConfig}, nil
		}
	}
	// both fail
	return nil, fmt.Errorf("%s, %s", introspectErr.Error(), claimErr.Error())
}

// validate token using Introspection
func (m *Manager) introspect(rawAccessToken string) (*IntrospectionResponse, error) {
	if m.introspectionClient == nil {
		return nil, fmt.Errorf("introspection client not configured")
	}
	var verifiedIntrospection *IntrospectionResponse
	cacheKey := "introspection-" + rawAccessToken
	if cachedItem, hasCachedItem := m.cache.GetExpiryAwareItem(cacheKey); hasCachedItem {
		if cachedIntrospection, ok := cachedItem.(IntrospectionResponse); ok && cachedIntrospection.VerifyExpiration() == nil {
			verifiedIntrospection = &cachedIntrospection
		}
	}
	if verifiedIntrospection == nil {
		// verify claims with introspection server
		req, err := buildIntrospectionRequest(rawAccessToken, m.config.IntrospectionConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to prepare introspection request due to %s", err)
		}
		resp, err := m.introspectionClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to execute introspection API due to %s", err)
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		var introspection IntrospectionResponse
		if err := json.NewDecoder(resp.Body).Decode(&introspection); err != nil {
			return nil, fmt.Errorf("failed to decode introspection response due to %s", err)
		}
		m.cache.AddExpiryAwareItem(cacheKey, introspection)
		verifiedIntrospection = &introspection
	}
	return verifiedIntrospection, nil
}

// validate JWT token using JWS
func (m *Manager) claim(rawAccessToken string) (*CustomClaims, error) {
	jwtToken, err := jwt.ParseSigned(rawAccessToken)
	if err != nil {
		return nil, err
	}
	if m.jwsClient == nil {
		return nil, fmt.Errorf("JWS client not configured")
	}
	var verifiedClaims *CustomClaims
	cacheKey := "jws-" + rawAccessToken
	if cachedItem, hasCachedItem := m.cache.GetExpiryAwareItem(cacheKey); hasCachedItem {
		if cachedClaims, ok := cachedItem.(CustomClaims); ok && cachedClaims.VerifyExpiration() == nil {
			verifiedClaims = &cachedClaims
		}
	}
	if verifiedClaims == nil {
		// verify claims signature
		resp, err := m.jwsClient.Get(m.config.JWSConfig.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve JSON Web Keysets due to %s", err)
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		var jwks jose.JSONWebKeySet
		if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
			return nil, fmt.Errorf("failed to decode JSON Web Keysets response due to %s", err)
		}
		var claims CustomClaims
		if err := jwtToken.Claims(&jwks, &claims); err != nil {
			return nil, fmt.Errorf("failed to verify token signature due to %s", err)
		}
		m.cache.AddExpiryAwareItem(cacheKey, claims)
		verifiedClaims = &claims
	}
	return verifiedClaims, nil
}

func extractToken(raw string) (string, string, error) {
	firstSpaceIdx := strings.IndexFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r)
	})
	if firstSpaceIdx == -1 {
		return "", "", fmt.Errorf("invalid token format")
	}
	return strings.TrimSpace(raw[:firstSpaceIdx]), strings.TrimSpace(raw[firstSpaceIdx:]), nil
}
