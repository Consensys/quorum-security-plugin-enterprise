package oauth2

import (
	"net/url"
	"strings"
	"time"

	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
)

// interface to extract information for gRPC response
type preauthenticatedAuthenticationTokenHelper interface {
	Verify(aud string, issuers []string) error
	VerifyExpiration() error

	ExpiredAt() time.Time
	GrantedAuthorities() []*proto.GrantedAuthority
}

// raw string with format: rpc://<service>[._]<method> or private,public://xxx
func toAuthority(raw string) *proto.GrantedAuthority {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	switch s := u.Scheme; strings.ToLower(s) {
	case "rpc":
		extract := u.Host
		var s, m string
		defaultWildCard := func(v string) string {
			if v == "" {
				return "*"
			}
			return v
		}
		parts := strings.FieldsFunc(extract, func(r rune) bool {
			return r == '.' || r == '_'
		})
		if len(parts) == 0 {
			s, m = "*", "*"
		} else if len(parts) == 1 {
			if strings.HasPrefix(extract, parts[0]) {
				s, m = defaultWildCard(strings.TrimSpace(parts[0])), "*"
			} else {
				s, m = "*", defaultWildCard(strings.TrimSpace(parts[0]))
			}
		} else {
			s, m = defaultWildCard(strings.TrimSpace(parts[0])), defaultWildCard(strings.TrimSpace(parts[1]))
		}
		return &proto.GrantedAuthority{
			Service: s,
			Method:  m,
			Raw:     raw,
		}
	default:
		return &proto.GrantedAuthority{
			Raw: raw,
		}
	}
}

// space-separated raw authority string
func toAuthorities(raw string) []*proto.GrantedAuthority {
	rawAuthorities := strings.Fields(raw)
	authorities := make([]*proto.GrantedAuthority, 0)
	for _, rawAuthority := range rawAuthorities {
		raw := toAuthority(strings.TrimSpace(rawAuthority))
		if raw != nil {
			authorities = append(authorities, raw)
		}
	}
	return authorities
}
