package oauth2

import (
	"testing"

	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	testifyassert "github.com/stretchr/testify/assert"
)

func TestToAuthority_rpc_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	raw := "rpc://admin_nodeInfo"
	a := toAuthority(raw)

	assert.Equal("admin", a.GetService())
	assert.Equal("nodeInfo", a.GetMethod())
	assert.Equal(raw, a.GetRaw())
}

func TestToAuthority_rpc_whenMethodWildCard(t *testing.T) {
	assert := testifyassert.New(t)

	a := toAuthority("rpc://admin")

	assert.Equal("admin", a.GetService())
	assert.Equal("*", a.GetMethod())
}

func TestToAuthority_rpc_whenMethodWildCardEmpty(t *testing.T) {
	assert := testifyassert.New(t)

	a := toAuthority("rpc://admin_")

	assert.Equal("admin", a.GetService())
	assert.Equal("*", a.GetMethod())
}

func TestToAuthority_rpc_whenServiceWildCardEmpty(t *testing.T) {
	assert := testifyassert.New(t)

	a := toAuthority("rpc://.nodeInfo")

	assert.Equal("*", a.GetService())
	assert.Equal("nodeInfo", a.GetMethod())
}

func TestToAuthority_rpc_whenWildCardBoth(t *testing.T) {
	assert := testifyassert.New(t)

	a := toAuthority("rpc://")

	assert.Equal("*", a.GetService())
	assert.Equal("*", a.GetMethod())
}

func TestToAuthority_rpc_whenWildCardBoth_withSingleSeparator(t *testing.T) {
	assert := testifyassert.New(t)

	a := toAuthority("rpc://.")

	assert.Equal("*", a.GetService())
	assert.Equal("*", a.GetMethod())
}

func TestToAuthorities_whenTypical(t *testing.T) {
	assert := testifyassert.New(t)

	l := toAuthorities("rpc://admin_*   rpc://debug.*   rpc://eth_blockNumber rpc://. private://arbitrary")

	assert.Len(l, 5)
	assert.Contains(l, &proto.GrantedAuthority{Service: "admin", Method: "*", Raw: "rpc://admin_*"})
	assert.Contains(l, &proto.GrantedAuthority{Service: "debug", Method: "*", Raw: "rpc://debug.*"})
	assert.Contains(l, &proto.GrantedAuthority{Service: "eth", Method: "blockNumber", Raw: "rpc://eth_blockNumber"})
	assert.Contains(l, &proto.GrantedAuthority{Service: "*", Method: "*", Raw: "rpc://."})
	assert.Contains(l, &proto.GrantedAuthority{Raw: "private://arbitrary"})
}
