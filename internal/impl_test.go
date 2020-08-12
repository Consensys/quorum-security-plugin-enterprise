package internal

import (
	"context"
	"testing"

	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto_common"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

// we dont' support call to the host process for this plugin
func TestSecurityPluginImpl_GRPCClient(t *testing.T) {
	testObject := &SecurityPluginImpl{}

	_, err := testObject.GRPCClient(context.Background(), nil, nil)

	assert.Error(t, err)
}

func TestSecurityPluginImpl_GRPCServer(t *testing.T) {
	testObject := &SecurityPluginImpl{}

	server := grpc.NewServer()
	err := testObject.GRPCServer(nil, server)

	assert.NoError(t, err)
	serviceInfo := server.GetServiceInfo()
	assert.Contains(t, serviceInfo, "proto_common.PluginInitializer")
	assert.Contains(t, serviceInfo, "proto.AuthenticationManager")
	assert.Contains(t, serviceInfo, "proto.TLSConfigurationSource")
}

func TestSecurityPluginImpl_Init(t *testing.T) {
	testObject := &SecurityPluginImpl{}

	_, err := testObject.Init(context.Background(), &proto_common.PluginInitialization_Request{
		HostIdentity: "node1",
		RawConfiguration: []byte(`
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
`),
	})

	assert.NoError(t, err)
	assert.NotNil(t, testObject.config, "config must be ready")
	assert.NotNil(t, testObject.tlsConfigSource, "tlsSource must be ready")
	assert.NotNil(t, testObject.authManager, "authManager must be ready")
	assert.Equal(t, "node1", testObject.config.TokenValidationConfig.Aud)
}

func TestSecurityPluginImpl_Get_whenNoTLSSource(t *testing.T) {
	testObject := &SecurityPluginImpl{
		tlsConfigSource: nil,
	}

	_, err := testObject.Get(context.Background(), nil)
	assert.Error(t, err)
}

func TestSecurityPluginImpl_Get_whenDelegate(t *testing.T) {
	arbitraryResponse := &proto.TLSConfiguration_Response{}
	testObject := &SecurityPluginImpl{
		tlsConfigSource: &stubTLSConfigurationSource{
			stubResponse: arbitraryResponse,
		},
	}

	response, err := testObject.Get(context.Background(), nil)

	assert.NoError(t, err)
	assert.Equal(t, arbitraryResponse, response)
}

func TestSecurityPluginImpl_Authenticate_whenDelegate(t *testing.T) {
	arbitraryResponse := &proto.PreAuthenticatedAuthenticationToken{}
	testObject := &SecurityPluginImpl{
		authManager: &stubAuthenticationManager{
			stubResonse: arbitraryResponse,
		},
	}

	response, err := testObject.Authenticate(context.Background(), nil)

	assert.NoError(t, err)
	assert.Equal(t, arbitraryResponse, response)
}

type stubTLSConfigurationSource struct {
	stubResponse *proto.TLSConfiguration_Response
}

func (sts *stubTLSConfigurationSource) Get(context.Context, *proto.TLSConfiguration_Request) (*proto.TLSConfiguration_Response, error) {
	return sts.stubResponse, nil
}

type stubAuthenticationManager struct {
	stubResonse *proto.PreAuthenticatedAuthenticationToken
}

func (sam *stubAuthenticationManager) Authenticate(context.Context, *proto.AuthenticationToken) (*proto.PreAuthenticatedAuthenticationToken, error) {
	return sam.stubResonse, nil
}
