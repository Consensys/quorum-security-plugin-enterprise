package internal

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/consensys/quorum-security-plugin-enterprise/internal/config"
	"github.com/consensys/quorum-security-plugin-enterprise/internal/oauth2"
	"github.com/consensys/quorum-security-plugin-enterprise/internal/tls"
	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto_common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const DefaultProtocolVersion = 1

var (
	// this must be identical to handshake config in Quorum Client
	DefaultHandshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  DefaultProtocolVersion,
		MagicCookieKey:   "QUORUM_PLUGIN_MAGIC_COOKIE",
		MagicCookieValue: "CB9F51969613126D93468868990F77A8470EB9177503C5A38D437FEFF7786E0941152E05C06A9A3313391059132A7F9CED86C0783FE63A8B38F01623C8257664",
	}
)

// implements all security interfaces and
// delegating calls to actual implementation
type SecurityPluginImpl struct {
	plugin.Plugin
	config          *config.SecurityConfiguration
	tlsConfigSource proto.TLSConfigurationSourceServer
	authManager     proto.AuthenticationManagerServer
}

// delegate call
func (p *SecurityPluginImpl) Authenticate(ctx context.Context, req *proto.AuthenticationToken) (*proto.PreAuthenticatedAuthenticationToken, error) {
	startTime := time.Now()
	defer func() {
		log.Println("[DEBUG] authentication took", time.Now().Sub(startTime).Round(time.Microsecond))
	}()
	if p.authManager == nil || reflect.ValueOf(p.authManager).IsNil() {
		// returning error code Unimplemented is the contract with Quorum
		// so it knows this plugin is not configured to support authentication manager
		return nil, status.Error(codes.Unimplemented, "no configuration")
	}
	return p.authManager.Authenticate(ctx, req)
}

// delegate call
func (p *SecurityPluginImpl) Get(ctx context.Context, req *proto.TLSConfiguration_Request) (*proto.TLSConfiguration_Response, error) {
	if p.tlsConfigSource == nil || reflect.ValueOf(p.tlsConfigSource).IsNil() {
		// returning error code Unimplemented is the contract with Quorum
		// so it knows this plugin is not configured to support TLS configuration source
		return nil, status.Error(codes.Unimplemented, "no configuration")
	}
	return p.tlsConfigSource.Get(ctx, req)
}

func (p *SecurityPluginImpl) Init(ctx context.Context, req *proto_common.PluginInitialization_Request) (*proto_common.PluginInitialization_Response, error) {
	startTime := time.Now()
	defer func() {
		log.Println("[INFO] plugin initialization took", time.Now().Sub(startTime).Round(time.Microsecond))
	}()
	conf, err := config.NewSecurityConfiguration(req.GetRawConfiguration())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	p.config = conf
	p.tlsConfigSource, err = tls.NewTLSConfigurationSource(conf.TLSConfig)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if conf.TokenValidationConfig != nil {
		if req.HostIdentity == "" {
			return nil, status.Error(codes.InvalidArgument, "missing geth node name")
		}
		conf.TokenValidationConfig.Aud = req.HostIdentity
	}
	p.authManager, err = oauth2.NewManager(conf.TokenValidationConfig)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &proto_common.PluginInitialization_Response{}, nil
}

func (p *SecurityPluginImpl) GRPCServer(b *plugin.GRPCBroker, s *grpc.Server) error {
	proto_common.RegisterPluginInitializerServer(s, p)
	proto.RegisterTLSConfigurationSourceServer(s, p)
	proto.RegisterAuthenticationManagerServer(s, p)
	return nil
}

func (*SecurityPluginImpl) GRPCClient(context.Context, *plugin.GRPCBroker, *grpc.ClientConn) (interface{}, error) {
	return nil, fmt.Errorf("not supported")
}
