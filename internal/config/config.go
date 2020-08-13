package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type AuthenticationMethod string

const (
	defaultIssuer              = "http://goquorum.com/oauth"
	defaultAuthorizationField  = "scope"
	defaultCacheLimit          = 80
	defaultExpirationInSeconds = 3600

	AMClientSecretBasic             = "client_secret_basic"
	AMClientSecretBasicClientId     = "clientId"
	AMClientSecretBasicClientSecret = "clientSecret"

	AMClientSecretForm             = "client_secret_form"
	AMClientSecretFormClientId     = "clientId"
	AMClientSecretFormClientSecret = "clientSecret"

	AMPrivateKey         = "private_key"
	AMPrivateKeyCertFile = "certFile"
	AMPrivateKeyKeyFile  = "keyFile"
)

type CipherSuite string
type CipherSuiteList []CipherSuite

var (
	// copy from crypto/tls/cipher_suites.go per go 1.11.6
	supportedCipherSuites = map[CipherSuite]uint16{
		"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}

	defaultCipherSuites = CipherSuiteList{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	}
)

func NewSecurityConfiguration(rawJSON []byte) (*SecurityConfiguration, error) {
	var conf SecurityConfiguration
	if err := json.Unmarshal(rawJSON, &conf); err != nil {
		return nil, fmt.Errorf("can't parse configuration: %s", rawJSON)
	}
	if err := conf.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %s", err)
	}
	conf.SetDefaults()
	return &conf, nil
}

// main configuration to protect JSON RPC server
type SecurityConfiguration struct {
	TLSConfig             *TLSConfiguration             `json:"tls"`
	TokenValidationConfig *TokenValidationConfiguration `json:"tokenValidation"`
}

func (c *SecurityConfiguration) validate() error {
	if c.TokenValidationConfig == nil && c.TLSConfig == nil {
		return fmt.Errorf("invalid configuration. 'tls' block and/or 'tokenValidation' block must be configured")
	}
	if c.TLSConfig != nil {
		if err := c.TLSConfig.validate(); err != nil {
			return err
		}
	}
	if c.TokenValidationConfig != nil {
		if err := c.TokenValidationConfig.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c *SecurityConfiguration) SetDefaults() {
	if c.TLSConfig != nil {
		c.TLSConfig.setDefaults()
	}
	if c.TokenValidationConfig != nil {
		c.TokenValidationConfig.setDefaults()
	}
}

func (cs CipherSuite) toUint16() (uint16, error) {
	v, ok := supportedCipherSuites[cs]
	if ok {
		return v, nil
	}
	return 0, fmt.Errorf("not supported cipher suite %s", cs)
}

func (cs CipherSuite) toUint32() (uint32, error) {
	v, err := cs.toUint16()
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

type TLSConfiguration struct {
	AutoGenerate bool `json:"auto"`
	// path to cert file, if auto generate, it's the output file
	CertFile EnvironmentAwareValue `json:"certFile"`
	// path to key file, if auto generate, it's the output file
	KeyFile EnvironmentAwareValue `json:"keyFile"`
	// advanced tls configuration
	AdvancedConfig *TLSAdvancedConfiguration `json:"advanced"`
}

func (t *TLSConfiguration) setDefaults() {
	if t.CertFile == "" {
		t.CertFile = "cert.pem"
	}
	if t.KeyFile == "" {
		t.KeyFile = "key.pem"
	}
	if t.AdvancedConfig == nil {
		t.AdvancedConfig = new(TLSAdvancedConfiguration)
	}
	t.AdvancedConfig.setDefaults()
}

func (t *TLSConfiguration) validate() error {
	if !t.AutoGenerate {
		if FileDoesNotExist(t.CertFile.String()) {
			return fmt.Errorf("cert file [%s] does not exist", t.CertFile)
		}
		if FileDoesNotExist(t.KeyFile.String()) {
			return fmt.Errorf("key file [%s] does not exist", t.KeyFile)
		}
	}
	return nil
}

func (csl CipherSuiteList) ToUint16Array() ([]uint16, error) {
	a := make([]uint16, len(csl))
	for i, cs := range csl {
		v, err := cs.toUint16()
		if err != nil {
			return nil, err
		}
		a[i] = v
	}
	return a, nil
}

func (csl CipherSuiteList) ToUint32Array() ([]uint32, error) {
	a := make([]uint32, len(csl))
	for i, cs := range csl {
		v, err := cs.toUint32()
		if err != nil {
			return nil, err
		}
		a[i] = v
	}
	return a, nil
}

type TLSAdvancedConfiguration struct {
	// preferred cipher suites
	CipherSuites CipherSuiteList `json:"cipherSuites"`
}

type TLSConnectionConfiguration struct {
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
	// server certificate
	// will be ignored if insecureSkipVerify is true
	CertFile EnvironmentAwareValue `json:"certFile"`
	// certificate of CA which signs server certificate
	// will be ignored if insecureSkipVerify is true
	CaFile EnvironmentAwareValue `json:"caFile"`
	// advanced configuration for TLS
	AdvancedConfig *TLSAdvancedConfiguration `json:"advanced"`
}

func (tac *TLSAdvancedConfiguration) setDefaults() {
	if len(tac.CipherSuites) == 0 {
		tac.CipherSuites = defaultCipherSuites
	}
}

func (tc *TLSConnectionConfiguration) setDefaults() {

}

func (tc *TLSConnectionConfiguration) validate() error {
	if !tc.InsecureSkipVerify && FileDoesNotExist(tc.CertFile.String()) {
		return fmt.Errorf("no cert file for server tls connection")
	}
	return nil
}

// support URI format with 'env' scheme during JSON unmarshalling
type EnvironmentAwareValue string

func (d *EnvironmentAwareValue) UnmarshalJSON(data []byte) error {
	v := string(data)
	isString := strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"")
	if !isString {
		return fmt.Errorf("not a string")
	}
	v = strings.TrimFunc(v, func(r rune) bool {
		return r == '"'
	})
	if u, err := url.Parse(v); err == nil {
		switch u.Scheme {
		case "env":
			v = os.Getenv(u.Host)
		}
	}
	*d = EnvironmentAwareValue(v)
	return nil
}

func (d EnvironmentAwareValue) String() string {
	return string(d)
}

// value can be an URL with 'env' scheme in order to read value
// from env
type EnvironmentAwareCredentials map[string]EnvironmentAwareValue

type AuthenticationConfiguration struct {
	Method      AuthenticationMethod        `json:"method"`
	Credentials EnvironmentAwareCredentials `json:"credentials"`
}

func (ac *AuthenticationConfiguration) validate() error {
	validateCredentials := func(f string) error {
		if _, ok := ac.Credentials[f]; !ok {
			return fmt.Errorf("missing %s for authentication method %s", f, ac.Method)
		}
		return nil
	}
	switch ac.Method {
	case AMClientSecretBasic:
		if err := validateCredentials(AMClientSecretBasicClientId); err != nil {
			return err
		}
		if err := validateCredentials(AMClientSecretBasicClientSecret); err != nil {
			return err
		}
	case AMClientSecretForm:
		if err := validateCredentials(AMClientSecretFormClientId); err != nil {
			return err
		}
		if err := validateCredentials(AMClientSecretFormClientSecret); err != nil {
			return err
		}
	case AMPrivateKey:
		if err := validateCredentials(AMPrivateKeyCertFile); err != nil {
			return err
		}
		if err := validateCredentials(AMPrivateKeyKeyFile); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported authentication method [%s] for introspect", ac.Method)
	}
	return nil
}

func (ac *AuthenticationConfiguration) UsePrivateKey() bool {
	return ac.Method == AMPrivateKey
}

func (ac *AuthenticationConfiguration) PrivateKeyFiles() (certFile string, keyFile string) {
	certFile, keyFile = ac.Credentials[AMPrivateKeyCertFile].String(), ac.Credentials[AMPrivateKeyKeyFile].String()
	return
}

type CacheConfiguration struct {
	Limit               int `json:"limit"              `
	ExpirationInSeconds int `json:"expirationInSeconds"`
}

func (cc *CacheConfiguration) setDefaults() {
	cc.Limit = defaultCacheLimit
	cc.ExpirationInSeconds = defaultExpirationInSeconds
}

type IntrospectionConfiguration struct {
	Endpoint string `json:"endpoint"`
	// configure how to authenticate with introspection endpoint
	AuthenticationConfig *AuthenticationConfiguration `json:"authentication"`
	TLSConnectionConfig  *TLSConnectionConfiguration  `json:"tlsConnection" `
}

func (i *IntrospectionConfiguration) validate() error {
	if i.Endpoint == "" {
		return fmt.Errorf("missing introspection endpoint")
	}
	if i.AuthenticationConfig == nil {
		return fmt.Errorf("missing authentication configuration for introspect")
	}
	if err := i.AuthenticationConfig.validate(); err != nil {
		return err
	}
	if i.TLSConnectionConfig != nil {
		if err := i.TLSConnectionConfig.validate(); err != nil {
			return fmt.Errorf("[introspect] %s", err)
		}
	}
	return nil
}

func (i *IntrospectionConfiguration) setDefaults() {
	if i.TLSConnectionConfig != nil {
		i.TLSConnectionConfig.setDefaults()
	}
}

// JSON Web Signature configuration
type JWSConfiguration struct {
	Endpoint            string                      `json:"endpoint"     `
	TLSConnectionConfig *TLSConnectionConfiguration `json:"tlsConnection"`
}

func (jwsc *JWSConfiguration) validate() error {
	if jwsc.Endpoint == "" {
		return fmt.Errorf("missing endpoint to retrieve JSON Web Keyset")
	}
	if jwsc.TLSConnectionConfig != nil {
		if err := jwsc.TLSConnectionConfig.validate(); err != nil {
			return fmt.Errorf("[jws] %s", err)
		}
	}
	return nil
}

func (jwsc *JWSConfiguration) setDefaults() {
	if jwsc.TLSConnectionConfig != nil {
		jwsc.TLSConnectionConfig.setDefaults()
	}
}

// JSON Web Token configuration
type JWTConfiguration struct {
	// define a field name in JWT token used to retrieve scopes/roles
	// which are used to perform authorization check
	AuthorizationField string `json:"authorizationField"`

	// if introspection API is provided, use it instead of JWT
	PreferIntrospection bool `json:"preferIntrospection"`
}

func (jwtc *JWTConfiguration) validate() error {
	return nil
}

func (jwtc *JWTConfiguration) setDefaults() {
	if jwtc.AuthorizationField == "" {
		jwtc.AuthorizationField = defaultAuthorizationField
	}
}

type TokenValidationConfiguration struct {
	// name of a node which is the recipient of the token
	// we don't allow to configure this, instead, it has to come from geth during initialization
	Aud string `json:"-"`
	// this corresponds to `iss` claim which identifies the principal
	// that issued the token
	Issuers             []string                    `json:"issuers"`
	CacheConfig         *CacheConfiguration         `json:"cache"`
	IntrospectionConfig *IntrospectionConfiguration `json:"introspect"`
	JWSConfig           *JWSConfiguration           `json:"jws"`
	JWTConfig           *JWTConfiguration           `json:"jwt"`
}

func (a *TokenValidationConfiguration) validate() error {
	mustExist := a.UseIntrospection() || a.UseJWS()
	if !mustExist {
		return fmt.Errorf("missing introspect/jws configuration")
	}
	if a.UseIntrospection() {
		if err := a.IntrospectionConfig.validate(); err != nil {
			return err
		}
	}
	if a.UseJWS() {
		if err := a.JWSConfig.validate(); err != nil {
			return err
		}
	}
	if a.JWTConfig != nil {
		if err := a.JWTConfig.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (a *TokenValidationConfiguration) UseIntrospection() bool {
	return a.IntrospectionConfig != nil
}

func (a *TokenValidationConfiguration) UseJWS() bool {
	return a.JWSConfig != nil
}

func (a *TokenValidationConfiguration) setDefaults() {
	if len(a.Issuers) == 0 {
		a.Issuers = []string{defaultIssuer}
	}
	if a.IntrospectionConfig != nil {
		a.IntrospectionConfig.setDefaults()
	}
	if a.JWSConfig != nil {
		a.JWSConfig.setDefaults()
	}
	if a.JWTConfig == nil {
		a.JWTConfig = &JWTConfiguration{}
	}
	a.JWTConfig.setDefaults()
	if a.CacheConfig == nil {
		a.CacheConfig = &CacheConfiguration{}
		a.CacheConfig.setDefaults()
	}
}

func FileDoesNotExist(filePath string) bool {
	_, err := os.Stat(filePath)
	if err != nil && os.IsNotExist(err) {
		return true
	}
	return false
}
