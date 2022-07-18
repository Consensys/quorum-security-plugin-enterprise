package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/consensys/quorum-security-plugin-enterprise/internal/config"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type certConfig struct {
	hosts      string        // Comma-separated hostnames and IPs to generate a certificate for
	validFor   time.Duration // Duration that certificate is valid for
	rsaBits    int           // Size of RSA key to generate, ignore if ecdsa is used
	ecdsaCurve string        // ecdsa curve to use to generate key
}

var defaultCertConfig = &certConfig{
	hosts:      "localhost,127.0.0.1",
	validFor:   1 * 365 * 24 * time.Hour, // 1 years
	rsaBits:    2048,
	ecdsaCurve: "P256",
}

func generateDefaultCert() ([]byte, []byte, error) {
	return generateCert(defaultCertConfig)
}

// returns cert and private key in PEM format
func generateCert(cfg *certConfig) ([]byte, []byte, error) {
	log.Println("[DEBUG] Generating TLS certificate")
	var priv interface{}
	var err error
	switch cfg.ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, cfg.rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		// Ensure to avoid 1.10.8 and 1.11.x before 1.11.5 https://www.cvedetails.com/cve/CVE-2019-6486/
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("not supported ecdsa curve [%s]", cfg.ecdsaCurve)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate privatey key: %s", err)
	}
	notBefore, notAfter := time.Now(), time.Now().Add(cfg.validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Quorum"},
			CommonName:   "*",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	hosts := strings.Split(cfg.hosts, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %s", err)
	}
	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write cert: %s", err)
	}
	block, err := pemBlockForKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create private key block: %s", err)
	}
	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, block); err != nil {
		return nil, nil, fmt.Errorf("failed to write key: %s", err)
	}
	return certOut.Bytes(), keyOut.Bytes(), nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, fmt.Errorf("private key type not supported: %v", k)
	}
}

func prepareTLS(conf *config.TLSConfiguration) ([]byte, []byte, error) {
	certFile, keyFile := conf.CertFile, conf.KeyFile
	if conf.AutoGenerate && config.FileDoesNotExist(certFile.String()) && config.FileDoesNotExist(keyFile.String()) {
		certPem, keyPem, err := generateDefaultCert()
		if err != nil {
			return nil, nil, err
		}
		if err := ioutil.WriteFile(conf.CertFile.String(), certPem, 0644); err != nil {
			return nil, nil, err
		}
		if err := ioutil.WriteFile(conf.KeyFile.String(), keyPem, 0600); err != nil {
			return nil, nil, err
		}
		return certPem, keyPem, nil
	} else {
		certPem, err := ioutil.ReadFile(certFile.String())
		if err != nil {
			return nil, nil, err
		}
		keyPem, err := ioutil.ReadFile(keyFile.String())
		if err != nil {
			return nil, nil, err
		}
		return certPem, keyPem, nil
	}
}

func NewHttpClient(endpoint string, conf *config.TLSConnectionConfiguration, authConfig *config.AuthenticationConfiguration) (*http.Client, error) {
	if strings.HasPrefix(endpoint, "http://") {
		return &http.Client{}, nil
	}
	tlsConfig := &tls.Config{}
	if conf != nil {
		if conf.AdvancedConfig != nil && len(conf.AdvancedConfig.CipherSuites) > 0 {
			suites, err := conf.AdvancedConfig.CipherSuites.ToUint16Array()
			if err != nil {
				return nil, err
			}
			tlsConfig.CipherSuites = suites
		}
		tlsConfig.InsecureSkipVerify = conf.InsecureSkipVerify
		if !conf.InsecureSkipVerify {
			var certPem, caPem []byte
			var err error
			if conf.CertFile != "" {
				certPem, err = ioutil.ReadFile(conf.CertFile.String())
				if err != nil {
					return nil, err
				}
			}
			if conf.CaFile != "" {
				caPem, err = ioutil.ReadFile(conf.CaFile.String())
				if err != nil {
					return nil, err
				}
			}
			if len(certPem) != 0 || len(caPem) != 0 {
				certPool, err := x509.SystemCertPool()
				if err != nil {
					certPool = x509.NewCertPool()
				}
				if len(certPem) != 0 {
					certPool.AppendCertsFromPEM(certPem)
				}
				if len(caPem) != 0 {
					certPool.AppendCertsFromPEM(caPem)
				}
				tlsConfig.RootCAs = certPool
			}
		}
	}
	if authConfig != nil && authConfig.UsePrivateKey() {
		// Load client cert
		certFile, keyFile := authConfig.PrivateKeyFiles()
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.BuildNameToCertificate()
	}
	client := &http.Client{
		Transport: http.DefaultTransport,
	}
	// default http client transport is known so it's safe to cast without check here
	client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	return client, nil
}

// this implements proto.TLSConfigurationSourceServer service interface
type TLSConfigurationSource struct {
	conf *config.TLSConfiguration
}

func NewTLSConfigurationSource(conf *config.TLSConfiguration) (*TLSConfigurationSource, error) {
	if conf == nil {
		return nil, nil
	}
	return &TLSConfigurationSource{
		conf: conf,
	}, nil
}

func (c *TLSConfigurationSource) Get(ctx context.Context, req *proto.TLSConfiguration_Request) (*proto.TLSConfiguration_Response, error) {
	cipherSuites, err := c.conf.AdvancedConfig.CipherSuites.ToUint32Array()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	certPem, keyPem, err := prepareTLS(c.conf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	resp := &proto.TLSConfiguration_Response{
		Data: &proto.TLSConfiguration_Data{
			CertPem:      certPem,
			KeyPem:       keyPem,
			CipherSuites: cipherSuites,
		},
	}
	return resp, nil
}
