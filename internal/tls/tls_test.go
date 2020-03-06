package tls

import (
	"context"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/jpmorganchase/quorum-plugin-security/internal/config"
	"github.com/jpmorganchase/quorum-security-plugin-sdk-go/proto"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCert(t *testing.T) {
	_, _, err := generateDefaultCert()

	assert.NoError(t, err)
}

func TestPrepareTLS_whenAutoGenerateCert(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "q-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	conf := &config.TLSConfiguration{
		AutoGenerate: true,
		CertFile:     config.EnvironmentAwareValue(path.Join(tmpDir, "cert.pem")),
		KeyFile:      config.EnvironmentAwareValue(path.Join(tmpDir, "key.pem")),
	}
	_, _, err = prepareTLS(conf)

	assert.NoError(t, err)
	assert.False(t, config.FileDoesNotExist(conf.KeyFile.String()), "Key file must exist")
	assert.False(t, config.FileDoesNotExist(conf.CertFile.String()), "Cert file must exist")
}

func TestPrepareTLS_whenFilesAlreadyExist(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "q-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	conf := &config.TLSConfiguration{
		AutoGenerate: true,
		CertFile:     config.EnvironmentAwareValue(path.Join(tmpDir, "cert.pem")),
		KeyFile:      config.EnvironmentAwareValue(path.Join(tmpDir, "key.pem")),
	}
	arbitraryKeyPem := []byte("arbitrary key data")
	arbitraryCertPem := []byte("arbitrary cert data")
	if err := ioutil.WriteFile(conf.CertFile.String(), arbitraryCertPem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(conf.KeyFile.String(), arbitraryKeyPem, 0600); err != nil {
		t.Fatal(err)
	}

	actualCert, actualKey, err := prepareTLS(conf)

	assert.NoError(t, err)
	assert.Equal(t, arbitraryCertPem, actualCert)
	assert.Equal(t, arbitraryKeyPem, actualKey)
}

func TestNewHttpClient_whenTypical(t *testing.T) {

	tempDir, err := ioutil.TempDir("", "q-")

	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	// generate a new certificate
	arbitraryConfig := &config.TLSConfiguration{
		AutoGenerate: true,
		CertFile:     config.EnvironmentAwareValue(filepath.Join(tempDir, "cert.pem")),
		KeyFile:      config.EnvironmentAwareValue(filepath.Join(tempDir, "key.pem")),
	}
	_, _, err = prepareTLS(arbitraryConfig)

	assert.NoError(t, err)

	conf := &config.TLSConnectionConfiguration{
		InsecureSkipVerify: false,
		CertFile:           arbitraryConfig.CertFile,
	}
	_, err = NewHttpClient("https://arbitraryhost", conf, &config.AuthenticationConfiguration{
		Method: config.AMPrivateKey,
		Credentials: config.EnvironmentAwareCredentials{
			config.AMPrivateKeyCertFile: config.EnvironmentAwareValue(arbitraryConfig.CertFile),
			config.AMPrivateKeyKeyFile:  config.EnvironmentAwareValue(arbitraryConfig.KeyFile),
		},
	})

	assert.NoError(t, err, "creating new http client with tls configuration")
}

func TestNewTLSConfigurationSource_whenTypical(t *testing.T) {
	arbitraryConfig := &config.TLSConfiguration{}

	testObject, err := NewTLSConfigurationSource(arbitraryConfig)

	assert.NoError(t, err)
	assert.Equal(t, arbitraryConfig, testObject.conf)
}

func TestNewTLSConfigurationSource_whenNoConfig(t *testing.T) {
	testObject, err := NewTLSConfigurationSource(nil)

	assert.NoError(t, err)
	assert.Nil(t, testObject)
}

func TestTLSConfigurationSource_Get(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "q-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	conf := &config.TLSConfiguration{
		AutoGenerate: true,
		CertFile:     config.EnvironmentAwareValue(path.Join(tmpDir, "cert.pem")),
		KeyFile:      config.EnvironmentAwareValue(path.Join(tmpDir, "key.pem")),
		AdvancedConfig: &config.TLSAdvancedConfiguration{
			CipherSuites: config.CipherSuiteList{
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			},
		},
	}
	testObject, err := NewTLSConfigurationSource(conf)
	assert.NoError(t, err)

	response, err := testObject.Get(context.Background(), &proto.TLSConfiguration_Request{})

	assert.NoError(t, err)
	assert.NotNil(t, response.Data)
}
