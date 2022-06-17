package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	// PrivateKeyBlockType is a possible value for pem.Block.Type.
	PrivateKeyBlockType = "PRIVATE KEY"
	// PublicKeyBlockType is a possible value for pem.Block.Type.
	PublicKeyBlockType = "PUBLIC KEY"
	// CertificateBlockType is a possible value for pem.Block.Type.
	CertificateBlockType = "CERTIFICATE"
	// RSAPrivateKeyBlockType is a possible value for pem.Block.Type.
	RSAPrivateKeyBlockType = "RSA PRIVATE KEY"
	rsaKeySize             = 2048
)

type Config struct {
	KubeConfigDir string   `yaml:"kubeConfigDir"`
	CaSign        []CaSign `yaml:"CaSign"`
}
type Sign struct {
	Name     string `yaml:"Name"`
	CertName string `yaml:"CertName"`
	KeyName  string `yaml:"KeyName"`
}
type CaSign struct {
	Name        string   `yaml:"Name"`
	CertName    string   `yaml:"CertName"`
	KeyName     string   `yaml:"KeyName"`
	Sign        []Sign   `yaml:"Sign"`
	KubeConfigs []string `yaml:"KubeConfigs,omitempty"`
}

func GetConf() *Config {

	data, err := ioutil.ReadFile("./config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	var conf *Config

	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		panic(err)
	}
	return conf
}

func main() {

	conf := GetConf()
	fmt.Println(conf)
	newkubeConfigDir := fmt.Sprintf("%s_%s", conf.KubeConfigDir, time.Now().Format("20060102150405"))
	pkiDir := fmt.Sprintf("%s/pki", conf.KubeConfigDir)
	newPkiDir := fmt.Sprintf("%s/pki", newkubeConfigDir)
	os.MkdirAll(newPkiDir, 0755)
	for _, caSign := range conf.CaSign {
		caCert, caKey, err := TryLoadCertAndKeyFromDisk(pkiDir, caSign.Name)
		if err != nil {
			panic(err)
		}

		for _, sign := range caSign.Sign {
			pemCert, pemKey, err := TryLoadCertAndKeyFromDisk(pkiDir, sign.Name)
			if err != nil {
				panic(err)
			}
			newPemCert, newPemKey, err := NewCertFromOld(caCert, caKey, pemCert, pemKey)
			if err != nil {
				panic(err)
			}
			WriteCertAndKey(newPkiDir, sign.Name, newPemCert, newPemKey)
		}

		//  kubeConfig
		if len(caSign.KubeConfigs) > 0 {
			for _, name := range caSign.KubeConfigs {
				filename := fmt.Sprintf("%s/%s", conf.KubeConfigDir, name)
				c, err := clientcmd.LoadFromFile(filename)
				if err != nil {
					panic(err)
				}
				for _, user := range c.AuthInfos {
					if len(user.ClientCertificateData) > 0 {
						pemCert, pemKey, err := TryToLoadCertAndKeyFromByte(user.ClientCertificateData, user.ClientKeyData)
						if err != nil {
							panic(err)
						}
						newPemCert, _, err := NewCertFromOld(caCert, caKey, pemCert, pemKey)
						if err != nil {
							panic(err)
						}
						user.ClientCertificateData = EncodeCertPEM(newPemCert)
					}

					if len(user.ClientCertificate) > 0 {
						pemCert, pemKey, err := TryToLoadCertAndKeyFromDisk(user.ClientCertificate, user.ClientKey)
						if err != nil {
							panic(err)
						}
						newPemCert, newPemKey, err := NewCertFromOld(caCert, caKey, pemCert, pemKey)
						if err != nil {
							panic(err)
						}

						encoded, err := keyutil.MarshalPrivateKeyToPEM(newPemKey)
						if err != nil {
							panic(err)
						}

						user.ClientCertificate = ""
						user.ClientKey = ""
						user.ClientCertificateData = EncodeCertPEM(newPemCert)
						user.ClientKeyData = encoded

					}
				}
				err = clientcmd.WriteToFile(*c, fmt.Sprintf("%s/%s", newkubeConfigDir, filepath.Base(filename)))
				if err != nil {
					panic(err)
				}
			}
		}

	}
}

func NewCertFromOld(caCert *x509.Certificate, caKey crypto.Signer, pemCert *x509.Certificate, pemKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	if err := VerifyCertificate(caCert, pemCert); err != nil {
		return nil, nil, err
	}
	newPemCert, newPemKey, err := NewCertAndKey(caCert, caKey, pemCert, pemKey)
	if err != nil {
		return nil, nil, err
	}
	return newPemCert, newPemKey, nil
}

func VerifyCertificate(caCert, pemCert *x509.Certificate) error {

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: pemCert.NotBefore.Add(+time.Second),
		//KeyUsages: pemCert.ExtKeyUsage,
	}
	if _, err := pemCert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: %s", err)
	}
	fmt.Printf("Verify certificate: Issuer: %s Subject: %s\n", pemCert.Issuer, pemCert.Subject)

	return nil
}

func EncodeCertPEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  CertificateBlockType,
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}

// NewCertAndKey creates new certificate and key by passing the certificate authority certificate and key
func NewCertAndKey(caCert *x509.Certificate, caKey crypto.Signer, pemCert *x509.Certificate, pemKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {

	cert, err := NewSignedCert(pemCert, pemKey, caCert, caKey, false)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to sign certificate")
	}

	return cert, pemKey, nil
}

// NewSignedCert creates a signed certificate using the given CA certificate and key
func NewSignedCert(pemCert *x509.Certificate, key crypto.Signer, caCert *x509.Certificate, caKey crypto.Signer, isCA bool) (*x509.Certificate, error) {

	certTmpl := *pemCert
	certTmpl.NotAfter = caCert.NotAfter

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

func TryToLoadCertAndKeyFromByte(clientCertificateData, clientKeyData []byte) (*x509.Certificate, crypto.Signer, error) {
	block, _ := pem.Decode(clientCertificateData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := TryLoadKeyFromBytes(clientKeyData)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// TryToLoadCertAndKeyFromDisk tries to load a cert and a key from the disk and validates that they are valid
func TryToLoadCertAndKeyFromDisk(certName, keyName string) (*x509.Certificate, crypto.Signer, error) {
	cert, err := TryToLoadCertFromDisk(certName)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to load certificate")
	}

	key, err := TryToLoadKeyFromDisk(keyName)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to load key")
	}

	return cert, key, nil
}

// TryLoadCertAndKeyFromDisk tries to load a cert and a key from the disk and validates that they are valid
func TryLoadCertAndKeyFromDisk(pkiPath, name string) (*x509.Certificate, crypto.Signer, error) {
	cert, err := TryLoadCertFromDisk(pkiPath, name)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to load certificate")
	}

	key, err := TryLoadKeyFromDisk(pkiPath, name)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to load key")
	}

	return cert, key, nil
}

// TryLoadCertFromDisk tries to load the cert from the disk
func TryToLoadCertFromDisk(certificatePath string) (*x509.Certificate, error) {

	certs, err := certutil.CertsFromFile(certificatePath)
	if err != nil {
		return nil, errors.Wrapf(err, "couldn't load the certificate file %s", certificatePath)
	}

	// We are only putting one certificate in the certificate pem file, so it's safe to just pick the first one
	// TODO: Support multiple certs here in order to be able to rotate certs
	cert := certs[0]

	return cert, nil
}

// TryLoadCertFromDisk tries to load the cert from the disk
func TryLoadCertFromDisk(pkiPath, name string) (*x509.Certificate, error) {
	certificatePath := pathForCert(pkiPath, name)

	certs, err := certutil.CertsFromFile(certificatePath)
	if err != nil {
		return nil, errors.Wrapf(err, "couldn't load the certificate file %s", certificatePath)
	}

	// We are only putting one certificate in the certificate pem file, so it's safe to just pick the first one
	// TODO: Support multiple certs here in order to be able to rotate certs
	cert := certs[0]

	return cert, nil
}

// TryLoadKeyFromDisk tries to load the key from the disk and validates that it is valid
func TryToLoadKeyFromDisk(privateKeyPath string) (crypto.Signer, error) {

	// Parse the private key from a file
	privKey, err := keyutil.PrivateKeyFromFile(privateKeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "couldn't load the private key file %s", privateKeyPath)
	}

	// Allow RSA and ECDSA formats only
	var key crypto.Signer
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		key = k
	case *ecdsa.PrivateKey:
		key = k
	default:
		return nil, errors.Errorf("the private key file %s is neither in RSA nor ECDSA format", privateKeyPath)
	}

	return key, nil
}

// TryLoadKeyFromDisk tries to load the key from the disk and validates that it is valid
func TryLoadKeyFromDisk(pkiPath, name string) (crypto.Signer, error) {
	privateKeyPath := pathForKey(pkiPath, name)

	// Parse the private key from a file
	privKey, err := keyutil.PrivateKeyFromFile(privateKeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "couldn't load the private key file %s", privateKeyPath)
	}

	// Allow RSA and ECDSA formats only
	var key crypto.Signer
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		key = k
	case *ecdsa.PrivateKey:
		key = k
	default:
		return nil, errors.Errorf("the private key file %s is neither in RSA nor ECDSA format", privateKeyPath)
	}

	return key, nil
}

// TryLoadKeyFromDisk tries to load the key from the disk and validates that it is valid
func TryLoadKeyFromBytes(keyData []byte) (crypto.Signer, error) {

	// Parse the private key from []byte
	privKey, err := keyutil.ParsePrivateKeyPEM(keyData)
	if err != nil {
		panic(err)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "couldn't load the private key  %s", string(keyData))
	}

	// Allow RSA and ECDSA formats only
	var key crypto.Signer
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		key = k
	case *ecdsa.PrivateKey:
		key = k
	default:
		return nil, errors.Errorf("the private key file %s is neither in RSA nor ECDSA format", string(keyData))
	}

	return key, nil
}

// WriteCertAndKey stores certificate and key at the specified location
func WriteCertAndKey(pkiPath string, name string, cert *x509.Certificate, key crypto.Signer) error {
	if err := WriteKey(pkiPath, name, key); err != nil {
		return errors.Wrap(err, "couldn't write key")
	}

	return WriteCert(pkiPath, name, cert)
}

// WriteCert stores the given certificate at the given location
func WriteCert(pkiPath, name string, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate cannot be nil when writing to file")
	}

	certificatePath := pathForCert(pkiPath, name)
	if err := certutil.WriteCert(certificatePath, EncodeCertPEM(cert)); err != nil {
		return errors.Wrapf(err, "unable to write certificate to file %s", certificatePath)
	}

	return nil
}

// WriteKey stores the given key at the given location
func WriteKey(pkiPath, name string, key crypto.Signer) error {
	if key == nil {
		return errors.New("private key cannot be nil when writing to file")
	}

	privateKeyPath := pathForKey(pkiPath, name)
	encoded, err := keyutil.MarshalPrivateKeyToPEM(key)
	if err != nil {
		return errors.Wrapf(err, "unable to marshal private key to PEM")
	}
	if err := keyutil.WriteKey(privateKeyPath, encoded); err != nil {
		return errors.Wrapf(err, "unable to write private key to file %s", privateKeyPath)
	}

	return nil
}

func pathForCert(pkiPath, name string) string {
	return filepath.Join(pkiPath, fmt.Sprintf("%s.crt", name))
}

func pathForKey(pkiPath, name string) string {
	return filepath.Join(pkiPath, fmt.Sprintf("%s.key", name))
}

func pathForPublicKey(pkiPath, name string) string {
	return filepath.Join(pkiPath, fmt.Sprintf("%s.pub", name))
}

func pathForCSR(pkiPath, name string) string {
	return filepath.Join(pkiPath, fmt.Sprintf("%s.csr", name))
}
