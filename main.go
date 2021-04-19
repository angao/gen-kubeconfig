package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/angao/gen-kubeconfig/pki"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
)

var (
	certificatesDir string
	masterURL       string
)

func init() {
	flag.StringVar(&certificatesDir, "caPath", "", "cartificate path")
	flag.StringVar(&masterURL, "masterURL", "", "Kubernetes APIServer address")
}

type clientCertAuth struct {
	CAKey         crypto.Signer
	Organizations []string
}

// tokenAuth struct holds info required to use a token to provide authentication info in a kubeconfig object
type tokenAuth struct {
	Token string `datapolicy:"token"`
}

type kubeConfigSpec struct {
	CACert         *x509.Certificate
	APIServer      string
	ClientName     string
	TokenAuth      *tokenAuth      `datapolicy:"token"`
	ClientCertAuth *clientCertAuth `datapolicy:"security-key"`
}

//var token = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImhBblJhak0yQW94a2NLUTlSMHppNHpsMm5Gb29vTm1fMnF4ZWhQV0VaWEEifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZXYiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiazgtZGV2LXRva2VuLTQycmNmIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6Ims4LWRldiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImQ3MTIwNGY2LTNmNjAtNDdlNS1iYjg1LTFhZDc1ZmEwNTJiZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZXY6azgtZGV2In0.dkesRG7G0zw0px9_6cVIRO8m2sKirrOmESTPfbgVYIvYQ52YhKp-21HdkMwGuDRAynOmVP4-cbqf8dO5nC1zDkAZ2t0IocL3OwyXru6T_V4Wtp-ktVfUe9tZPqsOEQJBYytzKi3WXH30NyDJAJJCdmVild2S-xZmaAScnTdvd9Dz1wEsy3HSTdtM-txoXFFmQDPMCdjwjl6eOf07910m6KcH_QAeKE1RHtU2P6V3-YbP0iQaCCL5h3gfEqu1SjKIHJ90tV8uA-zzQ9XJ4D1ybhsRI7-lptVWYSJMyQyEWF_xXO-nd0GzmG0rdCgVr4GM6hiGN7T55hy8_SgYkJ09ZQ`

func main() {
	flag.Parse()

	// "https://10.227.78.254:8443"
	if err := WriteKubeConfig(os.Stdout, certificatesDir, masterURL); err != nil {
		panic(err)
	}
}

func WriteKubeConfig(out io.Writer, certificatesDir, addr string) error {
	// creates the KubeConfigSpecs, actualized for the current InitConfiguration
	caCert, caKey, err := pki.TryLoadCertAndKeyFromDisk(certificatesDir, "ca")
	if err != nil {
		return errors.Wrap(err, "couldn't create a kubeconfig; the CA files couldn't be loaded")
	}

	// Validate period
	if err := pki.ValidateCertPeriod(caCert, 0); err != nil {
		return err
	}

	spec := &kubeConfigSpec{
		ClientName: "dev",
		APIServer:  addr,
		CACert:     caCert,
		ClientCertAuth: &clientCertAuth{
			CAKey: caKey,
		},
	}

	return writeKubeConfigFromSpec(out, spec, "kubernetes")
}

func buildKubeConfigFromSpec(spec *kubeConfigSpec, clustername string) (*clientcmdapi.Config, error) {
	// If this kubeconfig should use token
	if spec.TokenAuth != nil {
		// create a kubeconfig with a token
		return CreateWithToken(
			spec.APIServer,
			clustername,
			spec.ClientName,
			pki.EncodeCertPEM(spec.CACert),
			spec.TokenAuth.Token,
		), nil
	}

	// otherwise, create a client certs
	clientCertConfig := newClientCertConfigFromKubeConfigSpec(spec)

	clientCert, clientKey, err := pki.NewCertAndKey(spec.CACert, spec.ClientCertAuth.CAKey, &clientCertConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failure while creating %s client certificate", spec.ClientName)
	}

	encodedClientKey, err := keyutil.MarshalPrivateKeyToPEM(clientKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal private key to PEM")
	}
	// create a kubeconfig with the client certs
	return CreateWithCerts(
		spec.APIServer,
		clustername,
		spec.ClientName,
		pki.EncodeCertPEM(spec.CACert),
		encodedClientKey,
		pki.EncodeCertPEM(clientCert),
	), nil
}

func CreateWithToken(serverURL, clusterName, userName string, caCert []byte, token string) *clientcmdapi.Config {
	config := CreateBasic(serverURL, clusterName, userName, caCert)
	config.AuthInfos[userName] = &clientcmdapi.AuthInfo{
		Token: token,
	}
	return config
}

// CreateWithCerts creates a KubeConfig object with access to the API server with client certificates
func CreateWithCerts(serverURL, clusterName, userName string, caCert []byte, clientKey []byte, clientCert []byte) *clientcmdapi.Config {
	config := CreateBasic(serverURL, clusterName, userName, caCert)
	config.AuthInfos[userName] = &clientcmdapi.AuthInfo{
		ClientKeyData:         clientKey,
		ClientCertificateData: clientCert,
	}
	return config
}

// CreateBasic creates a basic, general KubeConfig object that then can be extended
func CreateBasic(serverURL, clusterName, userName string, caCert []byte) *clientcmdapi.Config {
	// Use the cluster and the username as the context name
	contextName := fmt.Sprintf("%s@%s", userName, clusterName)

	return &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			clusterName: {
				Server:                   serverURL,
				CertificateAuthorityData: caCert,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {
				Cluster:  clusterName,
				AuthInfo: userName,
			},
		},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{},
		CurrentContext: contextName,
	}
}

func newClientCertConfigFromKubeConfigSpec(spec *kubeConfigSpec) pki.CertConfig {
	return pki.CertConfig{
		Config: certutil.Config{
			CommonName:   spec.ClientName,
			Organization: spec.ClientCertAuth.Organizations,
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
	}
}

func writeKubeConfigFromSpec(out io.Writer, spec *kubeConfigSpec, clustername string) error {
	// builds the KubeConfig object
	config, err := buildKubeConfigFromSpec(spec, clustername)
	if err != nil {
		return err
	}

	// writes the kubeconfig to disk if it not exists
	configBytes, err := clientcmd.Write(*config)
	if err != nil {
		return errors.Wrap(err, "failure while serializing admin kubeconfig")
	}

	_, _ = fmt.Fprintln(out, string(configBytes))
	return nil
}
