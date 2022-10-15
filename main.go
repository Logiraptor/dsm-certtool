package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type SynologyConfig struct {
	Insecure bool
	Url      string
	Username string
	Password string
}

type Config struct {
	ClientConfig SynologyConfig

	CertFile string
	KeyFile  string
}

func main() {
	var config Config
	flag.StringVar(&config.ClientConfig.Url, "url", "", "Synology URL")
	flag.StringVar(&config.ClientConfig.Username, "username", "", "Synology username")
	flag.StringVar(&config.ClientConfig.Password, "password", "", "Synology password")
	flag.BoolVar(&config.ClientConfig.Insecure, "insecure", false, "Skip TLS verification")

	flag.StringVar(&config.CertFile, "cert", "", "Certificate file")
	flag.StringVar(&config.KeyFile, "key", "", "Key file")

	flag.Parse()

	if config.ClientConfig.Password == "" {
		if password, ok := os.LookupEnv("SYNO_PASSWORD"); ok {
			config.ClientConfig.Password = password
		}
	}

	client := NewSynologyClient(config.ClientConfig)

	version, err := client.GetAPIVersion("SYNO.API.Auth", "SYNO.Core.Certificate")
	if err != nil {
		log.Println("Error getting API version:", err)
		os.Exit(1)
	}

	version.Print()

	err = client.Login()
	if err != nil {
		log.Println("Error logging in:", err)
		os.Exit(1)
	}

	defer client.Logout()

	certs, err := client.ListCertificates()
	if err != nil {
		log.Println("Error listing certificates:", err)
		os.Exit(1)
	}

	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Println("Error loading certificate:", err)
		os.Exit(1)
	}

	id, ok := findExistingCertID(&cert, certs)
	if !ok {
		log.Printf("Certificate with CN %s not found, creating new one", cert.Leaf.Subject.CommonName)
	} else {
		log.Printf("Certificate with CN %s found with id %s, updating", cert.Leaf.Subject.CommonName, id)
	}

	err = client.UploadCertificate(id, cert)
	if err != nil {
		log.Println("Error uploading certificate", err)
		os.Exit(1)
	}
}

func findExistingCertID(cert *tls.Certificate, certs CertificatesResponse) (string, bool) {
	var err error
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", false
	}
	for _, c := range certs.Data.Certificates {
		if c.Subject.CommonName == cert.Leaf.Subject.CommonName {
			return c.ID, true
		}
	}
	return "", false
}

type SynologyClient struct {
	config SynologyConfig
	*http.Client
}

func NewSynologyClient(config SynologyConfig) *SynologyClient {
	// Create a client with cookie jar
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Println("Error creating cookie jar:", err)
		os.Exit(1)
	}

	client := &http.Client{
		Jar: jar,
	}

	if config.Insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &SynologyClient{
		config: config,
		Client: &http.Client{
			Jar: jar,
		},
	}
}

type APIVersion struct {
	Data map[string]struct {
		MinVersion int `json:"minVersion"`
		MaxVersion int `json:"maxVersion"`
	} `json:"data"`
}

func (a APIVersion) Print() {
	for k, v := range a.Data {
		log.Printf("%s (min: %d, max: %d)\n", k, v.MinVersion, v.MaxVersion)
	}
}

func (c *SynologyClient) GetAPIVersion(apis ...string) (*APIVersion, error) {
	url := fmt.Sprintf("%s/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=%s", c.config.Url, strings.Join(apis, ","))
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var version APIVersion
	err = json.NewDecoder(resp.Body).Decode(&version)
	return &version, err
}

type LoginResponse struct {
	Data struct {
		Sid string `json:"sid"`
		Did string `json:"did"`
	} `json:"data"`
	Success bool `json:"success"`
}

func (c *SynologyClient) Login() error {
	url := fmt.Sprintf("%s/webapi/entry.cgi?api=SYNO.API.Auth&version=7&method=login&account=%s&passwd=%s", c.config.Url, c.config.Username, c.config.Password)
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var login LoginResponse
	err = json.NewDecoder(resp.Body).Decode(&login)
	if err != nil {
		return err
	}

	if !login.Success {
		return fmt.Errorf("Login failed")
	}
	return nil
}

func (c *SynologyClient) Logout() error {
	url := fmt.Sprintf("%s/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=logout", c.config.Url)
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	type LogoutResponse struct {
		Success bool `json:"success"`
	}
	var logout LogoutResponse
	err = json.NewDecoder(resp.Body).Decode(&logout)
	if err != nil {
		return err
	}

	if !logout.Success {
		return fmt.Errorf("Logout failed")
	}

	return nil
}

type CertificatesResponse struct {
	Data    Data `json:"data"`
	Success bool `json:"success"`
}

type Issuer struct {
	City         string `json:"city"`
	CommonName   string `json:"common_name"`
	Country      string `json:"country"`
	Organization string `json:"organization"`
}

type SelfSignedCacrtInfo struct {
	Issuer  Issuer  `json:"issuer"`
	Subject Subject `json:"subject"`
}

type Services struct {
	DisplayName     string `json:"display_name"`
	IsPkg           bool   `json:"isPkg"`
	Owner           string `json:"owner"`
	Service         string `json:"service"`
	Subscriber      string `json:"subscriber"`
	DisplayNameI18N string `json:"display_name_i18n,omitempty"`
	MultipleCert    bool   `json:"multiple_cert,omitempty"`
	UserSetable     bool   `json:"user_setable,omitempty"`
}

type Subject struct {
	City         string   `json:"city"`
	CommonName   string   `json:"common_name"`
	Country      string   `json:"country"`
	Organization string   `json:"organization"`
	SubAltName   []string `json:"sub_alt_name"`
}

type Certificates struct {
	Desc                string              `json:"desc"`
	ID                  string              `json:"id"`
	IsBroken            bool                `json:"is_broken"`
	IsDefault           bool                `json:"is_default"`
	Issuer              Issuer              `json:"issuer"`
	KeyTypes            string              `json:"key_types"`
	Renewable           bool                `json:"renewable"`
	SelfSignedCacrtInfo SelfSignedCacrtInfo `json:"self_signed_cacrt_info"`
	Services            []Services          `json:"services"`
	SignatureAlgorithm  string              `json:"signature_algorithm"`
	Subject             Subject             `json:"subject"`
	UserDeletable       bool                `json:"user_deletable"`
	ValidFrom           string              `json:"valid_from"`
	ValidTill           string              `json:"valid_till"`
}

type Data struct {
	Certificates []Certificates `json:"certificates"`
}

func (c *SynologyClient) ListCertificates() (CertificatesResponse, error) {
	url := fmt.Sprintf("%s/webapi/entry.cgi?api=SYNO.Core.Certificate.CRT&method=list&version=1", c.config.Url)
	resp, err := c.Get(url)
	if err != nil {
		return CertificatesResponse{}, err
	}

	var certificates CertificatesResponse
	err = json.NewDecoder(resp.Body).Decode(&certificates)
	if err != nil {
		return CertificatesResponse{}, err
	}

	if !certificates.Success {
		return CertificatesResponse{}, fmt.Errorf("ListCertificates failed")
	}

	return certificates, nil
}

func (c *SynologyClient) UploadCertificate(id string, cert tls.Certificate) error {

	key, crt, ca, err := encodeCerts(cert)
	if err != nil {
		return err
	}

	// Intentionally ignoring errors here since it's all writing into a buffer
	buf := &bytes.Buffer{}
	formData := multipart.NewWriter(buf)
	writeFile(formData, "key", "tls.key", key)
	writeFile(formData, "cert", "tls.crt", crt)
	writeFile(formData, "inter_cert", "ca.crt", ca)

	if id != "" {
		formData.WriteField("id", id)
	}
	formData.WriteField("desc", "Provisioned by dsm-certtool")
	formData.WriteField("as_default", "true")
	formData.Close()

	url := fmt.Sprintf("%s/webapi/entry.cgi?api=SYNO.Core.Certificate&method=import&version=1", c.config.Url)
	resp, err := c.Post(url, formData.FormDataContentType(), buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	type UploadResponse struct {
		Success bool `json:"success"`
		Data    struct {
			ID           string `json:"id"`
			RestartHttpD bool   `json:"restart_httpd"`
		} `json:"data"`
	}
	var upload UploadResponse
	err = json.NewDecoder(resp.Body).Decode(&upload)
	if err != nil {
		return err
	}

	if !upload.Success {
		return fmt.Errorf("Upload failed")
	}

	if upload.Data.RestartHttpD {
		log.Println("HTTP services were restarted")
	} else {
		log.Println("HTTP services were not restarted")
	}

	return nil
}

func writeFile(formData *multipart.Writer, field, file string, data []byte) {
	formFile, err := formData.CreateFormFile(field, file)
	if err != nil {
		log.Fatal(err)
	}
	formFile.Write(data)
}

func encodeCerts(cert tls.Certificate) (key, crt, ca []byte, err error) {
	var keyBuf, crtBuf, caBuf bytes.Buffer

	if err := pem.Encode(&keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))}); err != nil {
		return nil, nil, nil, err
	}

	if err := pem.Encode(&crtBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}); err != nil {
		return nil, nil, nil, err
	}

	for _, cert := range cert.Certificate[1:] {
		if err := pem.Encode(&caBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return nil, nil, nil, err
		}
	}

	return keyBuf.Bytes(), crtBuf.Bytes(), caBuf.Bytes(), nil
}
