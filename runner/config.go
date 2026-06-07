package runner

import (
	"crypto/tls"
	"net/http"
	"time"
)

type Config struct {
	URL          string
	List         string
	Output       string
	Verbose      bool
	Concurrency  int
	Timeout      int
	client       *http.Client
	fingerprints []Fingerprint
}

func (s *Config) initHTTPClient() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := time.Duration(10) * time.Second
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
	s.client = client
}

func (c *Config) loadFingerprints() error {
	fingerprints, err := Fingerprints()
	if err != nil {
		return err
	}
	c.fingerprints = fingerprints
	return nil
}
