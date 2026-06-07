package runner

import (
	"io"
	"log"
	"regexp"
	"strings"
)

type resultStatus string

const (
	ResultHTTPError     resultStatus = "HTTP ERROR"
	ResultResponseError resultStatus = "RESPONSE ERROR"
	ResultVulnerable    resultStatus = "VULNERABLE"
	ResultNotVulnerable resultStatus = "NOT VULNERABLE"
)

type Result struct {
	ResStatus    resultStatus
	Entry        Fingerprint
	ResponseBody string
}

func (c *Config) checkSubdomain(subdomain string) Result {
	url := normalizeURL(subdomain)

	resp, err := c.client.Get(url)
	if err != nil {
		return Result{ResStatus: ResultHTTPError, Entry: Fingerprint{}}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{ResStatus: ResultResponseError, Entry: Fingerprint{}}
	}

	body := string(bodyBytes)
	return c.matchResponse(body)
}

func (c *Config) matchResponse(body string) Result {
	for _, fp := range c.fingerprints {
		if strings.Contains(body, fp.Fingerprint) {
			if confirmsVulnerability(body, fp) {
				return Result{
					ResStatus:    ResultVulnerable,
					Entry:        fp,
					ResponseBody: body,
				}
			}
			if hasNonVulnerableIndicators(fp) {
				return Result{
					ResStatus:    ResultNotVulnerable,
					Entry:        fp,
					ResponseBody: body,
				}
			}
		}
	}
	return Result{
		ResStatus:    ResultNotVulnerable,
		Entry:        Fingerprint{},
		ResponseBody: body,
	}
}

func hasNonVulnerableIndicators(fp Fingerprint) bool {
	return fp.NXDomain
}

func confirmsVulnerability(body string, fp Fingerprint) bool {
	if fp.NXDomain {
		return false
	}
	if fp.Fingerprint != "" {
		re, err := regexp.Compile(fp.Fingerprint)
		if err != nil {
			log.Printf("Error compiling regex for fingerprint %s: %v", fp.Fingerprint, err)
			return false
		}
		if re.MatchString(body) {
			return true
		}
	}
	return false
}
