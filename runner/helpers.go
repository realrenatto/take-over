package runner

import (
	"net/url"
	"strings"
)

func isValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	return err == nil
}

// normalizeURL ensures the URL has a scheme; defaults to https.
func normalizeURL(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "https://" + target
}
