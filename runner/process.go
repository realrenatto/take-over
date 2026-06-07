package runner

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

func Process(config *Config) error {
	fingerprints, err := Fingerprints()
	if err != nil {
		return fmt.Errorf("Process: %v", err)
	}

	config.initHTTPClient()
	config.loadFingerprints()
	subdomains := getSubdomains(config)

	fmt.Printf("[INF] Targets loaded for current scan: %d\n", len(subdomains))
	fmt.Printf("[INF] Fingerprints loaded for current scan: %d\n", len(fingerprints))
	fmt.Printf("[INF] Concurrency: %d\n", config.Concurrency)

	// Open output file upfront for real-time writing
	var outFile *os.File
	if config.Output != "" {
		outFile, err = os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("Process: cannot open output file: %v", err)
		}
		defer outFile.Close()
	}

	const ExtraChannelCapacity = 5
	subdomainCh := make(chan string, config.Concurrency+ExtraChannelCapacity)
	resCh := make(chan *processorResult, config.Concurrency)

	var wg sync.WaitGroup
	wg.Add(config.Concurrency)

	// Collector goroutine: prints and writes in real time
	var collectorDone sync.WaitGroup
	collectorDone.Add(1)
	go func() {
		defer collectorDone.Done()
		for r := range resCh {
			switch r.status {
			case ResultVulnerable:
				line := fmt.Sprintf("[VULNERABLE] %s | %s", r.subdomain, r.service)
				fmt.Println(line)
				if outFile != nil {
					fmt.Fprintln(outFile, line)
				}
			case ResultHTTPError, ResultResponseError:
				if config.Verbose {
					fmt.Printf("[%s] %s\n", r.status, r.subdomain)
				}
			default: // NOT VULNERABLE
				if config.Verbose {
					fmt.Printf("[NOT VULNERABLE] %s\n", r.subdomain)
				}
			}
		}
	}()

	for i := 0; i < config.Concurrency; i++ {
		go processorWorker(subdomainCh, resCh, config, &wg)
	}

	distributeSubdomains(subdomains, subdomainCh)
	wg.Wait()
	close(resCh)
	collectorDone.Wait()

	return nil
}

type processorResult struct {
	subdomain string
	status    resultStatus
	service   string
}

func processorWorker(subdomainCh <-chan string, resCh chan<- *processorResult, c *Config, wg *sync.WaitGroup) {
	defer wg.Done()
	for subdomain := range subdomainCh {
		result := c.checkSubdomain(subdomain)
		resCh <- &processorResult{
			subdomain: subdomain,
			status:    result.ResStatus,
			service:   result.Entry.Service,
		}
	}
}

func distributeSubdomains(subdomains []string, subdomainCh chan<- string) {
	for _, subdomain := range subdomains {
		subdomainCh <- subdomain
	}
	close(subdomainCh)
}

func getSubdomains(c *Config) []string {
	if c.URL != "" {
		// Support comma-separated URLs
		parts := strings.Split(c.URL, ",")
		var result []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		return result
	}
	subdomains, err := readSubdomains(c.List)
	if err != nil {
		log.Fatalf("Error reading subdomains: %s", err)
	}
	return subdomains
}
