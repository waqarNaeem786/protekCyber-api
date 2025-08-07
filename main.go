package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)


type Threat struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Date        string   `json:"date"`
	Tags        []string `json:"tags"`
	Indicators  []struct {
		Indicator string `json:"indicator"`
		Type      string `json:"type"`
	} `json:"indicators"`
	References []string `json:"references"`
}

type CVE struct {
	CVEID       string  `json:"cve_id"`
	Vendor      string  `json:"vendor"`
	Product     string  `json:"product"`
	Description string  `json:"description"`
	Published   string  `json:"published"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Status      string  `json:"status"`
}

type Pulse struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Tags            []string `json:"tags"`
	IndicatorCount  int      `json:"indicator_count"`
	Adversary       string   `json:"adversary"`
	MalwareFamilies []string `json:"malware_families"`
	Created         string   `json:"created"`
}

type AllThreatData struct {
	Pulses []Pulse `json:"pulses"`
}

var cache = struct {
	data      []Threat
	timestamp time.Time
}{}

var allThreatCache = struct {
	data      AllThreatData
	timestamp time.Time
}{data: AllThreatData{Pulses: make([]Pulse, 0)}}

var cveCache = struct {
	data      []CVE
	timestamp time.Time
}{}

var mockCVEs = []CVE{
	{
		CVEID:       "CVE-2025-0001",
		Vendor:      "unknown",
		Product:     "Unknown Product",
		Description: "Placeholder CVE due to API unavailability",
		Published:   time.Now().Format("2006-01-02"),
		CVSS:        0.0,
		Severity:    "low",
		Status:      "none",
	},
	{
		CVEID:       "CVE-2025-0002",
		Vendor:      "microsoft",
		Product:     "Windows",
		Description: "Mock vulnerability in Windows kernel",
		Published:   time.Now().AddDate(0, 0, -1).Format("2006-01-02"),
		CVSS:        7.8,
		Severity:    "high",
		Status:      "poc",
	},
	{
		CVEID:       "CVE-2025-0003",
		Vendor:      "apache",
		Product:     "HTTP Server",
		Description: "Mock remote code execution in Apache",
		Published:   time.Now().AddDate(0, 0, -2).Format("2006-01-02"),
		CVSS:        9.1,
		Severity:    "critical",
		Status:      "exploited",
	},
}

type CustomTime struct {
	time.Time
}

func (ct *CustomTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	parsed, err := time.Parse("2006-01-02T15:04:05.999999", s)
	if err != nil {
		return fmt.Errorf("custom time parse error: %v", err)
	}
	ct.Time = parsed
	return nil
}

type OTXResponse struct {
	Results []struct {
		ID          string     `json:"id"`
		Name        string     `json:"name"`
		Description string     `json:"description"`
		Created     CustomTime `json:"created"`
		Tags        []string   `json:"tags"`
		Indicators  []struct {
			Indicator string `json:"indicator"`
			Type      string `json:"type"`
		} `json:"indicators"`
		References      []string `json:"references"`
		Adversary       string   `json:"adversary"`
		MalwareFamilies []string `json:"malware_families"`
	} `json:"results"`
}

var (
	otxAPIKey  = os.Getenv("OTX_API_KEY")
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

func main() {
	http.HandleFunc("/api/threats", threatsHandler)
	http.HandleFunc("/health", healthCheck)
	http.HandleFunc("/api/cves", cvesHandler)
	http.HandleFunc("/api/all-threats", allThreatsHandler)
	http.HandleFunc("/api/checkpoint-threats", checkpointThreatsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func enableCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowed := map[string]bool{
		"http://localhost:6969":     true,
		"https://protekcyber.co.uk": true,
	}
	if allowed[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
}


func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("JSON encode error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Add this to your main.go
func checkpointThreatsHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	enableCORS(w, r)
	
	// Set proper headers for streaming
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable buffering for Nginx
	w.Header().Set("Transfer-Encoding", "chunked")	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 0, // No timeout - keep connection open
	}
	
	// Get stream from Check Point API
	resp, err := client.Get("https://threatmap-api.checkpoint.com/ThreatMap/api/feed")
	if err != nil {
		log.Printf("Failed to connect to Check Point API: %v", err)
		http.Error(w, "Failed to connect to threat feed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	
	// Create a buffer for reading chunks
	buf := make([]byte, 1024)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, err := w.Write([]byte("data: \n\n"))
				if err != nil {
					log.Printf("Failed to send heartbeat: %v", err)
					return
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			}
		}
	}()
	// Stream the response to client
	for {
		n, err := resp.Body.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Stream error: %v", err)
			}
			break
		}
		
		// Write chunk to client
		_, err = w.Write(buf[:n])
		if err != nil {
			log.Printf("Client disconnected: %v", err)
			break
		}
		
		// Flush the response
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	
	log.Println("Stream completed")
}

// func checkpointThreatsHandler(w http.ResponseWriter, r *http.Request) {
//  enableCORS(w, r)
    
//     // Set headers for streaming response
//     w.Header().Set("Content-Type", "text/event-stream")
//     w.Header().Set("Cache-Control", "no-cache")
//     w.Header().Set("Connection", "keep-alive")
    
//     // Get data from Check Point
//     resp, err := http.Get("https://threatmap-api.checkpoint.com/ThreatMap/api/feed")
//     if err != nil {
//         log.Printf("Error fetching threats: %v", err)
//         http.Error(w, "Failed to connect to threat feed", http.StatusBadGateway)
//         return
//     }
//     defer resp.Body.Close()
    
//     // Stream the response directly to client
//     _, err = io.Copy(w, resp.Body)
//     if err != nil {
//         log.Printf("Stream error: %v", err)
//     }
// }

func threatsHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if time.Since(cache.timestamp) < time.Hour && len(cache.data) > 0 {
		jsonResponse(w, cache.data)
		return
	}

	threats, err := fetchOTXThreats()
	if err != nil {
		log.Printf("OTX fetch failed: %v", err)
		if len(cache.data) > 0 {
			jsonResponse(w, cache.data)
			return
		}
		http.Error(w, "Threat data unavailable", http.StatusServiceUnavailable)
		return
	}

	cache.data = threats
	cache.timestamp = time.Now()
	jsonResponse(w, threats)
}





func fetchOTXThreats() ([]Threat, error) {
	if otxAPIKey == "" {
		return nil, fmt.Errorf("OTX_API_KEY environment variable not set")
	}

	req, err := http.NewRequest("GET", "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=4", nil)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %v", err)
	}
	req.Header.Add("X-OTX-API-KEY", otxAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTX API error: %s, body: %s", resp.Status, string(body))
	}

	var otxResp OTXResponse
	if err := json.Unmarshal(body, &otxResp); err != nil {
		return nil, fmt.Errorf("JSON decode failed: %v, body: %s", err, string(body))
	}

	if len(otxResp.Results) == 0 {
		return nil, fmt.Errorf("no results returned from OTX API")
	}

	return transformOTXToThreats(otxResp), nil
}

func transformOTXToThreats(otxResp OTXResponse) []Threat {
	var threats []Threat
	for _, pulse := range otxResp.Results {
		threat := Threat{
			ID:          pulse.ID,
			Name:        pulse.Name,
			Description: pulse.Description,
			Date:        pulse.Created.Format(time.RFC3339),
			Tags:        pulse.Tags,
			Indicators:  pulse.Indicators,
			References:  pulse.References,
		}

		threat.Type = "other"
		for _, tag := range pulse.Tags {
			switch {
			case contains([]string{"ransomware", "phishing", "apt"}, tag):
				threat.Type = tag
			case contains([]string{"critical", "high", "medium"}, tag):
				threat.Severity = tag
			}
		}

		threats = append(threats, threat)
	}
	return threats
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func isCVE(tag string) bool {
	return strings.HasPrefix(strings.ToLower(tag), "cve-")
}

func fetchOTXPulses(limit int) ([]Pulse, error) {
	if otxAPIKey == "" {
		return nil, fmt.Errorf("OTX_API_KEY environment variable not set")
	}

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=%d", limit)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %v", err)
	}
	req.Header.Add("X-OTX-API-KEY", otxAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTX API error: %s, body: %s", resp.Status, string(body))
	}

	var otxResp OTXResponse
	if err := json.Unmarshal(body, &otxResp); err != nil {
		return nil, fmt.Errorf("JSON decode failed: %v, body: %s", err, string(body))
	}

	var pulses []Pulse
	for _, result := range otxResp.Results {
		pulses = append(pulses, Pulse{
			ID:              result.ID,
			Name:            result.Name,
			Description:     result.Description,
			Tags:            result.Tags,
			IndicatorCount:  len(result.Indicators),
			Adversary:       result.Adversary,
			MalwareFamilies: result.MalwareFamilies,
			Created:         result.Created.Format("2006-01-02T15:04:05.999999"),
		})
	}

	// Sort pulses by creation date (newest first)
	sort.Slice(pulses, func(i, j int) bool {
		ti, _ := time.Parse("2006-01-02T15:04:05.999999", pulses[i].Created)
		tj, _ := time.Parse("2006-01-02T15:04:05.999999", pulses[j].Created)
		return ti.After(tj)
	})

	// Ensure exactly 7 pulses
	for len(pulses) < 7 {
		pulses = append(pulses, Pulse{
			ID:              fmt.Sprintf("fallback-%d", len(pulses)+1),
			Name:            "Unknown Threat",
			Description:     "No recent threat data available.",
			Tags:            []string{"unknown"},
			IndicatorCount:  10,
			Adversary:       "",
			MalwareFamilies: []string{},
			Created:         time.Now().Format("2006-01-02T15:04:05.999999"),
		})
	}

	log.Printf("Fetched %d valid pulses", len(pulses))
	for i, pulse := range pulses {
		log.Printf("Pulse %d: ID=%s, Name=%s, Description=%s, Tags=%v, Adversary=%s, MalwareFamilies=%v, IndicatorCount=%d, Created=%s",
			i+1, pulse.ID, pulse.Name, truncateDescription(pulse.Description, 100), pulse.Tags, pulse.Adversary, pulse.MalwareFamilies, pulse.IndicatorCount, pulse.Created)
	}

	return pulses, nil
}

func allThreatsHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if time.Since(allThreatCache.timestamp) < time.Hour && len(allThreatCache.data.Pulses) > 0 {
		jsonResponse(w, allThreatCache.data)
		return
	}

	data, err := fetchAllThreatData()
	if err != nil {
		log.Printf("Failed to fetch all threat data: %v", err)
		if len(allThreatCache.data.Pulses) > 0 {
			jsonResponse(w, allThreatCache.data)
			return
		}
		http.Error(w, "Threat data unavailable", http.StatusServiceUnavailable)
		return
	}

	allThreatCache.data = data
	allThreatCache.timestamp = time.Now()
	jsonResponse(w, data)
}

func fetchAllThreatData() (AllThreatData, error) {
	pulses, err := fetchOTXPulses(7)
	if err != nil {
		log.Printf("Failed to fetch pulses: %v", err)
		return AllThreatData{Pulses: []Pulse{}}, err
	}

	return AllThreatData{Pulses: pulses}, nil
}

func truncateDescription(desc string, maxLen int) string {
	if desc == "" {
		return "No detailed threat description available from recent intelligence."
	}
	if len(desc) <= maxLen {
		return desc
	}
	return desc[:maxLen] + "..."
}

func cvesHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if time.Since(cveCache.timestamp) < 24*time.Hour && len(cveCache.data) > 0 {
		jsonResponse(w, cveCache.data)
		return
	}

	cves, err := fetchNVDCVEs()
	if err != nil {
		log.Printf("NVD fetch failed: %v", err)
		if len(cveCache.data) > 0 {
			jsonResponse(w, cveCache.data)
			return
		}
		jsonResponse(w, mockCVEs)
		return
	}

	cveCache.data = cves
	cveCache.timestamp = time.Now()
	jsonResponse(w, cves)
}

func fetchNVDCVEs() ([]CVE, error) {
	const maxRetries = 3
	const retryDelay = 6 * time.Second
	const resultsPerPage = 10
	startIndex := 0
	var allCVEs []CVE
	var resp *http.Response // Initialize resp to avoid nil dereference

	endDate := time.Now().UTC()
	startDate := endDate.AddDate(0, 0, -119)
	pubStart := startDate.Format("2006-01-02T15:04:05.000Z")
	pubEnd := endDate.Format("2006-01-02T15:04:05.000Z")

	for {
		url := fmt.Sprintf(
			"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=%d&startIndex=%d&pubStartDate=%s&pubEndDate=%s&hasKev",
			resultsPerPage, startIndex, pubStart, pubEnd,
		)

		for attempt := 1; attempt <= maxRetries; attempt++ {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Printf("Request creation failed: %v", err)
				if attempt == maxRetries {
					return nil, fmt.Errorf("request creation failed after %d attempts: %v", maxRetries, err)
				}
				time.Sleep(retryDelay)
				continue
			}
			if nvdAPIKey := os.Getenv("NVD_API_KEY"); nvdAPIKey != "" {
				req.Header.Add("apiKey", nvdAPIKey)
			}

			resp, err = httpClient.Do(req)
			if err != nil {
				log.Printf("NVD API request failed (attempt %d): %v", attempt, err)
				if attempt < maxRetries {
					time.Sleep(retryDelay)
					continue
				}
				return nil, fmt.Errorf("NVD API request failed after %d attempts: %v", maxRetries, err)
			}

			// Check status code before proceeding
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusNotFound {
					log.Printf("NVD API returned 404 for startIndex %d", startIndex)
					if len(allCVEs) > 0 {
						return allCVEs, nil
					}
					url = fmt.Sprintf(
						"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=%d&startIndex=%d&pubStartDate=2023-01-01T00:00:00.000Z&pubEndDate=%s&hasKev",
						resultsPerPage, startIndex, pubEnd,
					)
					if attempt < maxRetries {
						time.Sleep(retryDelay)
						continue
					}
					return nil, fmt.Errorf("NVD API error: %s, body: %s", resp.Status, string(body))
				}
				if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
					resp.Body.Close()
					log.Printf("NVD API returned %d (attempt %d), retrying after delay", resp.StatusCode, attempt)
					if attempt < maxRetries {
						time.Sleep(retryDelay)
						continue
					}
					return nil, fmt.Errorf("NVD API error: %s, body: %s", resp.Status, string(body))
				}
				resp.Body.Close()
				return nil, fmt.Errorf("NVD API error: %s, body: %s", resp.Status, string(body))
			}
			break // Successful request, exit retry loop
		}

		// Ensure resp is not nil before proceeding
		if resp == nil {
			return nil, fmt.Errorf("no response received after %d attempts", maxRetries)
		}

		defer resp.Body.Close() // Safe to defer now

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		var nvdResp struct {
			ResultsPerPage  int `json:"resultsPerPage"`
			StartIndex      int `json:"startIndex"`
			TotalResults    int `json:"totalResults"`
			Vulnerabilities []struct {
				Cve struct {
					ID           string `json:"id"`
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
					Published string `json:"published"`
					Metrics   struct {
						CvssMetricV31 []struct {
							CvssData struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssData"`
						} `json:"cvssMetricV31"`
					} `json:"metrics"`
					Configurations []struct {
						Nodes []struct {
							CpeMatch []struct {
								Criteria string `json:"criteria"`
							} `json:"cpeMatch"`
						} `json:"nodes"`
					} `json:"configurations"`
					CisaExploitAdd string `json:"cisaExploitAdd"`
				} `json:"cve"`
			} `json:"vulnerabilities"`
		}

		if err := json.Unmarshal(body, &nvdResp); err != nil {
			return nil, fmt.Errorf("JSON decode failed: %v, body: %s", err, string(body))
		}

		for _, vuln := range nvdResp.Vulnerabilities {
			cve := CVE{
				CVEID:     vuln.Cve.ID,
				Published: vuln.Cve.Published[:10],
			}

			for _, desc := range vuln.Cve.Descriptions {
				if desc.Lang == "en" {
					cve.Description = desc.Value
					break
				}
			}
			if cve.Description == "" && len(vuln.Cve.Descriptions) > 0 {
				cve.Description = vuln.Cve.Descriptions[0].Value
			}

			if len(vuln.Cve.Metrics.CvssMetricV31) > 0 {
				cve.CVSS = vuln.Cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
				cve.Severity = cvssToSeverity(cve.CVSS)
			} else {
				cve.CVSS = 0.0
				cve.Severity = "low"
			}

			for _, config := range vuln.Cve.Configurations {
				for _, node := range config.Nodes {
					for _, cpe := range node.CpeMatch {
						parts := strings.Split(cpe.Criteria, ":")
						if len(parts) >= 5 {
							cve.Vendor = strings.ToLower(parts[3])
							cve.Product = parts[4]
							break
						}
					}
					if cve.Vendor != "" {
						break
					}
				}
				if cve.Vendor != "" {
					break
				}
			}
			if cve.Vendor == "" {
				cve.Vendor = "unknown"
				cve.Product = "Unknown Product"
			}

			cve.Status = "none"
			if vuln.Cve.CisaExploitAdd != "" {
				cve.Status = "exploited"
			} else if strings.Contains(strings.ToLower(cve.Description), "proof of concept") || strings.Contains(strings.ToLower(cve.Description), "poc") {
				cve.Status = "poc"
			}

			allCVEs = append(allCVEs, cve)
		}

		if nvdResp.StartIndex+nvdResp.ResultsPerPage >= nvdResp.TotalResults {
			break
		}
		startIndex += nvdResp.ResultsPerPage
	}

	if len(allCVEs) == 0 {
		log.Printf("No CVEs returned from NVD API, returning mock data")
		return mockCVEs, nil
	}

	return allCVEs, nil
}

func cvssToSeverity(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

