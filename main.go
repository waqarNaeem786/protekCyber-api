package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"
)

// CVE represents the structure expected by the frontend CVE Tracker
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

// Cache for CVE data
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
}

// Threat represents the frontend-expected structure
type Pulse struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Tags            []string `json:"tags"`
	IndicatorCount  int      `json:"indicator_count"`
	Adversary       string   `json:"adversary"`
	MalwareFamilies []string `json:"malware_families"`
	Created         string   `json:"created"`
}

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

// OTXResponse mirrors AlienVault's API structure
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
		References []string `json:"references"`
	} `json:"results"`
}

var (
	otxAPIKey  = os.Getenv("OTX_API_KEY")
	httpClient = &http.Client{Timeout: 10 * time.Second}
	cache      = struct {
		data      []Threat
		timestamp time.Time
	}{}
	explorerCache = struct {
		data      map[string]map[string]interface{}
		timestamp time.Time
	}{data: make(map[string]map[string]interface{})}
)

func main() {
	http.HandleFunc("/api/threats", threatsHandler)
	http.HandleFunc("/health", healthCheck)
	http.HandleFunc("/api/threat-explorer/", threatExplorerHandler)
	http.HandleFunc("/api/cves", cvesHandler)
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

func threatsHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if time.Since(cache.timestamp) > time.Hour {
		if newThreats, err := fetchOTXThreats(); err == nil {
			cache.data = newThreats
			cache.timestamp = time.Now()
		}
	}

	if time.Since(cache.timestamp) < 5*time.Minute && len(cache.data) > 0 {
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

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func threatExplorerHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	category := strings.TrimPrefix(r.URL.Path, "/api/threat-explorer/")

	if time.Since(explorerCache.timestamp) < 5*time.Minute {
		if cachedData, exists := explorerCache.data[category]; exists {
			jsonResponse(w, cachedData)
			return
		}
	}

	data := getThreatData(category)
	explorerCache.data[category] = data
	explorerCache.timestamp = time.Now()
	jsonResponse(w, data)
}

func getThreatData(category string) map[string]interface{} {
	tagMapping := map[string]string{
		"malware":         "ransomware",
		"phishing":        "phishing",
		"vulnerabilities": "vulnerability",
		"apt":             "apt",
		"emerging":        "emerging",
	}

	otxTag := tagMapping[category]
	if otxTag == "" {
		otxTag = category
	}

	if otxAPIKey == "" {
		log.Println("Error: OTX_API_KEY environment variable not set")
		return getFallbackData(category)
	}

	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://otx.alienvault.com/api/v1/pulses/subscribed?tags=%s&limit=5", otxTag),
		nil)
	if err != nil {
		log.Printf("Error creating OTX request: %v", err)
		return getFallbackData(category)
	}
	req.Header.Add("X-OTX-API-KEY", otxAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("OTX API request failed: %v", err)
		return getFallbackData(category)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("OTX API error: %s", resp.Status)
		return getFallbackData(category)
	}

	var result struct {
		Results []Pulse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("JSON decode error: %v", err)
		return getFallbackData(category)
	}

	if len(result.Results) == 0 {
		log.Printf("No results for category %s", category)
		return getFallbackData(category)
	}

	// Process top groups
	maxValue := 1000.0 // Adjust based on expected max IndicatorCount
	topGroups := make([]map[string]interface{}, 0)
	knownRansomware := map[string]int{
		"Secp0":            80, // Hardcoded for demo; replace with OTX data or external source
		"Rainbow Hyena":    60,
		"Octalyn Stealer":  40,
		"Konfety":          50,
		"AsyncRAT - S1087": 30,
	}

	if category == "malware" || category == "apt" || category == "phishing" || category == "emerging" || category == "vulnerabilities" {
		for name, value := range knownRansomware {
			topGroups = append(topGroups, map[string]interface{}{
				"name":  name,
				"value": value,
			})
		}
	} else {
		for _, pulse := range result.Results {
			groupName := pulse.Name
			if pulse.Adversary != "" {
				groupName = pulse.Adversary
			} else if len(pulse.MalwareFamilies) > 0 {
				groupName = pulse.MalwareFamilies[0]
			}

			value := float64(pulse.IndicatorCount)
			if value == 0 {
				createdTime, err := time.Parse("2006-01-02T15:04:05.999999", pulse.Created)
				if err == nil {
					value = time.Since(createdTime).Hours() / 24
				} else {
					value = 30
				}
			}
			normalizedValue := int(math.Min(value*100/maxValue, 100))

			topGroups = append(topGroups, map[string]interface{}{
				"name":  groupName,
				"value": normalizedValue,
			})

			if len(topGroups) >= 5 {
				break
			}
		}
	}

	// Get trends description
	var trends string
	if len(result.Results) > 0 {
		trends = result.Results[0].Description
		if trends == "" {
			trends = fmt.Sprintf("Recent activity involving %s. %d indicators observed.",
				strings.Join(result.Results[0].Tags, ", "),
				result.Results[0].IndicatorCount)
		}
	} else {
		trends = fmt.Sprintf("Current trends in %s threats. Monitoring ongoing.", category)
	}

	// Generate stats based on category
	var stats []string
	switch category {
	case "malware":
		stats = []string{
			fmt.Sprintf("%d incidents", len(result.Results)),
			getMostCommonTag(result.Results),
			fmt.Sprintf("%d avg indicators", getAverageIndicators(result.Results)),
			getNewestPulseDate(result.Results),
		}
	case "phishing":
		stats = []string{
			fmt.Sprintf("%.1f%% click rate", float64(getAverageIndicators(result.Results))/10),
			getMostCommonTag(result.Results),
			fmt.Sprintf("%d incidents", len(result.Results)),
			getNewestPulseDate(result.Results),
		}
	case "vulnerabilities":
		stats = []string{
			fmt.Sprintf("%d incidents", len(result.Results)),
			getMostCommonTag(result.Results),
			fmt.Sprintf("%d avg indicators", getAverageIndicators(result.Results)),
			getNewestPulseDate(result.Results),
		}
	case "apt":
		stats = []string{
			fmt.Sprintf("%d incidents", len(result.Results)),
			getMostCommonTag(result.Results),
			fmt.Sprintf("%d avg indicators", getAverageIndicators(result.Results)),
			getNewestPulseDate(result.Results),
		}
	case "emerging":
		stats = []string{
			fmt.Sprintf("%d incidents", len(result.Results)),
			getMostCommonTag(result.Results),
			fmt.Sprintf("%d avg indicators", getAverageIndicators(result.Results)),
			getNewestPulseDate(result.Results),
		}
	default:
		stats = []string{
			fmt.Sprintf("%d incidents", len(result.Results)),
			getMostCommonTag(result.Results),
			fmt.Sprintf("%d avg indicators", getAverageIndicators(result.Results)),
			getNewestPulseDate(result.Results),
		}
	}

	// Get emerging items
	emerging := getEmergingItems(result.Results, otxTag)

	return map[string]interface{}{
		"topGroups": topGroups,
		"trends":    trends,
		"stats":     stats,
		"emerging":  emerging,
		"title":     time.Now().Format("January 2006"),
	}
}

func getMostCommonTag(pulses []Pulse) string {
	tagCount := make(map[string]int)
	for _, pulse := range pulses {
		for _, tag := range pulse.Tags {
			tagCount[tag]++
		}
	}

	maxCount := 0
	commonTag := ""
	for tag, count := range tagCount {
		if count > maxCount {
			maxCount = count
			commonTag = tag
		}
	}

	if commonTag != "" {
		return commonTag
	}
	return "Various"
}

func getAverageIndicators(pulses []Pulse) int {
	if len(pulses) == 0 {
		return 0
	}

	total := 0
	for _, pulse := range pulses {
		total += pulse.IndicatorCount
	}
	return total / len(pulses)
}

func getNewestPulseDate(pulses []Pulse) string {
	if len(pulses) == 0 {
		return "No recent data"
	}

	newest := pulses[0].Created
	for _, pulse := range pulses {
		if pulse.Created > newest {
			newest = pulse.Created
		}
	}

	return newest[:10] // Simplified to return YYYY-MM-DD
}

func getEmergingItems(pulses []Pulse, mainTag string) []string {
	uniqueTags := make(map[string]bool)
	for _, pulse := range pulses {
		for _, tag := range pulse.Tags {
			if !strings.EqualFold(tag, mainTag) {
				uniqueTags[tag] = true
			}
		}
	}

	items := make([]string, 0, len(uniqueTags))
	for tag := range uniqueTags {
		items = append(items, tag)
	}

	if len(items) > 4 {
		items = items[:4]
	}

	genericItems := []string{"New variants", "Zero-day exploits", "Evasion techniques", "Cloud targeting"}
	for i := len(items); i < 4; i++ {
		items = append(items, genericItems[i%len(genericItems)])
	}

	return items
}

func getFallbackData(category string) map[string]interface{} {
	return map[string]interface{}{
		"topGroups": []map[string]interface{}{
			{"name": " " + category, "value": 50},
			{"name": " " + category, "value": 30},
		},
		"trends": "Showing fallback data for " + category,
		"stats": []string{
			"0 incidents",
			"Various",
			"0 avg indicators",
			"No recent data",
		},
		"emerging": []string{
			"New variants",
			"Zero-day exploits",
			"Evasion techniques",
			"Cloud targeting",
		},
		"title": time.Now().Format("January 2006"),
	}
}

func cvesHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return cached data if fresh (within 24 hours)
	if time.Since(cveCache.timestamp) < 24*time.Hour && len(cveCache.data) > 0 {
		jsonResponse(w, cveCache.data)
		return
	}

	// Fetch new CVE data from NVD
	cves, err := fetchNVDCVEs()
	if err != nil {
		log.Printf("NVD fetch failed: %v", err)
		if len(cveCache.data) > 0 {
			jsonResponse(w, cveCache.data) // Fallback to cache
			return
		}
		jsonResponse(w, mockCVEs) // Fallback to mock data
		return
	}

	// Update cache
	cveCache.data = cves
	cveCache.timestamp = time.Now()
	jsonResponse(w, cves)
}

// fetchNVDCVEs fetches CVE data from NVD with pagination and retries
func fetchNVDCVEs() ([]CVE, error) {
	const maxRetries = 3
	const retryDelay = 6 * time.Second // Respect NVD rate limit (5 req/30s without API key)
	const resultsPerPage = 10
	startIndex := 0
	var allCVEs []CVE

	// Calculate valid date range (within 120 days, ending at current date)
	endDate := time.Now().UTC()
	startDate := endDate.AddDate(0, 0, -119) // 120-day limit
	pubStart := startDate.Format("2006-01-02T15:04:05.000Z")
	pubEnd := endDate.Format("2006-01-02T15:04:05.000Z")

	for {
		// Construct URL with valid parameters
		url := fmt.Sprintf(
			"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=%d&startIndex=%d&pubStartDate=%s&pubEndDate=%s&hasKev",
			resultsPerPage, startIndex, pubStart, pubEnd,
		)

		var resp *http.Response
		var err error

		// Retry logic
		for attempt := 1; attempt <= maxRetries; attempt++ {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return nil, fmt.Errorf("request creation failed: %v", err)
			}

			// Add NVD API key if available
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

			// Handle non-200 status
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusNotFound {
					log.Printf("NVD API returned 404 for startIndex %d", startIndex)
					if len(allCVEs) > 0 {
						return allCVEs, nil // Return what we have
					}
					// Try broader date range (e.g., last year)
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
					return nil, fmt.Errorf("NVD API error: %s", resp.Status)
				}
				resp.Body.Close()
				return nil, fmt.Errorf("NVD API error: %s, body: %s", resp.Status, string(body))
			}
			break
		}

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		// Parse NVD response
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

		// Transform NVD data to CVE struct
		for _, vuln := range nvdResp.Vulnerabilities {
			cve := CVE{
				CVEID:     vuln.Cve.ID,
				Published: vuln.Cve.Published[:10], // YYYY-MM-DD
			}

			// Description
			for _, desc := range vuln.Cve.Descriptions {
				if desc.Lang == "en" {
					cve.Description = desc.Value
					break
				}
			}
			if cve.Description == "" && len(vuln.Cve.Descriptions) > 0 {
				cve.Description = vuln.Cve.Descriptions[0].Value
			}

			// CVSS and Severity
			if len(vuln.Cve.Metrics.CvssMetricV31) > 0 {
				cve.CVSS = vuln.Cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
				cve.Severity = cvssToSeverity(cve.CVSS)
			} else {
				cve.CVSS = 0.0
				cve.Severity = "low"
			}

			// Vendor and Product from CPE
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

			// Status (use hasKev for exploited status)
			cve.Status = "none"
			if vuln.Cve.CisaExploitAdd != "" {
				cve.Status = "exploited"
			} else if strings.Contains(strings.ToLower(cve.Description), "proof of concept") || strings.Contains(strings.ToLower(cve.Description), "poc") {
				cve.Status = "poc"
			}

			allCVEs = append(allCVEs, cve)
		}

		// Check if more results exist
		if nvdResp.StartIndex+nvdResp.ResultsPerPage >= nvdResp.TotalResults {
			break
		}
		startIndex += nvdResp.ResultsPerPage
	}

	if len(allCVEs) == 0 {
		return nil, fmt.Errorf("no CVEs returned from NVD API")
	}

	return allCVEs, nil
}

// cvssToSeverity maps CVSS score to severity
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
