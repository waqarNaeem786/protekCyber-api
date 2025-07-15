package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Threat represents the frontend-expected structure
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
)

func main() {
	http.HandleFunc("/api/threats", threatsHandler)
	http.HandleFunc("/health", healthCheck)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server running on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func enableCORS(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:6969") // Your frontend origin
	(*w).Header().Set("Access-Control-Allow-Methods", "GET")
}

func threatsHandler(w http.ResponseWriter, r *http.Request) {
	// Handle CORS preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	enableCORS(&w)

	// Refresh data if cache is stale (>1 hour old)
	if time.Since(cache.timestamp) > time.Hour {
		if newThreats, err := fetchOTXThreats(); err == nil {
			cache.data = newThreats
			cache.timestamp = time.Now()
		}
	}

	// Serve from cache if fresh (<5 minutes)
	if time.Since(cache.timestamp) < 5*time.Minute && len(cache.data) > 0 {
		jsonResponse(w, cache.data)
		return
	}

	// Fallback to forced refresh if cache is empty/stale
	threats, err := fetchOTXThreats()
	if err != nil {
		log.Printf("OTX fetch failed: %v", err)
		if len(cache.data) > 0 {
			jsonResponse(w, cache.data) // Serve stale cache
			return
		}
		http.Error(w, "Threat data unavailable", http.StatusServiceUnavailable)
		return
	}

	// Update cache and return fresh data
	cache.data = threats
	cache.timestamp = time.Now()
	jsonResponse(w, threats)
}

func fetchOTXThreats() ([]Threat, error) {
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

	// Debug: Print raw response (remove in production)
	body, _ := io.ReadAll(resp.Body)
	log.Printf("OTX API Response: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTX API error: %s", resp.Status)
	}

	var otxResp OTXResponse
	if err := json.Unmarshal(body, &otxResp); err != nil {
		return nil, fmt.Errorf("JSON decode failed: %v", err)
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

		// Determine type and severity from tags
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
	w.Header().Set("Cache-Control", "public, max-age=300") // 5 min browser cache
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("JSON encode error: %v", err)
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
