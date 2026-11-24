// =============================================================================
// REST API для ИАС БИ — Go
// Компиляция: go build -o api api.go
// Запуск: ./api
// =============================================================================

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"sync"
)

type ScanRequest struct {
	Target string `json:"target"`
}

type Finding struct {
	Source      string  `json:"source"`
	Type        string  `json:"type"`
	Port        int     `json:"port"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	CWE         string  `json:"cwe,omitempty"`
	CVE         string  `json:"cve,omitempty"`
}

type Incident struct {
	Detected        bool      `json:"detected"`
	RiskScore       float64   `json:"risk_score"`
	Category        string    `json:"category"`
	Recommendations []string  `json:"recommendations"`
	Findings        []Finding `json:"findings"`
}

var (
	mu       sync.Mutex
	scans    = make(map[string]Incident)
)

// Запуск Nmap и парсинг
func runNmap(target string) ([]Finding, error) {
	cmd := exec.Command("nmap", "-sV", "-oX", "-", target)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	// Здесь должен быть вызов C++ парсера
	// Для простоты возвращаем заглушку
	_ = output
	return []Finding{
		{Source: "nmap", Type: "service", Port: 22, Severity: "medium", Description: "SSH open"},
	}, nil
}

// Запуск Masscan
func runMasscan(target string) ([]Finding, error) {
	cmd := exec.Command("masscan", "-p1-1000", target, "--rate", "100", "-oJ", "-")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	_ = output
	return []Finding{
		{Source: "masscan", Type: "port", Port: 80, Severity: "low", Description: "HTTP open"},
	}, nil
}

// Запуск Nikto
func runNikto(target string) ([]Finding, error) {
	cmd := exec.Command("nikto", "-h", target, "-o", "-", "-Format", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	_ = output
	return []Finding{
		{Source: "nikto", Type: "vulnerability", Port: 80, Severity: "medium", Description: "Missing X-Frame-Options", CWE: "CWE-1021"},
	}, nil
}

// Обработчик POST /scan
func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Параллельный запуск сканеров
	var wg sync.WaitGroup
	var findings []Finding
	var findingsMu sync.Mutex
	
	scanners := []func(string) ([]Finding, error){runNmap, runMasscan, runNikto}
	for _, scanner := range scanners {
		wg.Add(1)
		go func(s func(string) ([]Finding, error)) {
			defer wg.Done()
			f, err := s(req.Target)
			if err == nil {
				findingsMu.Lock()
				findings = append(findings, f...)
				findingsMu.Unlock()
			}
		}(scanner)
	}
	wg.Wait()
	
	// Оценка инцидента (упрощённо)
	incident := Incident{
		Detected:        false,
		RiskScore:       0,
		Category:        "none",
		Recommendations: []string{},
		Findings:        findings,
	}
	
	for _, f := range findings {
		if f.Severity == "critical" {
			incident.Detected = true
			incident.RiskScore = 9.5
			incident.Category = "critical_vulnerability"
		}
	}
	
	mu.Lock()
	scans[req.Target] = incident
	mu.Unlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(incident)
}

// Обработчик GET /incidents
func incidentsHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func main() {
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/incidents", incidentsHandler)
	
	fmt.Println("API запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
