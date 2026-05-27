package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

//go:embed dashboard.html
var dashboardHTML []byte

// --- STRUCTS (The complete model set) ---
type Vulnerability struct {
	Name     string `json:"name"`
	Released string `json:"released"`
	Severity string `json:"severity"`
}

type NodeInfo struct {
	Name        string `json:"name"`
	Kernel      string `json:"kernel"`
	PatchStatus string `json:"patchStatus"`
	Vulnerable  bool   `json:"vulnerable"`
}

type ClusterDetail struct {
	Name       string     `json:"name"`
	Context    string     `json:"context"`
	Region     string     `json:"region"`
	Status     string     `json:"status"`
	NodeCount  int        `json:"nodeCount"`
	Vulnerable int        `json:"vulnerable"`
	Nodes      []NodeInfo `json:"nodes"`
}

type FleetAggregate struct {
	SecurityScore     int             `json:"securityScore"`
	UnpatchedCVEs     int             `json:"unpatchedCVEs"`
	CISLinuxPercent   int             `json:"cisLinuxPct"`
	CISEKSPercent     int             `json:"cisEksPct"`
	AgentCoverage     string          `json:"agentCoverage"`
	VulnerabilityList []Vulnerability `json:"vulnerabilityList"`
	Clusters          []ClusterDetail `json:"clusters"`
}

var (
	mu    sync.RWMutex
	fleet FleetAggregate
)

// --- MAIN ENGINE ---
func main() {
	// 1. Initialize Fleet State (Hardcoded mock-data for visual parity)
	fleet = FleetAggregate{
		SecurityScore: 82, UnpatchedCVEs: 12, CISLinuxPercent: 12, CISEKSPercent: 48,
		AgentCoverage: "705/170+",
		VulnerabilityList: []Vulnerability{
			{"CVE-2026-32280", "a month ago", "CRITICAL"},
			{"CVE-2026-32283", "a month ago", "CRITICAL"},
			{"CVE-2025-68121", "4 months ago", "HIGH"},
		},
	}

	// 2. HTTP Routes
	http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		json.NewEncoder(w).Encode(fleet)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(dashboardHTML)
	})

	log.Println("PDKS Intelligence Plane Active: http://localhost:8080")
	go runDiscoveryCycle() // Start background cluster polling
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func runDiscoveryCycle() {
	// This would contain your logic from the previous iteration
	// that populates fleet.Clusters by scanning kubeconfigs
}
