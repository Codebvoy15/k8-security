package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

//go:embed dashboard.html
var dashboardHTML []byte

// ── DATA STRUCTS ────────────────────────────────────────────────────────────

type AppDetail struct {
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	Image       string   `json:"image"`
	Privileged  bool     `json:"privileged"`
	HostNetwork bool     `json:"hostNetwork"`
	RunAsRoot   bool     `json:"runAsRoot"`
	NoLimits    bool     `json:"noLimits"`
	Issues      []string `json:"issues"`
	RiskScore   int      `json:"riskScore"`
}

type NamespaceSummary struct {
	Name     string      `json:"name"`
	AppCount int         `json:"appCount"`
	Issues   int         `json:"issues"`
	Risk     string      `json:"risk"`
	Apps     []AppDetail `json:"apps"`
}

type NodeInfo struct {
	Name        string `json:"name"`
	Kernel      string `json:"kernel"`
	PatchStatus string `json:"patchStatus"`
	AlgifStatus string `json:"algifStatus"`
	Vulnerable  bool   `json:"vulnerable"`
	NodeType    string `json:"nodeType"`
	Zone        string `json:"zone"`
	IsSpot      bool   `json:"isSpot"`
	Ready       string `json:"ready"`
	RiskScore   int    `json:"riskScore"`
	RiskLevel   string `json:"riskLevel"`
}

type ClusterDetail struct {
	Name       string             `json:"name"`
	Context    string             `json:"context"`
	Region     string             `json:"region"`
	Status     string             `json:"status"`
	Error      string             `json:"error,omitempty"`
	Nodes      []NodeInfo         `json:"nodes"`
	Namespaces []NamespaceSummary `json:"namespaces"`
	NodeCount  int                `json:"nodeCount"`
	Vulnerable int                `json:"vulnerable"`
	PodCount   int                `json:"podCount"`
	NSCount    int                `json:"nsCount"`
	ScannedAt  time.Time          `json:"scannedAt"`
}

type PredictiveThreat struct {
	CVE             string `json:"cve"`
	Component       string `json:"component"`
	Severity        string `json:"severity"`
	ProbabilityPct  int    `json:"probabilityPct"`
	ImpactRadius    string `json:"impactRadius"`
	MitigationState string `json:"mitigationState"`
	Description     string `json:"description"`
}

type FleetData struct {
	Clusters        []ClusterDetail    `json:"clusters"`
	UpcomingThreats []PredictiveThreat `json:"upcomingThreats"`
	TotalClusters   int                `json:"totalClusters"`
	ScannedClusters int                `json:"scannedClusters"`
	FailedClusters  int                `json:"failedClusters"`
	TotalNodes      int                `json:"totalNodes"`
	VulnNodes       int                `json:"vulnNodes"`
	TotalPods       int                `json:"totalPods"`
	ScanInProgress  bool               `json:"scanInProgress"`
	ScanPct         int                `json:"scanPct"`
	LastScan        time.Time          `json:"lastScan"`
	ScanAge         string             `json:"scanAge"`
}

// ── STATE ORCHESTRATION ──────────────────────────────────────────────────────

var (
	mu    sync.RWMutex
	fleet FleetData
)

func main() {
	// Execute background polling manager loop
	go backgroundDiscoveryOrchestrator()

	// High-Performance Stream Endpoints
	setupRoutes := func(prefix string) {
		http.HandleFunc(prefix+"api/data", handleData)
		http.HandleFunc(prefix+"api/refresh", handleRefresh)
		http.HandleFunc(prefix, handleDashboard)
	}

	setupRoutes("/")
	setupRoutes("/pdks/")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("[CONTROL PLANE] FAANG-Grade PDKS Engine serving on http://localhost:%s", port)
	if err := http.ListenAndServe("0.0.0.0:"+port, nil); err != nil {
		log.Fatalf("[FATAL] Core proxy bind crash: %v", err)
	}
}

func handleData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	mu.RLock()
	defer mu.RUnlock()
	json.NewEncoder(w).Encode(fleet)
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	go runFleetScan()
	json.NewEncoder(w).Encode(map[string]string{"status": "SCAN_INITIALIZED"})
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(dashboardHTML)
}

func backgroundDiscoveryOrchestrator() {
	runFleetScan()
	ticker := time.NewTicker(4 * time.Minute)
	for range ticker.C {
		runFleetScan()
	}
}

// ── ASYNC FLEET EXPLORATION ENGINE ───────────────────────────────────────────

func runFleetScan() {
	mu.Lock()
	if fleet.ScanInProgress {
		mu.Unlock()
		return
	}
	fleet.ScanInProgress = true
	fleet.ScanPct = 0
	mu.Unlock()

	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	if envKc := os.Getenv("KUBECONFIG"); envKc != "" {
		kubeconfigPath = envKc
	}

	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		log.Printf("[CRITICAL] Configuration load fault: %v", err)
		mu.Lock()
		fleet.ScanInProgress = false
		mu.Unlock()
		return
	}

	var contexts []string
	for ctxName := range config.Contexts {
		contexts = append(contexts, ctxName)
	}
	sort.Strings(contexts)

	total := len(contexts)
	type chanResult struct{ detail ClusterDetail }
	resultCh := make(chan chanResult, total)
	workerPoolThrottle := make(chan struct{}, 15) // Throttled concurrency matrix

	for _, ctxName := range contexts {
		go func(targetCtx string) {
			workerPoolThrottle <- struct{}{}
			defer func() { <-workerPoolThrottle }()
			resultCh <- chanResult{detail: scanSingleContext(kubeconfigPath, targetCtx)}
		}(ctxName)
	}

	var collected []ClusterDetail
	done, okCount, failCount := 0, 0, 0
	totalNodes, vulnNodes, totalPods := 0, 0, 0

	for done < total {
		res := <-resultCh
		done++
		collected = append(collected, res.detail)

		if res.detail.Status == "ok" {
			okCount++
			totalNodes += res.detail.NodeCount
			vulnNodes += res.detail.Vulnerable
			totalPods += res.detail.PodCount
		} else {
			failCount++
		}

		pct := (done * 100) / total

		sort.Slice(collected, func(i, j int) bool {
			if collected[i].Vulnerable != collected[j].Vulnerable {
				return collected[i].Vulnerable > collected[j].Vulnerable
			}
			return collected[i].Name < collected[j].Name
		})

		mu.Lock()
		fleet = FleetData{
			Clusters:        collected,
			UpcomingThreats: getPredictiveThreatIntelligence(),
			TotalClusters:   total,
			ScannedClusters: okCount,
			FailedClusters:  failCount,
			TotalNodes:      totalNodes,
			VulnNodes:       vulnNodes,
			TotalPods:       totalPods,
			ScanInProgress:  done < total,
			ScanPct:         pct,
			LastScan:        time.Now(),
			ScanAge:         "just now",
		}
		mu.Unlock()
	}
}

func scanSingleContext(kubeconfigPath, contextName string) ClusterDetail {
	tokens := strings.Split(contextName, "/")
	name := tokens[len(tokens)-1]

	region := "us-east-1"
	arnTokens := strings.Split(contextName, ":")
	if len(arnTokens) >= 4 && strings.HasPrefix(contextName, "arn:aws:eks:") {
		region = arnTokens[3]
	}

	detail := ClusterDetail{
		Name: name, Context: contextName, Region: region, ScannedAt: time.Now(), Status: "ok",
	}

	clientConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	).ClientConfig()

	if err != nil {
		detail.Status = "error"
		detail.Error = err.Error()
		return detail
	}
	clientConfig.Timeout = 10 * time.Second

	cs, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		detail.Status = "error"
		detail.Error = err.Error()
		return detail
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	// Parse Infrastructure Compute Nodes
	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		detail.Status = "error"
		detail.Error = err.Error()
		return detail
	}

	//clusterIsVulnerable := false
	// Your loop block (around line 300) should look exactly like this:
	for _, node := range nodeList.Items {
		ready := "Unknown"
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" {
				ready = string(condition.Status)
			}
		}

		patched, algif, patchStatus := assessKernel(node.Status.NodeInfo.KernelVersion, node.Labels)
		score := 15
		if !patched {
			score += 55
			// Removed the "clusterIsVulnerable = true" line completely from here
		}
		if algif == "loaded" {
			score += 25
		}

		// ... remainder of node mapping assignment logic follows exactly the same

		detail.Nodes = append(detail.Nodes, NodeInfo{
			Name:        node.Name,
			Kernel:      node.Status.NodeInfo.KernelVersion,
			PatchStatus: patchStatus,
			AlgifStatus: algif,
			Vulnerable:  !patched,
			NodeType:    node.Labels["node.kubernetes.io/instance-type"],
			Zone:        node.Labels["topology.kubernetes.io/zone"],
			IsSpot:      node.Labels["eks.amazonaws.com/capacityType"] == "SPOT" || node.Labels["karpenter.sh/capacity-type"] == "spot",
			Ready:       ready,
			RiskScore:   score,
			RiskLevel:   nodeRisk(score),
		})
		detail.NodeCount++
		if !patched {
			detail.Vulnerable++
		}
	}

	// Parse Namespace Workload Inferences
	podList, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err == nil {
		detail.PodCount = len(podList.Items)
		nsMap := map[string]*NamespaceSummary{}

		for _, pod := range podList.Items {
			if pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
				continue
			}
			ns := pod.Namespace
			if nsMap[ns] == nil {
				nsMap[ns] = &NamespaceSummary{Name: ns, Apps: []AppDetail{}}
			}
			nsMap[ns].AppCount++

			app := AppDetail{Name: pod.Name, Namespace: ns, Issues: []string{}}
			if len(pod.Spec.Containers) > 0 {
				app.Image = pod.Spec.Containers[0].Image
			}
			app.HostNetwork = pod.Spec.HostNetwork

			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil {
					if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
						app.Privileged = true
					}
					if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
						app.RunAsRoot = true
					}
				}
				if container.Resources.Limits == nil || len(container.Resources.Limits) == 0 {
					app.NoLimits = true
				}
			}

			if app.Privileged {
				app.Issues = append(app.Issues, "privileged")
				app.RiskScore += 40
			}
			if app.HostNetwork {
				app.Issues = append(app.Issues, "hostNetwork")
				app.RiskScore += 25
			}
			if app.RunAsRoot {
				app.Issues = append(app.Issues, "runAsRoot")
				app.RiskScore += 15
			}
			if app.NoLimits {
				app.Issues = append(app.Issues, "noLimits")
				app.RiskScore += 10
			}

			if len(app.Issues) > 0 {
				nsMap[ns].Issues++
				nsMap[ns].Apps = append(nsMap[ns].Apps, app)
			}
		}

		for _, nsSummary := range nsMap {
			switch {
			case nsSummary.Issues > 8:
				nsSummary.Risk = "critical"
			case nsSummary.Issues > 3:
				nsSummary.Risk = "high"
			case nsSummary.Issues > 0:
				nsSummary.Risk = "medium"
			default:
				nsSummary.Risk = "low"
			}
			sort.Slice(nsSummary.Apps, func(i, j int) bool {
				return nsSummary.Apps[i].RiskScore > nsSummary.Apps[j].RiskScore
			})
			detail.Namespaces = append(detail.Namespaces, *nsSummary)
		}

		sort.Slice(detail.Namespaces, func(i, j int) bool {
			return detail.Namespaces[i].Issues > detail.Namespaces[j].Issues
		})
		detail.NSCount = len(detail.Namespaces)
	}

	return detail
}

func assessKernel(kernel string, labels map[string]string) (bool, string, string) {
	if !strings.Contains(kernel, "amzn2023") {
		return true, "n/a", "non-al2023"
	}
	parts := strings.Split(strings.Split(kernel, "-")[0], ".")
	if len(parts) < 3 {
		return false, "unknown", "unknown"
	}
	var major, minor, patch int
	fmt.Sscanf(parts[0], "%d", &major)
	fmt.Sscanf(parts[1], "%d", &minor)
	fmt.Sscanf(parts[2], "%d", &patch)
	if major == 6 && minor == 1 && patch >= 141 {
		return true, "blocked", "patched"
	}
	return false, "loaded", "unpatched"
}

func nodeRisk(score int) string {
	if score >= 65 {
		return "critical"
	}
	if score >= 40 {
		return "high"
	}
	if score >= 20 {
		return "medium"
	}
	return "low"
}

func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Change this function near the bottom of your main.go
func getPredictiveThreatIntelligence() []PredictiveThreat {
	return []PredictiveThreat{ // <-- Fix this from EarlyDisclosureThreat to PredictiveThreat
		{CVE: "CVE-2026-31431", Component: "kernel-amzn (AL2023)", Severity: "CRITICAL", ProbabilityPct: 94, ImpactRadius: "Fleet Compute Nodes", MitigationState: "MitigationDS Deployable", Description: "Unprivileged user can write to read-only page cache corrupting SUID binaries in memory via 4 crypto system calls to escape namespaces."},
		// ... keep the rest of the array values the same
	}
}
