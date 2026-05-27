package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

//go:embed dashboard.html
var dashboardHTML []byte

// ── MODELS ───────────────────────────────────────────────────────────────────

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

type FleetData struct {
	Clusters        []ClusterDetail `json:"clusters"`
	TotalClusters   int             `json:"totalClusters"`
	ScannedClusters int             `json:"scannedClusters"`
	FailedClusters  int             `json:"failedClusters"`
	TotalNodes      int             `json:"totalNodes"`
	VulnNodes       int             `json:"vulnNodes"`
	TotalPods       int             `json:"totalPods"`
	ScanInProgress  bool            `json:"scanInProgress"`
	ScanPct         int             `json:"scanPct"`
	LastScan        time.Time       `json:"lastScan"`
	ScanAge         string          `json:"scanAge"`
}

// ── STATE ─────────────────────────────────────────────────────────────────────

var (
	mu       sync.RWMutex
	fleet    FleetData
	scanning bool
)

// ── HELPERS ───────────────────────────────────────────────────────────────────

func clusterName(ctx string) string {
	if strings.Contains(ctx, "/") {
		p := strings.Split(ctx, "/")
		return p[len(p)-1]
	}
	return ctx
}

func regionFromCtx(ctx string) string {
	p := strings.Split(ctx, ":")
	if len(p) >= 4 && strings.HasPrefix(ctx, "arn:aws:eks:") {
		return p[3]
	}
	return ""
}

func assessKernel(kernel string, labels map[string]string) (patched bool, algif string, status string) {
	if v := labels["security.pfizer.com/algif-aead-status"]; v != "" {
		algif = v
		patched = v == "blocked"
		if patched {
			status = "patched"
		} else {
			status = "unpatched"
		}
		return
	}
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
	} else if score >= 40 {
		return "high"
	} else if score >= 20 {
		return "medium"
	}
	return "low"
}

func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "Token has expired"), strings.Contains(msg, "token has expired"):
		return "SSO token expired"
	case strings.Contains(msg, "Unauthorized"), strings.Contains(msg, "401"):
		return "Unauthorized"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "Timed out (25s)"
	case strings.Contains(msg, "connection refused"):
		return "Connection refused"
	case strings.Contains(msg, "exit status 1"):
		return "SSO token expired"
	default:
		if len(msg) > 80 {
			return msg[:80] + "..."
		}
		return msg
	}
}

// ── SCAN ONE CLUSTER ──────────────────────────────────────────────────────────

func scanCluster(kubeconfigPath, contextName string) ClusterDetail {
	name := clusterName(contextName)
	region := regionFromCtx(contextName)
	detail := ClusterDetail{
		Name: name, Context: contextName, Region: region, ScannedAt: time.Now(),
	}

	// Try client-go first
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules,
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	).ClientConfig()

	if err != nil {
		return scanViaKubectl(kubeconfigPath, contextName, name, region)
	}
	restCfg.Timeout = 20 * time.Second

	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return scanViaKubectl(kubeconfigPath, contextName, name, region)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ── Nodes ──
	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return scanViaKubectl(kubeconfigPath, contextName, name, region)
	}

	for _, n := range nodeList.Items {
		labels := n.Labels
		info := n.Status.NodeInfo
		ready := "Unknown"
		for _, c := range n.Status.Conditions {
			if string(c.Type) == "Ready" {
				ready = string(c.Status)
			}
		}
		patched, algif, status := assessKernel(info.KernelVersion, labels)
		score := 0
		if !patched {
			score += 65
		}
		if algif == "loaded" {
			score += 25
		}
		if score > 99 {
			score = 99
		}
		detail.Nodes = append(detail.Nodes, NodeInfo{
			Name: n.Name, Kernel: info.KernelVersion,
			PatchStatus: status, AlgifStatus: algif, Vulnerable: !patched,
			NodeType: labels["node.kubernetes.io/instance-type"],
			Zone:     labels["topology.kubernetes.io/zone"],
			IsSpot:   labels["eks.amazonaws.com/capacityType"] == "SPOT",
			Ready: ready, RiskScore: score, RiskLevel: nodeRisk(score),
		})
		detail.NodeCount++
		if !patched {
			detail.Vulnerable++
		}
	}

	// ── Pods → Namespace summary ──
	podList, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err == nil {
		detail.PodCount = len(podList.Items)
		nsMap := map[string]*NamespaceSummary{}

		for _, pod := range podList.Items {
			ns := pod.Namespace
			if nsMap[ns] == nil {
				nsMap[ns] = &NamespaceSummary{Name: ns}
			}
			nsMap[ns].AppCount++

			app := AppDetail{Name: pod.Name, Namespace: ns}
			if len(pod.Spec.Containers) > 0 {
				img := pod.Spec.Containers[0].Image
				// Trim long image names
				if idx := strings.LastIndex(img, "/"); idx >= 0 {
					img = img[idx+1:]
				}
				app.Image = img
			}
			app.HostNetwork = pod.Spec.HostNetwork

			for _, c := range pod.Spec.Containers {
				if c.SecurityContext != nil {
					if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
						app.Privileged = true
					}
					if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
						app.RunAsRoot = true
					}
				}
				if c.Resources.Limits == nil || len(c.Resources.Limits) == 0 {
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
				app.RiskScore += 5
			}

			if len(app.Issues) > 0 {
				nsMap[ns].Issues++
				nsMap[ns].Apps = append(nsMap[ns].Apps, app)
			}
		}

		for _, ns := range nsMap {
			if ns.AppCount == 0 {
				continue
			}
			switch {
			case ns.Issues > 5:
				ns.Risk = "critical"
			case ns.Issues > 2:
				ns.Risk = "high"
			case ns.Issues > 0:
				ns.Risk = "medium"
			default:
				ns.Risk = "low"
			}
			// Sort apps by risk
			sort.Slice(ns.Apps, func(i, j int) bool {
				return ns.Apps[i].RiskScore > ns.Apps[j].RiskScore
			})
			detail.Namespaces = append(detail.Namespaces, *ns)
		}
		sort.Slice(detail.Namespaces, func(i, j int) bool {
			return detail.Namespaces[i].Issues > detail.Namespaces[j].Issues
		})
		detail.NSCount = len(detail.Namespaces)
	}

	detail.Status = "ok"
	log.Printf("[SCAN] ✓ %s: nodes=%d vuln=%d pods=%d ns=%d",
		name, detail.NodeCount, detail.Vulnerable, detail.PodCount, detail.NSCount)
	return detail
}

func scanViaKubectl(kubeconfigPath, contextName, name, region string) ClusterDetail {
	detail := ClusterDetail{
		Name: name, Context: contextName, Region: region, ScannedAt: time.Now(),
	}
	args := []string{"--context=" + contextName, "get", "nodes", "-o", "json"}
	cmd := exec.Command("kubectl", args...)
	cmd.Env = os.Environ()
	var stderr strings.Builder
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		detail.Status = "error"
		detail.Error = classifyErr(err)
		return detail
	}

	var raw struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				NodeInfo   struct{ KernelVersion string `json:"kernelVersion"` } `json:"nodeInfo"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		detail.Status = "error"
		detail.Error = "parse error"
		return detail
	}
	for _, item := range raw.Items {
		labels := item.Metadata.Labels
		ready := "Unknown"
		for _, c := range item.Status.Conditions {
			if c.Type == "Ready" {
				ready = c.Status
			}
		}
		patched, algif, status := assessKernel(item.Status.NodeInfo.KernelVersion, labels)
		score := 0
		if !patched {
			score += 65
		}
		if algif == "loaded" {
			score += 25
		}
		detail.Nodes = append(detail.Nodes, NodeInfo{
			Name: item.Metadata.Name, Kernel: item.Status.NodeInfo.KernelVersion,
			PatchStatus: status, AlgifStatus: algif, Vulnerable: !patched,
			NodeType: labels["node.kubernetes.io/instance-type"],
			Zone:     labels["topology.kubernetes.io/zone"],
			IsSpot:   labels["eks.amazonaws.com/capacityType"] == "SPOT",
			Ready: ready, RiskScore: score, RiskLevel: nodeRisk(score),
		})
		detail.NodeCount++
		if !patched {
			detail.Vulnerable++
		}
	}
	detail.Status = "ok"
	return detail
}

// ── FLEET SCAN ────────────────────────────────────────────────────────────────

func getAllContexts(kubeconfigPath string) ([]string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	cfg, err := rules.Load()
	if err != nil {
		return nil, err
	}
	var ctxs []string
	for n := range cfg.Contexts {
		ctxs = append(ctxs, n)
	}
	sort.Strings(ctxs)
	return ctxs, nil
}

func runFleetScan() {
	mu.Lock()
	if scanning {
		mu.Unlock()
		return
	}
	scanning = true
	fleet.ScanInProgress = true
	fleet.ScanPct = 0
	mu.Unlock()

	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		home, _ := os.UserHomeDir()
		kc = home + "/.kube/config"
	}

	contexts, err := getAllContexts(kc)
	if err != nil {
		log.Printf("[SCAN] kubeconfig error: %v", err)
		mu.Lock()
		scanning = false
		fleet.ScanInProgress = false
		mu.Unlock()
		return
	}

	total := len(contexts)
	log.Printf("[SCAN] Starting — %d clusters", total)

	type result struct{ detail ClusterDetail }
	resultCh := make(chan result, total)
	sem := make(chan struct{}, 10)

	for _, ctx := range contexts {
		go func(c string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			resultCh <- result{detail: scanCluster(kc, c)}
		}(ctx)
	}

	var clusters []ClusterDetail
	done, okCount, failCount := 0, 0, 0
	totalNodes, vulnNodes, totalPods := 0, 0, 0

	for done < total {
		r := <-resultCh
		done++
		clusters = append(clusters, r.detail)

		if r.detail.Status == "ok" {
			okCount++
			totalNodes += r.detail.NodeCount
			vulnNodes += r.detail.Vulnerable
			totalPods += r.detail.PodCount
		} else {
			failCount++
		}

		pct := done * 100 / total

		// Sort: most vulnerable first, then errors, then by name
		sorted := make([]ClusterDetail, len(clusters))
		copy(sorted, clusters)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Vulnerable != sorted[j].Vulnerable {
				return sorted[i].Vulnerable > sorted[j].Vulnerable
			}
			if sorted[i].Status != sorted[j].Status {
				return sorted[i].Status == "ok"
			}
			return sorted[i].Name < sorted[j].Name
		})

		mu.Lock()
		fleet = FleetData{
			Clusters:        sorted,
			TotalClusters:   total,
			ScannedClusters: okCount,
			FailedClusters:  failCount,
			TotalNodes:      totalNodes,
			VulnNodes:       vulnNodes,
			TotalPods:       totalPods,
			ScanInProgress:  done < total,
			ScanPct:         pct,
			LastScan:        time.Now(),
			ScanAge:         fmt.Sprintf("scanning %d/%d clusters", done, total),
		}
		scanning = done < total
		mu.Unlock()
	}

	mu.Lock()
	fleet.ScanInProgress = false
	fleet.ScanPct = 100
	fleet.ScanAge = "just now"
	scanning = false
	mu.Unlock()

	log.Printf("[SCAN] Done — %d clusters OK, %d failed, %d nodes, %d vulnerable",
		okCount, failCount, totalNodes, vulnNodes)
}

// ── HTTP HANDLERS ─────────────────────────────────────────────────────────────

func handleData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")
	mu.RLock()
	defer mu.RUnlock()
	json.NewEncoder(w).Encode(fleet)
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	go runFleetScan()
	json.NewEncoder(w).Encode(map[string]string{"status": "triggered"})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	mu.RLock()
	defer mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok", "scanning": fleet.ScanInProgress,
		"pct": fleet.ScanPct, "clusters": fleet.TotalClusters,
	})
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Serve file if present (hot reload), otherwise embedded
	if b, err := os.ReadFile("dashboard.html"); err == nil {
		w.Header().Set("Content-Type", "text/html")
		w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(dashboardHTML)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("╔═══════════════════════════════════════╗")
	log.Println("║  PDKS Security Intelligence Platform  ║")
	log.Println("║  Pfizer Platform Engineering          ║")
	log.Println("╚═══════════════════════════════════════╝")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start scan immediately
	go runFleetScan()

	// Re-scan every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			go runFleetScan()
		}
	}()

	// Age ticker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			if !fleet.ScanInProgress && !fleet.LastScan.IsZero() {
				age := time.Since(fleet.LastScan)
				if age < time.Minute {
					fleet.ScanAge = "just now"
				} else if age < time.Hour {
					fleet.ScanAge = fmt.Sprintf("%dm ago", int(age.Minutes()))
				} else {
					fleet.ScanAge = fmt.Sprintf("%dh ago", int(age.Hours()))
				}
			}
			mu.Unlock()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/data", handleData)
	mux.HandleFunc("/api/refresh", handleRefresh)
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/", handleDashboard)

	log.Printf("[SERVER] Listening on http://localhost:%s", port)
	if err := http.ListenAndServe("0.0.0.0:"+port, mux); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
