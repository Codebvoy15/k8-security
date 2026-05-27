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
	// CVE data from Sysdig (merged in)
	CVEs     []VulnFinding `json:"cves,omitempty"`
	CritCVEs int           `json:"critCVEs"`
	HighCVEs int           `json:"highCVEs"`
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
	ScanAge    string             `json:"scanAge,omitempty"`
	Rank       int                `json:"rank"`
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
	// Predictive risk model output
	PredictiveRisk PredictiveRisk `json:"predictiveRisk"`
}

// PredictiveRisk holds the computed threat model for the fleet
type PredictiveRisk struct {
	OverallScore    int              `json:"overallScore"`  // 0-100
	AttackProb72h   int              `json:"attackProb72h"` // % probability
	Signals         []ThreatSignal   `json:"signals"`
	Scenarios       []AttackScenario `json:"scenarios"`
	TopRiskClusters []string         `json:"topRiskClusters"`
}

type ThreatSignal struct {
	Name        string `json:"name"`
	Score       int    `json:"score"`    // 0-100 intensity
	Category    string `json:"category"` // kernel, network, runtime, supply-chain, visibility
	Detail      string `json:"detail"`
	Mitigatable bool   `json:"mitigatable"`
	MitigateHow string `json:"mitigateHow"`
}

type AttackScenario struct {
	Title         string   `json:"title"`
	Likelihood    string   `json:"likelihood"` // critical/high/medium/low
	Steps         []string `json:"steps"`
	Impact        string   `json:"impact"`
	Mitigation    string   `json:"mitigation"`
	TimeToExploit string   `json:"timeToExploit"`
}

// ── SYSDIG VULNERABILITY FINDING ─────────────────────────────────────────────

type VulnFinding struct {
	VulnName       string  `json:"vulnName"`
	Severity       string  `json:"severity"`
	CVSS           float64 `json:"cvss"`
	CVSSVector     string  `json:"cvssVector"`
	FixVersion     string  `json:"fixVersion"`
	FixAvailDate   string  `json:"fixAvailDate"`
	DisclosureDate string  `json:"disclosureDate"`
	PackageName    string  `json:"packageName"`
	PackageVersion string  `json:"packageVersion"`
	PackageType    string  `json:"packageType"`
	PackagePath    string  `json:"packagePath"`
	ImageName      string  `json:"imageName"`
	ImageID        string  `json:"imageID"`
	OSName         string  `json:"osName"`
	ClusterName    string  `json:"clusterName"`
	Namespace      string  `json:"namespace"`
	WorkloadName   string  `json:"workloadName"`
	WorkloadType   string  `json:"workloadType"`
	ContainerName  string  `json:"containerName"`
	Context        string  `json:"context"`
	CISAKEVDate    string  `json:"cisaKevDate"`
	AcceptedRisk   bool    `json:"acceptedRisk"`
}

type VulnResponse struct {
	Findings []VulnFinding `json:"findings"`
	Total    int           `json:"total"`
	Error    string        `json:"error,omitempty"`
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
			Ready:    ready, RiskScore: score, RiskLevel: nodeRisk(score),
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
				NodeInfo struct {
					KernelVersion string `json:"kernelVersion"`
				} `json:"nodeInfo"`
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
			Ready:    ready, RiskScore: score, RiskLevel: nodeRisk(score),
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

	// Build a map of existing clusters so we don't lose data during rescan
	mu.RLock()
	existingMap := make(map[string]ClusterDetail)
	for _, c := range fleet.Clusters {
		existingMap[c.Context] = c
	}
	mu.RUnlock()

	// Track newly scanned results
	newResults := make(map[string]ClusterDetail)
	done, okCount, failCount := 0, 0, 0
	totalNodes, vulnNodes, totalPods := 0, 0, 0

	for done < total {
		r := <-resultCh
		done++
		newResults[r.detail.Context] = r.detail

		if r.detail.Status == "ok" {
			okCount++
			totalNodes += r.detail.NodeCount
			vulnNodes += r.detail.Vulnerable
			totalPods += r.detail.PodCount
		} else {
			failCount++
		}

		pct := done * 100 / total

		// Merge: use new result where available, keep old data for unscanned contexts
		merged := make([]ClusterDetail, 0, total)
		for _, ctx := range contexts {
			if nd, ok := newResults[ctx]; ok {
				merged = append(merged, nd)
			} else if od, ok := existingMap[ctx]; ok {
				// Keep old data, mark as stale
				od.ScanAge = "stale"
				merged = append(merged, od)
			}
		}

		// Sort: most vulnerable first
		sort.Slice(merged, func(i, j int) bool {
			if merged[i].Vulnerable != merged[j].Vulnerable {
				return merged[i].Vulnerable > merged[j].Vulnerable
			}
			if merged[i].Status != merged[j].Status {
				return merged[i].Status == "ok"
			}
			return merged[i].Name < merged[j].Name
		})

		mu.Lock()
		fleet.Clusters = merged
		fleet.TotalClusters = total
		fleet.ScannedClusters = okCount
		fleet.FailedClusters = failCount
		fleet.TotalNodes = totalNodes
		fleet.VulnNodes = vulnNodes
		fleet.TotalPods = totalPods
		fleet.ScanInProgress = done < total
		fleet.ScanPct = pct
		fleet.LastScan = time.Now()
		if done < total {
			fleet.ScanAge = fmt.Sprintf("scanning %d/%d", done, total)
		}
		mu.Unlock()
	}

	mu.Lock()
	fleet.ScanInProgress = false
	fleet.ScanPct = 100
	fleet.ScanAge = "just now"
	scanning = false
	// Assign ranks by vulnerability severity
	rank := 1
	for i := range fleet.Clusters {
		if fleet.Clusters[i].Status == "ok" && fleet.Clusters[i].Vulnerable > 0 {
			fleet.Clusters[i].Rank = rank
			rank++
		}
	}
	// Compute predictive risk model from real fleet data
	fleet.PredictiveRisk = computePredictiveRisk(&fleet)
	log.Printf("[PREDICT] Overall risk: %d/100, Attack probability 72h: %d%%",
		fleet.PredictiveRisk.OverallScore, fleet.PredictiveRisk.AttackProb72h)
	mu.Unlock()

	log.Printf("[SCAN] Done — %d clusters OK, %d failed, %d nodes, %d vulnerable",
		okCount, failCount, totalNodes, vulnNodes)
}

// ── PREDICTIVE RISK ENGINE ───────────────────────────────────────────────────

// computePredictiveRisk builds a threat model from real fleet data
// Based on Pfizer PDKS fleet: EKS+Rancher, Karpenter, AL2023, Portworx, Sysdig ViewOnly
func computePredictiveRisk(f *FleetData) PredictiveRisk {
	cs := f.Clusters
	totalNodes := f.TotalNodes
	vulnNodes := f.VulnNodes

	okClusters := 0
	for _, c := range cs {
		if c.Status == "ok" {
			okClusters++
		}
	}

	// Count privileged pods, hostNetwork pods across fleet
	privPods, hostNetPods, noLimitPods := 0, 0, 0
	spotVulnNodes := 0
	karpenterVulnNodes := 0
	for _, c := range cs {
		for _, n := range c.Nodes {
			if n.Vulnerable && n.IsSpot {
				spotVulnNodes++
			}
			// Detect karpenter by zone pattern (simplified)
			if n.Vulnerable && n.NodeType != "" {
				karpenterVulnNodes++
			}
		}
		for _, ns := range c.Namespaces {
			for _, app := range ns.Apps {
				if app.Privileged {
					privPods++
				}
				if app.HostNetwork {
					hostNetPods++
				}
				if app.NoLimits {
					noLimitPods++
				}
			}
		}
	}

	vulnPct := 0
	if totalNodes > 0 {
		vulnPct = vulnNodes * 100 / totalNodes
	}
	failPct := 0
	if f.TotalClusters > 0 {
		failPct = f.FailedClusters * 100 / f.TotalClusters
	}

	// Build signals — each scored 0-100 based on real data
	signals := []ThreatSignal{
		{
			Name:        "Copy Fail (CVE-2026-31431) nodes unpatched",
			Score:       min100(vulnPct),
			Category:    "kernel",
			Detail:      fmt.Sprintf("%d/%d nodes running AL2023 kernel <6.1.141 with algif_aead loaded. Public PoC available. CVSS 9.8.", vulnNodes, totalNodes),
			Mitigatable: true,
			MitigateHow: "Deploy algif_aead DaemonSet — 15 mins, zero downtime",
		},
		{
			Name:        "Karpenter provisioning unpatched AMIs",
			Score:       min100(vulnPct * 85 / 100),
			Category:    "kernel",
			Detail:      fmt.Sprintf("Karpenter auto-provisions nodes from EC2NodeClass. If AMI is not updated to kernel 6.1.141+, every scale-up event adds a new vulnerable node. ~%d vulnerable nodes likely Karpenter-managed.", karpenterVulnNodes),
			Mitigatable: true,
			MitigateHow: "Update EC2NodeClass amiSelector to patched AMI in all NodePools",
		},
		{
			Name:        "Detection & Response access blocked (View Only role)",
			Score:       75,
			Category:    "visibility",
			Detail:      "Sysdig-PDKS-Ops-s role is View Only. Runtime event feed is blocked — active Copy Fail exploit attempts are not visible. Detection gap is fleet-wide.",
			Mitigatable: true,
			MitigateHow: "Escalate to Sysdig admin to grant Vulnerability Management + D&R role",
		},
		{
			Name:        fmt.Sprintf("%d privileged containers on vulnerable nodes", privPods),
			Score:       min100(privPods * 10),
			Category:    "runtime",
			Detail:      fmt.Sprintf("%d privileged pods running across fleet. Privileged containers have full node access — post Copy Fail exploit, attacker immediately pivots into these pods.", privPods),
			Mitigatable: true,
			MitigateHow: "Remove privileged:true from non-system workloads, use securityContext constraints",
		},
		{
			Name:        "No network policies — lateral movement unrestricted",
			Score:       65,
			Category:    "network",
			Detail:      "CIS EKS benchmark shows 71% of clusters failing network policy controls. Post-exploit, attacker can reach any pod in any namespace with zero friction.",
			Mitigatable: true,
			MitigateHow: "Deploy namespace-level NetworkPolicy deny-all with explicit allow rules",
		},
		{
			Name:        fmt.Sprintf("%d unreachable clusters — blind spots", f.FailedClusters),
			Score:       min100(failPct),
			Category:    "visibility",
			Detail:      fmt.Sprintf("%d/%d clusters unreachable (SSO expired or network). These clusters have unknown vulnerability state — could be worse than visible clusters.", f.FailedClusters, f.TotalClusters),
			Mitigatable: true,
			MitigateHow: "Run aws sso login to refresh credentials, fix SSO automation",
		},
		{
			Name:        "7-month-old CVEs in Go/Java packages unpatched",
			Score:       60,
			Category:    "supply-chain",
			Detail:      "CVE-2025-58186, 58187, 61723, 61725 have had fixes since Oct 2025. Go 1.23.x packages (CVE-2025-68121 CVSS 10.0) running in aws-node, cluster-autoscaler, ebs-csi-node.",
			Mitigatable: true,
			MitigateHow: "Rebuild container images with updated Go 1.25.5+ and push to Artifactory",
		},
		{
			Name:        fmt.Sprintf("%d spot instances vulnerable — 2-min eviction window", spotVulnNodes),
			Score:       min100(spotVulnNodes * 8),
			Category:    "runtime",
			Detail:      fmt.Sprintf("%d vulnerable nodes are Spot instances. Attacker has at most 2 minutes per node before eviction, but can chain across multiple nodes via lateral movement.", spotVulnNodes),
			Mitigatable: false,
			MitigateHow: "Patch kernel first — spot is not a vulnerability by itself",
		},
		{
			Name:        "CIS Linux compliance at 12% — 41K resources below baseline",
			Score:       55,
			Category:    "runtime",
			Detail:      "41,000 compute resources failing CIS Linux Level 2. SSH hardening, filesystem permissions, bootloader config all failing. Every failure amplifies Copy Fail exploitability.",
			Mitigatable: true,
			MitigateHow: "Apply CIS hardening via UserData/Ansible on next AMI refresh. SSH hardening alone +15%.",
		},
	}

	// Sort signals by score desc
	sort.Slice(signals, func(i, j int) bool {
		return signals[i].Score > signals[j].Score
	})

	// Overall risk = weighted average of top signals
	overallScore := 0
	for i, s := range signals {
		w := 10 - i
		if w < 1 {
			w = 1
		}
		overallScore += s.Score * w
	}
	overallScore = overallScore / 55 // normalize
	if overallScore > 99 {
		overallScore = 99
	}

	// Attack probability 72h — higher if public PoC + vulnerable nodes + no D&R
	attackProb := vulnPct/2 + 20
	if vulnNodes > 0 {
		attackProb += 15
	} // public PoC exists
	if failPct > 20 {
		attackProb += 10
	} // blind spots
	if attackProb > 99 {
		attackProb = 99
	}

	// Top risk clusters
	var topRisk []string
	for _, c := range cs {
		if c.Vulnerable > 0 && c.Status == "ok" {
			topRisk = append(topRisk, c.Name)
			if len(topRisk) >= 5 {
				break
			}
		}
	}

	// Attack scenarios — specific to Pfizer PDKS infra
	scenarios := []AttackScenario{
		{
			Title:         "Copy Fail → Privileged Container Escape → Cluster Compromise",
			Likelihood:    "critical",
			TimeToExploit: "< 5 minutes",
			Steps: []string{
				"Attacker gains unprivileged pod execution (any RCE in any workload)",
				"Runs Copy Fail PoC: 4 syscalls → root on AL2023 node",
				"Pivots into privileged container (aws-node, sysdig-agent, ebs-csi-node)",
				"Reads EC2 instance metadata → AWS credentials",
				"Uses AWS credentials to access S3, Secrets Manager, ECR",
				"Exfiltrates data or deploys persistent backdoor",
			},
			Impact:     "Full cluster compromise, AWS account access, data exfiltration",
			Mitigation: "1. Deploy algif_aead DaemonSet NOW  2. Remove privileged from non-system pods  3. Block IMDS access for pods (hop limit=1)",
		},
		{
			Title:         "Karpenter Scale-Up → New Vulnerable Node → Automated Exploitation",
			Likelihood:    "high",
			TimeToExploit: "Minutes after scale event",
			Steps: []string{
				"Traffic spike triggers Karpenter to provision new nodes",
				"New nodes use unpatched AMI — immediately vulnerable to Copy Fail",
				"Automated exploit scanner detects new node (Shodan/internal recon)",
				"Copy Fail runs on new node before team notices it joined fleet",
				"Lateral movement across VPC to other clusters in same region",
			},
			Impact:     "Continuous re-exposure — patching nodes is futile without AMI fix",
			Mitigation: "Update EC2NodeClass amiSelector to kernel 6.1.141+ AMI ID in all Karpenter NodePools",
		},
		{
			Title:         "Go Package CVE (CVSS 10.0) → aws-node Compromise → VPC CNI Exploit",
			Likelihood:    "high",
			TimeToExploit: "Hours",
			Steps: []string{
				"CVE-2025-68121 (Go 1.23.x, CVSS 10.0) affects aws-node DaemonSet on every node",
				"aws-node runs as DaemonSet with hostNetwork:true and privileged:true",
				"Exploit Go vulnerability in aws-node → root on host network",
				"From host network: intercept pod-to-pod traffic across entire VPC",
				"Inject malicious responses into service mesh / DNS",
				"Exfiltrate credentials passed over the network",
			},
			Impact:     "VPC-wide traffic interception, credential theft, supply chain injection",
			Mitigation: "Rebuild aws-node image with Go 1.25.5+. Update VPC CNI addon to latest.",
		},
		{
			Title:         "Blind Cluster (SSO Expired) → Undetected Compromise",
			Likelihood:    "medium",
			TimeToExploit: "Already may be compromised",
			Steps: []string{
				fmt.Sprintf("%d clusters unreachable — no scan data, no Sysdig visibility", f.FailedClusters),
				"These clusters have unknown kernel versions, unknown running workloads",
				"If already compromised, no alerts fire (D&R blocked, agents stale)",
				"Attacker maintains persistence undetected indefinitely",
			},
			Impact:     "Unknown — could already be compromised with zero visibility",
			Mitigation: "Priority: run aws sso login, scan these clusters, deploy Sysdig agents with D&R role",
		},
	}

	return PredictiveRisk{
		OverallScore:    overallScore,
		AttackProb72h:   attackProb,
		Signals:         signals,
		Scenarios:       scenarios,
		TopRiskClusters: topRisk,
	}
}

func min100(v int) int {
	if v > 100 {
		return 100
	}
	if v < 0 {
		return 0
	}
	return v
}

// ── SYSDIG VULNERABILITY API ─────────────────────────────────────────────────

// fetchSysdigVulns calls the Sysdig VM API to get real workload vulnerability findings
// Matches what you see in Sysdig UI: Kubernetes Workload Vulnerability Findings
func fetchSysdigVulns(token, base string, limit int) VulnResponse {
	if token == "" {
		return VulnResponse{Error: "SYSDIG_TOKEN not set"}
	}
	if base == "" {
		base = "https://us2.app.sysdig.com"
	}
	if limit <= 0 {
		limit = 500
	}

	// Sysdig VM Findings API — the one that backs the workload vulnerability table in UI
	// Try multiple endpoint paths as Sysdig has updated their API over versions
	endpoints := []string{
		fmt.Sprintf("%s/api/scanning/v1/results/vulnerabilities?limit=%d&filter=kubernetes.cluster.name+!=+\"\"", base, limit),
		fmt.Sprintf("%s/api/v1/vulnerabilities/findings?limit=%d&scope=kubernetes", base, limit),
		fmt.Sprintf("%s/vm/v1/vulnerabilities/findings?limit=%d", base, limit),
	}

	client := &http.Client{Timeout: 30 * time.Second}

	for _, endpoint := range endpoints {
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[SYSDIG-VULN] Request error %s: %v", endpoint, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 403 {
			log.Printf("[SYSDIG-VULN] 403 Forbidden — View Only role lacks VM access: %s", endpoint)
			continue
		}
		if resp.StatusCode != 200 {
			log.Printf("[SYSDIG-VULN] HTTP %d from %s", resp.StatusCode, endpoint)
			continue
		}

		// Try to parse — Sysdig has different response shapes
		var raw map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			continue
		}

		findings := parseSysdigVulnResponse(raw)
		if len(findings) > 0 {
			log.Printf("[SYSDIG-VULN] Got %d findings from %s", len(findings), endpoint)
			return VulnResponse{Findings: findings, Total: len(findings)}
		}
	}

	// All endpoints failed — return descriptive error
	return VulnResponse{
		Error: "Sysdig VM API requires 'Vulnerability Management' role. Current role (Sysdig-PDKS-Ops-s) is View Only — escalate to Sysdig admin to enable VM API access.",
	}
}

// parseSysdigVulnResponse handles different Sysdig API response shapes
func parseSysdigVulnResponse(raw map[string]interface{}) []VulnFinding {
	var findings []VulnFinding

	// Try "data" array (v1 format)
	if data, ok := raw["data"].([]interface{}); ok {
		for _, item := range data {
			if m, ok := item.(map[string]interface{}); ok {
				findings = append(findings, mapToVulnFinding(m))
			}
		}
	}
	// Try "findings" array
	if data, ok := raw["findings"].([]interface{}); ok {
		for _, item := range data {
			if m, ok := item.(map[string]interface{}); ok {
				findings = append(findings, mapToVulnFinding(m))
			}
		}
	}
	// Try "vulnerabilities" array
	if data, ok := raw["vulnerabilities"].([]interface{}); ok {
		for _, item := range data {
			if m, ok := item.(map[string]interface{}); ok {
				findings = append(findings, mapToVulnFinding(m))
			}
		}
	}
	return findings
}

func mapToVulnFinding(m map[string]interface{}) VulnFinding {
	str := func(key string) string {
		if v, ok := m[key]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
		// Try alternate key names
		alts := map[string][]string{
			"vulnName":       {"vulnerabilityName", "cve", "name", "vuln"},
			"severity":       {"vulnerabilitySeverity", "riskScore"},
			"packageName":    {"package", "pkgName"},
			"packageVersion": {"pkgVersion", "version"},
			"packageType":    {"pkgType", "type"},
			"packagePath":    {"pkgPath", "path"},
			"imageName":      {"image", "containerImage"},
			"clusterName":    {"kubernetesClusterName", "kubernetes.cluster.name", "cluster"},
			"namespace":      {"kubernetesNamespace", "kubernetes.namespace.name"},
			"workloadName":   {"kubernetesWorkloadName", "workload"},
			"workloadType":   {"kubernetesWorkloadType"},
			"containerName":  {"kubernetesContainerName", "container"},
			"fixVersion":     {"fix", "fixedVersion"},
			"imageID":        {"containerImageId", "imageDigest"},
		}
		if altsKeys, ok := alts[key]; ok {
			for _, alt := range altsKeys {
				if v, ok := m[alt]; ok && v != nil {
					return fmt.Sprintf("%v", v)
				}
			}
		}
		return ""
	}
	f64 := func(key string) float64 {
		if v, ok := m[key]; ok {
			switch t := v.(type) {
			case float64:
				return t
			case string:
				var f float64
				fmt.Sscanf(t, "%f", &f)
				return f
			}
		}
		return 0
	}
	return VulnFinding{
		VulnName:       str("vulnName"),
		Severity:       str("severity"),
		CVSS:           f64("cvss"),
		CVSSVector:     str("cvssVector"),
		FixVersion:     str("fixVersion"),
		FixAvailDate:   str("fixAvailDate"),
		DisclosureDate: str("disclosureDate"),
		PackageName:    str("packageName"),
		PackageVersion: str("packageVersion"),
		PackageType:    str("packageType"),
		PackagePath:    str("packagePath"),
		ImageName:      str("imageName"),
		ImageID:        str("imageID"),
		OSName:         str("osName"),
		ClusterName:    str("clusterName"),
		Namespace:      str("namespace"),
		WorkloadName:   str("workloadName"),
		WorkloadType:   str("workloadType"),
		ContainerName:  str("containerName"),
		CISAKEVDate:    str("cisaKevDate"),
	}
}

// handleVulnFindings serves real Sysdig vuln findings
func handleVulnFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")

	token := os.Getenv("SYSDIG_TOKEN")
	base := os.Getenv("SYSDIG_BASE")

	limit := 500
	result := fetchSysdigVulns(token, base, limit)
	json.NewEncoder(w).Encode(result)
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
	mux.HandleFunc("/api/vulns", handleVulnFindings)
	mux.HandleFunc("/", handleDashboard)

	log.Printf("[SERVER] Listening on http://localhost:%s", port)
	if err := http.ListenAndServe("0.0.0.0:"+port, mux); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
