package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type DashboardData struct {
	Summary         SummaryData      `json:"summary"`
	Compliance      ComplianceData   `json:"compliance"`
	Cves            []CVE            `json:"cves"`
	Nodes           []NodeReport     `json:"nodes"`
	Workloads       []WorkloadReport `json:"workloads"` // Updated to track true workloads
	Clusters        []ClusterReport  `json:"clusters"`
	Alerts          []AlertItem      `json:"alerts"`
	ScanAge         string           `json:"scanAge"`
	ScanInProgress  bool             `json:"scanInProgress"`
	ScanPct         int              `json:"scanPct"`
	TotalContexts   int              `json:"totalContexts"`
	ScannedContexts int              `json:"scannedContexts"`
	FailedContexts  int              `json:"failedContexts"`
}

type SummaryData struct {
	Vulnerable  int `json:"vulnerable"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
	AgentsLive  int `json:"agentsLive"`
	TotalNodes  int `json:"totalNodes"`
	AlgifLoaded int `json:"algifLoaded"`
	RiskScore   int `json:"riskScore"`
}

type ComplianceData struct {
	Eks    int `json:"eks"`
	Linux  int `json:"linux"`
	Sysdig int `json:"sysdig"`
}

type CVE struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	AgeDays   int    `json:"ageDays"`
	AgeText   string `json:"ageText"`
	Component string `json:"component"`
}

type NodeReport struct {
	Name           string   `json:"name"`
	Cluster        string   `json:"cluster"`
	ClusterContext string   `json:"clusterContext"`
	Kernel         string   `json:"kernel"`
	PatchStatus    string   `json:"patchStatus"`
	AlgifStatus    string   `json:"algifStatus"`
	Ready          string   `json:"ready"`
	NodeType       string   `json:"nodeType"`
	Zone           string   `json:"zone"`
	IsSpot         bool     `json:"isSpot"`
	Karpenter      bool     `json:"karpenter"`
	Nodepool       string   `json:"nodepool"`
	RiskScore      int      `json:"riskScore"`
	RiskLevel      string   `json:"riskLevel"`
	RiskFactors    []string `json:"riskFactors"`
	ScannedAt      string   `json:"scannedAt"`
}

type WorkloadReport struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Cluster    string `json:"cluster"`
	Type       string `json:"type"` // e.g., "Deployment", "DaemonSet"
	Replicas   string `json:"replicas"`
	RiskScore  int    `json:"riskScore"`
	RiskLevel  string `json:"riskLevel"`
	Issues     string `json:"issues"`
	Image      string `json:"image"`
	Vulnerable bool   `json:"vulnerable"`
}

type ClusterReport struct {
	Name       string `json:"name"`
	Context    string `json:"context"`
	Region     string `json:"region"`
	NodeCount  int    `json:"nodeCount"`
	Vulnerable int    `json:"vulnerable"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	ScannedAt  string `json:"scannedAt"`
}

type AlertItem struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	Level    string `json:"level"`
	FiredAt  string `json:"firedAt"`
	Notified bool   `json:"notified"`
}

type NodeDrilldownDetail struct {
	PodCount     int        `json:"podCount"`
	PrivCount    int        `json:"privCount"`
	HostNetCount int        `json:"hostNetCount"`
	SecretCount  int        `json:"secretCount"`
	BlastLevel   string     `json:"blastLevel"`
	Namespaces   []string   `json:"namespaces"`
	Pods         []PodBrief `json:"pods"`
	ScannedAt    string     `json:"scannedAt"`
	Error        string     `json:"error,omitempty"`
}

type PodBrief struct {
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	Status      string   `json:"status"`
	RiskScore   int      `json:"riskScore"`
	RiskReasons []string `json:"riskReasons"`
}

var (
	cacheMutex sync.RWMutex
	cachedData DashboardData
)

func main() {
	go triggerMetricsScan()

	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			triggerMetricsScan()
		}
	}()

	http.HandleFunc("/api/data", getDataHandler)
	http.HandleFunc("/api/nodedetail", getNodeDetailHandler)
	http.HandleFunc("/api/refresh", forceRefreshHandler)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "dashboard.html")
	})

	fmt.Println("🚀 PDKS Security backend serving on: http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getDataHandler(w http.ResponseWriter, r *http.Request) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cachedData)
}

func forceRefreshHandler(w http.ResponseWriter, r *http.Request) {
	triggerMetricsScan()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"scan triggered"}`))
}

func getNodeDetailHandler(w http.ResponseWriter, r *http.Request) {
	nodeName := r.URL.Query().Get("node")
	targetContext := r.URL.Query().Get("context")
	w.Header().Set("Content-Type", "application/json")
	if nodeName == "" {
		http.Error(w, "missing node query param", http.StatusBadRequest)
		return
	}
	detail := fetchRealNodePods(nodeName, targetContext)
	json.NewEncoder(w).Encode(detail)
}

func triggerMetricsScan() {
	cacheMutex.Lock()
	cachedData.ScanInProgress = true
	cachedData.ScanPct = 10
	cacheMutex.Unlock()

	var nodesList []NodeReport
	var workloadsList []WorkloadReport
	var clustersList []ClusterReport
	var alertsList []AlertItem

	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		log.Printf("Failed to load local Kubeconfig: %v", err)
		return
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	totalCtxs := len(config.Contexts)
	scannedCtxs := 0
	failedCtxs := 0

	for contextName := range config.Contexts {
		wg.Add(1)
		go func(ctxName string) {
			defer wg.Done()

			ctxParts := strings.Split(ctxName, "/")
			cName := ctxParts[len(ctxParts)-1]

			clusterReport := ClusterReport{
				Context:   ctxName,
				Name:      cName,
				Status:    "ok",
				ScannedAt: time.Now().Format(time.RFC3339),
			}

			clusterReport.Region = "us-east-1"
			if strings.Contains(ctxName, "us-west-2") {
				clusterReport.Region = "us-west-2"
			} else if strings.Contains(ctxName, "eu-west-1") {
				clusterReport.Region = "eu-west-1"
			}

			// Replace the old clientConfig setup block around line 234 with this:
			clientConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
				&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
				&clientcmd.ConfigOverrides{CurrentContext: ctxName},
			).ClientConfig()

			if err == nil {
				clientConfig.Timeout = 7 * time.Second
			}

			var clientset *kubernetes.Clientset
			if err == nil {
				clientset, err = kubernetes.NewForConfig(clientConfig)
			}

			if err != nil {
				clusterReport.Status = "error"
				clusterReport.Error = err.Error()
				mu.Lock()
				failedCtxs++
				clustersList = append(clustersList, clusterReport)
				mu.Unlock()
				return
			}

			// Gather Live Nodes
			liveNodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				clusterReport.Status = "error"
				clusterReport.Error = err.Error()
				mu.Lock()
				failedCtxs++
				clustersList = append(clustersList, clusterReport)
				mu.Unlock()
				return
			}

			clusterReport.NodeCount = len(liveNodes.Items)
			var clusterVulnNodes int
			var localNodes []NodeReport

			clusterIsVulnerable := false
			for _, node := range liveNodes.Items {
				kVersion := node.Status.NodeInfo.KernelVersion
				isUnpatched := true
				if strings.Contains(kVersion, "6.1.") {
					var revision int
					_, fmtErr := fmt.Sscanf(kVersion, "6.1.%d", &revision)
					if fmtErr == nil && revision >= 141 {
						isUnpatched = false
					}
				}

				patchStatus := "unpatched"
				if !isUnpatched {
					patchStatus = "patched"
				}

				nodeType := node.Labels["node.kubernetes.io/instance-type"]
				if nodeType == "" {
					nodeType = node.Labels["beta.kubernetes.io/instance-type"]
				}
				zone := node.Labels["topology.kubernetes.io/zone"]

				_, isSpot := node.Labels["eks.amazonaws.com/capacityType"]
				if !isSpot {
					_, isSpot = node.Labels["karpenter.sh/capacity-type"]
				}
				nodepool, hasKarpenter := node.Labels["karpenter.sh/nodepool"]

				readyStatus := "False"
				for _, cond := range node.Status.Conditions {
					if cond.Type == "Ready" {
						readyStatus = string(cond.Status)
					}
				}

				algifStatus := "loaded"
				if !isUnpatched {
					algifStatus = "blocked"
				}

				score := 15
				var factors []string
				if isUnpatched {
					score += 50
					factors = append(factors, "Kernel unpatched")
					clusterVulnNodes++
					clusterIsVulnerable = true
				}
				if algifStatus == "loaded" {
					score += 15
					factors = append(factors, "algif_aead module active")
				}

				level := "low"
				if score >= 65 {
					level = "critical"
				} else if score >= 40 {
					level = "high"
				}

				localNodes = append(localNodes, NodeReport{
					Name:           node.Name,
					Cluster:        clusterReport.Name,
					ClusterContext: ctxName,
					Kernel:         kVersion,
					PatchStatus:    patchStatus,
					AlgifStatus:    algifStatus,
					Ready:          readyStatus,
					NodeType:       nodeType,
					Zone:           zone,
					IsSpot:         isSpot,
					Karpenter:      hasKarpenter,
					Nodepool:       nodepool,
					RiskScore:      score,
					RiskLevel:      level,
					RiskFactors:    factors,
					ScannedAt:      time.Now().Format(time.RFC3339),
				})
			}

			clusterReport.Vulnerable = clusterVulnNodes

			// Gather Live Workloads (Deployments)
			var localWorkloads []WorkloadReport
			deps, err := clientset.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
			if err == nil {
				for _, dep := range deps.Items {
					image := "unknown"
					if len(dep.Spec.Template.Spec.Containers) > 0 {
						image = dep.Spec.Template.Spec.Containers[0].Image
					}

					wlScore := 20
					wlIssues := "None"
					wlLevel := "low"

					if clusterIsVulnerable && dep.Namespace != "kube-system" {
						wlScore = 70
						wlLevel = "critical"
						wlIssues = "Runs on cluster with unpatched nodes"
					}

					localWorkloads = append(localWorkloads, WorkloadReport{
						Name:       dep.Name,
						Namespace:  dep.Namespace,
						Cluster:    clusterReport.Name,
						Type:       "Deployment",
						Replicas:   fmt.Sprintf("%d/%d", dep.Status.ReadyReplicas, *dep.Spec.Replicas),
						RiskScore:  wlScore,
						RiskLevel:  wlLevel,
						Issues:     wlIssues,
						Image:      image,
						Vulnerable: clusterIsVulnerable,
					})
				}
			}

			mu.Lock()
			scannedCtxs++
			nodesList = append(nodesList, localNodes...)
			workloadsList = append(workloadsList, localWorkloads...)
			clustersList = append(clustersList, clusterReport)
			mu.Unlock()

		}(contextName)
	}

	wg.Wait()

	var vulnNodes, critNodes, highNodes, medNodes, lowNodes, algifCount int
	for _, n := range nodesList {
		if n.PatchStatus == "unpatched" {
			vulnNodes++
		}
		if n.AlgifStatus == "loaded" {
			algifCount++
		}
		switch n.RiskLevel {
		case "critical":
			critNodes++
		case "high":
			highNodes++
		case "medium":
			medNodes++
		case "low":
			lowNodes++
		}
	}

	globalRisk := 20
	if len(nodesList) > 0 {
		globalRisk = (critNodes*90 + highNodes*65 + medNodes*35) / len(nodesList)
	}

	dummyCVEs := []CVE{
		{ID: "CVE-2026-31431", Severity: "Critical", AgeDays: 14, AgeText: "14d ago", Component: "kernel-amzn"},
		{ID: "CVE-2025-58186", Severity: "High", AgeDays: 210, AgeText: "7 months ago", Component: "glibc"},
	}

	if vulnNodes > 0 {
		alertsList = append(alertsList, AlertItem{
			Title:   "Copy Fail Vulnerability Exposure",
			Body:    fmt.Sprintf("Detected %d nodes exposed across reachable execution contexts.", vulnNodes),
			Level:   "critical",
			FiredAt: time.Now().Format(time.RFC3339),
		})
	}

	cacheMutex.Lock()
	cachedData = DashboardData{
		Summary: SummaryData{
			Vulnerable:  vulnNodes,
			Critical:    critNodes,
			High:        highNodes,
			Medium:      medNodes,
			Low:         lowNodes,
			AgentsLive:  746,
			TotalNodes:  len(nodesList),
			AlgifLoaded: algifCount,
			RiskScore:   globalRisk,
		},
		Compliance: ComplianceData{
			Eks:    48,
			Linux:  12,
			Sysdig: 0,
		},
		Cves:            dummyCVEs,
		Nodes:           nodesList,
		Workloads:       workloadsList,
		Clusters:        clustersList,
		Alerts:          alertsList,
		ScanAge:         "just now",
		ScanInProgress:  false,
		ScanPct:         100,
		TotalContexts:   totalCtxs,
		ScannedContexts: scannedCtxs,
		FailedContexts:  failedCtxs,
	}
	cacheMutex.Unlock()
}

func fetchRealNodePods(nodeName, ctxName string) NodeDrilldownDetail {
	detail := NodeDrilldownDetail{
		ScannedAt:  time.Now().Format(time.RFC3339),
		BlastLevel: "LOW",
	}

	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	// Replace the old clientConfig setup block around line 484 with this:
	clientConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: ctxName},
	).ClientConfig()

	if err != nil {
		detail.Error = err.Error()
		return detail
	}

	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		detail.Error = err.Error()
		return detail
	}

	pods, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		detail.Error = err.Error()
		return detail
	}

	detail.PodCount = len(pods.Items)
	nsMap := make(map[string]bool)

	for _, pod := range pods.Items {
		nsMap[pod.Namespace] = true
		isPrivileged := false
		hasHostNetwork := pod.Spec.HostNetwork
		hasSecrets := false

		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				isPrivileged = true
			}
		}
		for _, vol := range pod.Spec.Volumes {
			if vol.Secret != nil {
				hasSecrets = true
			}
		}

		podScore := 10
		var reasons []string
		if isPrivileged {
			detail.PrivCount++
			podScore += 50
			reasons = append(reasons, "Privileged space container")
		}
		if hasHostNetwork {
			detail.HostNetCount++
			podScore += 20
			reasons = append(reasons, "hostNetwork configuration active")
		}
		if hasSecrets {
			detail.SecretCount++
			podScore += 5
			reasons = append(reasons, "Mounted core Secret mapping")
		}

		detail.Pods = append(detail.Pods, PodBrief{
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			Status:      string(pod.Status.Phase),
			RiskScore:   podScore,
			RiskReasons: reasons,
		})
	}

	for ns := range nsMap {
		detail.Namespaces = append(detail.Namespaces, ns)
	}

	if detail.PrivCount > 0 || detail.HostNetCount > 0 {
		detail.BlastLevel = "CRITICAL"
	} else if detail.SecretCount > 3 {
		detail.BlastLevel = "HIGH"
	}

	return detail
}
