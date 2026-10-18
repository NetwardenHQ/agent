package k8s

// Typed views of the Kubernetes API objects the health engine reads. Only the
// fields consumed are declared; the server sends much more and encoding/json
// ignores the rest. These are intentionally hand-written (not client-go's
// generated types) to keep the dependency surface at zero.

// genericList is the envelope every list endpoint returns. The resourceVersion
// in its metadata is where the subsequent watch resumes from.
type genericList[T any] struct {
	Metadata ListMeta `json:"metadata"`
	Items    []T      `json:"items"`
}

// ---- Pod ----------------------------------------------------------------

type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
	Status   PodStatus  `json:"status"`
}

func (p Pod) key() string { return "pod|" + p.Metadata.Namespace + "|" + p.Metadata.Name }

type PodSpec struct {
	NodeName   string      `json:"nodeName,omitempty"`
	Containers []Container `json:"containers,omitempty"`
}

type Container struct {
	Resources struct {
		Limits map[string]string `json:"limits,omitempty"`
	} `json:"resources,omitempty"`
	Name  string `json:"name"`
	Image string `json:"image"`
}

type PodStatus struct {
	// PodIP is how the agent reaches an exporter running inside another pod
	// (CloudNativePG publishes its metrics on the pod itself). Scraping the IP
	// directly avoids asking for `pods/proxy`, which would be a grant to GET
	// any port of any pod in the cluster, far more than reading /metrics needs.
	PodIP                 string            `json:"podIP,omitempty"`
	Phase                 string            `json:"phase,omitempty"`  // Pending/Running/Succeeded/Failed/Unknown
	Reason                string            `json:"reason,omitempty"` // e.g. Evicted
	Message               string            `json:"message,omitempty"`
	Conditions            []PodCondition    `json:"conditions,omitempty"`
	ContainerStatuses     []ContainerStatus `json:"containerStatuses,omitempty"`
	InitContainerStatuses []ContainerStatus `json:"initContainerStatuses,omitempty"`
	StartTime             string            `json:"startTime,omitempty"`
}

type PodCondition struct {
	Type    string `json:"type"`   // PodScheduled, Ready, Initialized, ContainersReady
	Status  string `json:"status"` // True / False / Unknown
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type ContainerStatus struct {
	Name         string         `json:"name"`
	Ready        bool           `json:"ready"`
	RestartCount int            `json:"restartCount"`
	Image        string         `json:"image"`
	State        ContainerState `json:"state"`
	LastState    ContainerState `json:"lastState"`
}

type ContainerState struct {
	Waiting    *ContainerStateWaiting    `json:"waiting,omitempty"`
	Terminated *ContainerStateTerminated `json:"terminated,omitempty"`
	Running    *ContainerStateRunning    `json:"running,omitempty"`
}

type ContainerStateWaiting struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type ContainerStateTerminated struct {
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message,omitempty"`
	ExitCode int    `json:"exitCode"`
}

type ContainerStateRunning struct {
	StartedAt string `json:"startedAt,omitempty"`
}

// ---- Node ---------------------------------------------------------------

type Node struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     NodeSpec   `json:"spec"`
	Status   NodeStatus `json:"status"`
}

func (n Node) key() string { return "node|" + n.Metadata.Name }

type NodeSpec struct {
	Unschedulable bool `json:"unschedulable,omitempty"`
}

type NodeStatus struct {
	Addresses []struct {
		Type    string `json:"type"`
		Address string `json:"address"`
	} `json:"addresses,omitempty"`
	Conditions []NodeCondition `json:"conditions,omitempty"`
	NodeInfo   NodeSystemInfo  `json:"nodeInfo,omitempty"`
	// Raw Kubernetes quantities ("4", "8155432Ki", "61255492Ki"). Capacity is
	// the machine; Allocatable is what is left for pods after system reserves.
	// Percentages are computed against Allocatable, because that is the number
	// the scheduler and the operator work within.
	Capacity    map[string]string `json:"capacity,omitempty"`
	Allocatable map[string]string `json:"allocatable,omitempty"`
}

type NodeCondition struct {
	Type    string `json:"type"`   // Ready, MemoryPressure, DiskPressure, PIDPressure
	Status  string `json:"status"` // True / False / Unknown
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type NodeSystemInfo struct {
	KubeletVersion string `json:"kubeletVersion,omitempty"`
	OSImage        string `json:"osImage,omitempty"`
}

// ---- ReplicaSet (owner resolution only) ---------------------------------
// Only the metadata is needed: a pod's controller ownerReference points at a
// ReplicaSet, whose own ownerReference points at the Deployment. Resolving
// that one hop turns "pod xyz" into "Deployment/foo" for the roll-up.

type ReplicaSet struct {
	Metadata ObjectMeta `json:"metadata"`
}

func (r ReplicaSet) key() string {
	return r.Metadata.Namespace + "/" + r.Metadata.Name
}

// ---- Job (batch/v1) -----------------------------------------------------
// A failed Job is the actionable unit behind "a CronJob run failed": the Job
// carries the Failed condition and an ownerReference to its CronJob, so the
// finding rolls up to CronJob/<name>, the name an operator recognizes.

type Job struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   JobStatus  `json:"status"`
}

func (j Job) key() string { return "job|" + j.Metadata.Namespace + "|" + j.Metadata.Name }

type JobStatus struct {
	Active     int            `json:"active,omitempty"`
	Succeeded  int            `json:"succeeded,omitempty"`
	Failed     int            `json:"failed,omitempty"`
	Conditions []JobCondition `json:"conditions,omitempty"`
}

// CronJob carries the schedule and the outcome of its recent runs. Everything
// the panel shows comes from here plus the Jobs it owns.
type CronJob struct {
	Metadata ObjectMeta    `json:"metadata"`
	Spec     CronJobSpec   `json:"spec"`
	Status   CronJobStatus `json:"status"`
}

func (c CronJob) key() string { return "cronjob|" + c.Metadata.Namespace + "|" + c.Metadata.Name }

type CronJobSpec struct {
	Schedule string `json:"schedule"`
	// Kubernetes lets a CronJob name its own timezone; when absent the API
	// server evaluates the schedule in UTC, and so does this collector.
	TimeZone *string `json:"timeZone,omitempty"`
	Suspend  *bool   `json:"suspend,omitempty"`
}

type CronJobStatus struct {
	Active             []ObjectReference `json:"active,omitempty"`
	LastScheduleTime   string            `json:"lastScheduleTime,omitempty"`
	LastSuccessfulTime string            `json:"lastSuccessfulTime,omitempty"`
}

type ObjectReference struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type JobCondition struct {
	Type    string `json:"type"` // Complete | Failed | SuccessCriteriaMet | FailureTarget
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// ---- Workloads (apps/v1) ------------------------------------------------
// Availability, rather than pod events, is the primary impact signal. A pod dying
// while its workload still has every replica available is a statistic; a
// workload below its desired count is the thing worth telling someone about.
//
// The three kinds report availability under different field names, so each is
// decoded separately and normalized by workloadStateOf* in health.go.

type Deployment struct {
	Metadata ObjectMeta       `json:"metadata"`
	Spec     DeploymentSpec   `json:"spec"`
	Status   DeploymentStatus `json:"status"`
}

func (d Deployment) key() string {
	return "Deployment|" + d.Metadata.Namespace + "|" + d.Metadata.Name
}

type DeploymentSpec struct {
	// Pointer: an absent replicas field defaults to 1, which is different from
	// an explicit 0 (deliberately scaled down, and not an outage).
	Replicas *int `json:"replicas,omitempty"`
}

type DeploymentStatus struct {
	Replicas           int                 `json:"replicas,omitempty"`
	AvailableReplicas  int                 `json:"availableReplicas,omitempty"`
	ReadyReplicas      int                 `json:"readyReplicas,omitempty"`
	UpdatedReplicas    int                 `json:"updatedReplicas,omitempty"`
	ObservedGeneration int64               `json:"observedGeneration,omitempty"`
	Conditions         []WorkloadCondition `json:"conditions,omitempty"`
}

type WorkloadCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type StatefulSet struct {
	Metadata ObjectMeta        `json:"metadata"`
	Spec     DeploymentSpec    `json:"spec"`
	Status   StatefulSetStatus `json:"status"`
}

func (s StatefulSet) key() string {
	return "StatefulSet|" + s.Metadata.Namespace + "|" + s.Metadata.Name
}

type StatefulSetStatus struct {
	Replicas           int   `json:"replicas,omitempty"`
	AvailableReplicas  int   `json:"availableReplicas,omitempty"`
	ReadyReplicas      int   `json:"readyReplicas,omitempty"`
	UpdatedReplicas    int   `json:"updatedReplicas,omitempty"`
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

type DaemonSet struct {
	Metadata ObjectMeta      `json:"metadata"`
	Status   DaemonSetStatus `json:"status"`
}

func (d DaemonSet) key() string {
	return "DaemonSet|" + d.Metadata.Namespace + "|" + d.Metadata.Name
}

// DaemonSetStatus carries the desired count in place of spec.replicas: the
// number of nodes the DaemonSet should run on.
type DaemonSetStatus struct {
	DesiredNumberScheduled int   `json:"desiredNumberScheduled,omitempty"`
	NumberAvailable        int   `json:"numberAvailable,omitempty"`
	NumberReady            int   `json:"numberReady,omitempty"`
	UpdatedNumberScheduled int   `json:"updatedNumberScheduled,omitempty"`
	ObservedGeneration     int64 `json:"observedGeneration,omitempty"`
}

// ---- PodDisruptionBudget (policy/v1) ------------------------------------
// A PDB is the workload owner's own statement of how much disruption it can
// absorb, so it is used in place of an invented threshold.

type PodDisruptionBudget struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   PDBStatus  `json:"status"`
}

func (p PodDisruptionBudget) key() string {
	return "PodDisruptionBudget|" + p.Metadata.Namespace + "|" + p.Metadata.Name
}

type PDBStatus struct {
	CurrentHealthy     int   `json:"currentHealthy,omitempty"`
	DesiredHealthy     int   `json:"desiredHealthy,omitempty"`
	DisruptionsAllowed int   `json:"disruptionsAllowed,omitempty"`
	ExpectedPods       int   `json:"expectedPods,omitempty"`
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ---- EndpointSlice (discovery.k8s.io/v1) --------------------------------
// Endpoint readiness answers whether traffic can land. A pod can be Running and
// not Ready; a Service whose endpoints are all unready is an outage even when
// every pod looks alive.

type EndpointSlice struct {
	Metadata  ObjectMeta `json:"metadata"`
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

func (e EndpointSlice) key() string {
	return "EndpointSlice|" + e.Metadata.Namespace + "|" + e.Metadata.Name
}

// serviceName reads the well-known label Kubernetes puts on every slice so
// several slices for one Service can be aggregated.
func (e EndpointSlice) serviceName() string {
	return e.Metadata.Labels["kubernetes.io/service-name"]
}

type Endpoint struct {
	Conditions EndpointConditions `json:"conditions"`
}

type EndpointConditions struct {
	// Pointer: absent means "assume ready" per the API contract, which is
	// different from an explicit false.
	Ready *bool `json:"ready,omitempty"`
}

func (e Endpoint) ready() bool {
	return e.Conditions.Ready == nil || *e.Conditions.Ready
}

// ---- Ingress ------------------------------------------------------------

// Ingress is read for the route inventory: which ingresses exist, what
// hostnames they answer for, and whether they terminate TLS. Traffic figures
// come from the controller's exporter, which knows nothing about ingresses that
// have served no requests; without this list those would be invisible rather
// than idle.
type Ingress struct {
	Metadata ObjectMeta  `json:"metadata"`
	Spec     IngressSpec `json:"spec"`
}

func (i Ingress) key() string { return "ingress|" + i.Metadata.Namespace + "|" + i.Metadata.Name }

type IngressSpec struct {
	IngressClassName string        `json:"ingressClassName,omitempty"`
	Rules            []IngressRule `json:"rules,omitempty"`
	TLS              []IngressTLS  `json:"tls,omitempty"`
}

type IngressRule struct {
	Host string `json:"host,omitempty"`
}

type IngressTLS struct {
	Hosts []string `json:"hosts,omitempty"`
}
