package common

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const (
	DefaultAPIEndpoint = "myhuaweicloud.com"
	DefaultSchema      = "https"
	DefaultCidr        = "192.168.0.0/24"
	DefaultGateway     = "192.168.0.1"
	DefaultVpcName     = "default-vpc"
	DefaultSubnetName  = "default-subnet"
	DefaultTimeout     = 30 * time.Second
	DefaultDuration    = 5 * time.Second
)

const (
	VirtualMachine = "VirtualMachine"
	BareMetal      = "BareMetal"
	Windows        = "Windows"
)

const (
	Available   = "Available"
	Unavailable = "Unavailable"
	ScalingUp   = "ScalingUp"
	ScalingDown = "ScalingDown"
	Creating    = "Creating"
	Deleting    = "Deleting"
	Upgrading   = "Upgrading"
	Resizing    = "Resizing"
	Empty       = "Empty"
)

type ClientInterface interface {
	GetAPIHostname() string
	GetAPIEndpoint() string
	GetBaseURL(endpoint, prefix string) string
	DoRequest(ctx context.Context, serviceType, method, url string, input interface{}) (*http.Response, error)
}

//ErrorInfo Error message
type ErrorInfo struct {
	StatusCode  int                    `json:"-"`
	Code        string                 `json:"code"`
	Description string                 `json:"message"`
	ErrorV1     map[string]interface{} `json:"error,omitempty"`
}

func (e *ErrorInfo) Error() string {
	return fmt.Sprintf("http status code[%d], huawei cloud api error code[%s], message: [%s]", e.StatusCode, e.Code, e.Description)
}

type VpcSt struct {
	Name string `json:"name,omitempty"`
	Cidr string `json:"cidr,omitempty"`
}

type VpcRequest struct {
	Vpc VpcSt `json:"vpc"`
}

type SubnetSt struct {
	Name      string `json:"name"`
	Cidr      string `json:"cidr"`
	GatewayIP string `json:"gateway_ip"`
	VpcID     string `json:"vpc_id"`
}

type SubnetRequest struct {
	Subnet SubnetSt `json:"subnet"`
}

//VpcInfo Used to parse the Vpc response
type VpcInfo struct {
	Vpc VpcResponse `json:"vpc"`
}

type VpcListInfo struct {
	Vpcs []*VpcResponse `json:"vpcs"`
}

//VpcResponse Vpc response fields
type VpcResponse struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Cidr            string   `json:"cidr"`
	Status          string   `json:"status"`
	NoSecurityGroup bool     `json:"noSecurityGroup"`
	Routes          []*Route `json:"routes"`
}

type Route struct {
	Destination string `json:"destination,omitempty"` //cidr format
	Nexthop     string `json:"nexthop,omitempty"`
}

//SubnetInfo Used to parse the Subnet response
type SubnetInfo struct {
	Subnet Subnet `json:"subnet"`
}

type SubnetListInfo struct {
	Subnets []*Subnet `json:"subnets"`
}

// Subnet response fields
type Subnet struct {
	ID               string `json:"id"`                // Specifies a resource ID in UUID format.
	Name             string `json:"name"`              // Specifies the name of the subnet.
	Cidr             string `json:"cidr"`              // Specifies the network segment of the subnet.
	GatewayIP        string `json:"gateway_ip"`        // Specifies the gateway address of the subnet.
	DhcpEnable       bool   `json:"dhcp_enable"`       // Specifies whether the DHCP function is enabled for the subnet.
	PrimaryDNS       string `json:"primary_dns"`       // Specifies the primary IP address of the DNS server on the subnet.
	SecondaryDNS     string `json:"secondary_dns"`     // Specifies the secondary IP address of the DNS server on the subnet.
	AvailabilityZone string `json:"availability_zone"` // Specifies the ID of the AZ to which the subnet belongs.
	VpcID            string `json:"vpc_id"`            // Specifies the ID of the VPC to which the subnet belongs.
	Status           string `json:"status"`            // Specifies the status of the subnet.The value can be ACTIVE, DOWN, BUILD, ERROR, or DELETE.
	NetworkID        string `json:"neutron_network_id"`
}

type NodeConfig struct {
	NodeFlavor          string
	AvailableZone       string
	SSHName             string
	RootVolumeSize      int64
	RootVolumeType      string
	DataVolumeSize      int64
	DataVolumeType      string
	BillingMode         int64
	NodeCount           int64
	NodeOperationSystem string
	PublicIP            PublicIP
	ExtendParam         ExtendParam
	UserPassword        UserPassword
	NodeLabels          map[string]string
}

//MetaInfo cluster struct
type MetaInfo struct {
	Name              string            `json:"name"`
	UID               string            `json:"uid,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	UpdateTimestamp   string            `json:"updateTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

type NetworkInfo struct {
	Vpc           string `json:"vpc,omitempty"`
	Subnet        string `json:"subnet,omitempty"`
	HighwaySubnet string `json:"highwaySubnet,omitempty"`
}

type ContainerNetworkInfo struct {
	Mode string `json:"mode,omitempty"`
	Cidr string `json:"cidr,omitempty"`
}

type AuthenticatingProxy struct {
	Ca string `json:"ca,omitempty"`
}

type Authentication struct {
	Mode                string               `json:"mode,omitempty"` // rbac,x509,authenticating_proxy -- rbac is needed
	AuthenticatingProxy *AuthenticatingProxy `json:"authenticatingProxy,omitempty"`
}

type SpecInfo struct {
	ClusterType      string                `json:"type,omitempty"`
	Flavor           string                `json:"flavor,omitempty"`
	K8sVersion       string                `json:"version,omitempty"`
	Description      string                `json:"description,omitempty"`
	BillingMode      int64                 `json:"billingMode"`
	Authentication   Authentication        `json:"authentication,omitempty"`
	HostNetwork      *NetworkInfo          `json:"hostNetwork,omitempty"`
	ContainerNetwork *ContainerNetworkInfo `json:"containerNetwork,omitempty"`
}

type EndPoints struct {
	URL  string `json:"url,omitempty"`
	Type string `json:"type,omitempty"`
}

type Conditions struct {
	Type               string `json:"type,omitempty"`
	Status             string `json:"status,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastProbeTime      string `json:"lastProbeTime,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
}

type StatusInfo struct {
	Phase      string      `json:"phase,omitempty"`
	JobID      string      `json:"jobID,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	Message    string      `json:"message,omitempty"`
	Conditions *Conditions `json:"conditions,omitempty"`
	Endpoints  []EndPoints `json:"endpoints,omitempty"`
}

type ClusterInfo struct {
	Kind       string      `json:"kind"`
	APIVersion string      `json:"apiVersion"`
	MetaData   MetaInfo    `json:"metadata"`
	Spec       SpecInfo    `json:"spec"`
	Status     *StatusInfo `json:"status,omitempty"`
}

//UpdateInfo update cluster struct
type UpdateInfo struct {
	Description string `json:"description"`
}
type UpdateCluster struct {
	Spec UpdateInfo `json:"spec"`
}

//NodeMetaInfo node struct
type NodeMetaInfo struct {
	Name              string            `json:"name"`
	UID               string            `json:"uid"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	UpdateTimestamp   string            `json:"updateTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

type UserPassword struct {
	UserName string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type NodeLogin struct {
	SSHKey       string       `json:"sshKey,omitempty"`
	UserPassword UserPassword `json:"userPassword,omitempty"`
}

type NodeVolume struct {
	Size       int64  `json:"size"`
	VolumeType string `json:"volumetype"`
}

type Bandwidth struct {
	ChargeMode string `json:"chargemode,omitempty"`
	Size       int64  `json:"size,omitempty"`
	ShareType  string `json:"sharetype,omitempty"`
}

type Eip struct {
	Iptype    string    `json:"iptype,omitempty"`
	Bandwidth Bandwidth `json:"bandwidth,omitempty"`
}

type PublicIP struct {
	Ids   []string `json:"ids,omitempty"`
	Count int64    `json:"count,omitempty"`
	Eip   *Eip     `json:"eip,omitempty"`
}

type ExtendParam struct {
	BMSPeriodType  string `json:"periodType,omitempty"`
	BMSPeriodNum   int64  `json:"periodNum,omitempty"`
	BMSIsAutoRenew string `json:"isAutoRenew,omitempty"`
}

type NodeSpecInfo struct {
	Flavor          string       `json:"flavor"`
	AvailableZone   string       `json:"az"`
	Login           NodeLogin    `json:"login"`
	RootVolume      NodeVolume   `json:"rootVolume"`
	DataVolumes     []NodeVolume `json:"dataVolumes"`
	PublicIP        PublicIP     `json:"publicIP,omitempty"`
	Count           int64        `json:"count,omitempty"`
	BillingMode     int64        `json:"billingMode,omitempty"`
	OperationSystem string       `json:"os,omitempty"`
	ExtendParam     *ExtendParam `json:"extendParam,omitempty"`
}

type NodeStatusInfo struct {
	JobID     string `json:"jobID,omitempty"`
	Phase     string `json:"phase,omitempty"`
	ServerID  string `json:"serverId,omitempty"`
	PublicIP  string `json:"publicIP,omitempty"`
	PrivateIP string `json:"privateIP,omitempty"`
}

type NodeInfo struct {
	Kind       string          `json:"kind"`
	APIVersion string          `json:"apiversion"`
	MetaData   NodeMetaInfo    `json:"metadata"`
	Spec       NodeSpecInfo    `json:"spec"`
	Status     *NodeStatusInfo `json:"status,omitempty"`
}

type NodeListInfo struct {
	Kind       string     `json:"kind,omitempty"`
	APIVersion string     `json:"apiVersion,omitempty"`
	Items      []NodeInfo `json:"items,omitempty"`
}

type ClusterListInfo struct {
	Kind       string        `json:"kind,omitempty"`
	APIVersion string        `json:"apiVersion,omitempty"`
	Items      []ClusterInfo `json:"items,omitempty"`
}

//Cluster cert info
type Cluster struct {
	Server                   string `json:"server,omitempty"`
	CertificateAuthorityData string `json:"certificate-authority-data,omitempty"`
}
type ClusterConfig struct {
	Name    string  `json:"name,omitempty"`
	Cluster Cluster `json:"cluster,omitempty"`
}

type User struct {
	ClientCertificateData string `json:"client-certificate-data,omitempty"`
	ClientKeyData         string `json:"client-key-data,omitempty"`
}
type UserConfig struct {
	Name string `json:"name,omitempty"`
	User User   `json:"user,omitempty"`
}

type Context struct {
	Cluster string `json:"context,omitempty"`
	User    string `json:"user,omitempty"`
}
type ContextConfig struct {
	Name    string  `json:"name,omitempty"`
	Context Context `json:"context,omitempty"`
}

type ClusterCert struct {
	Kind       string          `json:"kind,omitempty"`
	APIVersion string          `json:"apiVersion,omitempty"`
	Clusters   []ClusterConfig `json:"clusters,omitempty"`
	Users      []UserConfig    `json:"users,omitempty"`
	Contexts   []ContextConfig `json:"contexts,omitempty"`
}

//PubIP info
type PubIP struct {
	Type string `json:"type,omitempty"`
}

type BandwidthDesc struct {
	Name    string `json:"name,omitempty"`
	Size    uint32 `json:"size,omitempty"`
	ShrType string `json:"share_type,omitempty"`
	ChgMode string `json:"charge_mode,omitempty"`
}

type EipAllocArg struct {
	EipDesc   PubIP         `json:"publicip,omitempty"`
	BandWidth BandwidthDesc `json:"bandwidth,omitempty"`
}

type EipInfo struct {
	ID            string `json:"id,omitempty"`
	Status        string `json:"status,omitempty"`
	Type          string `json:"type,omitempty"`
	Addr          string `json:"public_ip_address,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	CreateTime    string `json:"create_time,omitempty"`
	BandwidthSize uint32 `json:"bandwidth_size,omitempty"`
}

type EipResp struct {
	Eip EipInfo `json:"publicip,omitempty"`
}

//FixedIP Port info
type FixedIP struct {
	SubnetID  string `json:"subnet_id,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

type PortInfo struct {
	ID       string    `json:"id,omitempty"`
	Status   string    `json:"status,omitempty"`
	FixedIPs []FixedIP `json:"fixed_ips,omitempty"`
}

type Ports struct {
	Ports []PortInfo `json:"ports,omitempty"`
}

type PortDesc struct {
	PortID string `json:"port_id,omitempty"`
}

type EipAssocArg struct {
	Port PortDesc `json:"publicip,omitempty"`
}

//JobMetaData Job status
type JobMetaData struct {
	UID               string `json:"uid,omitemtpy"`
	CreationTimestamp string `json:"creationTimestamp,omitempty"`
	UpdateTimestamp   string `json:"updateTimestamp,omitempty"`
}

type JobSpec struct {
	Type         string `json:"type,omitemtpy"`
	ClusterUID   string `json:"clusterUID,omitempty"`
	ResourceID   string `json:"resourceID,omitempty"`
	ResourceName string `json:"resourceName,omitemtpy"`
}

type JobStatus struct {
	Phase   string `json:"phase,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type JobInfo struct {
	Kind       string      `json:"kind,omitempty"`
	APIVersion string      `json:"apiVersion,omitempty"`
	Metadata   JobMetaData `json:"metadata,omitempty"`
	Spec       JobSpec     `json:"spec,omitempty"`
	Status     JobStatus   `json:"status,omitempty"`
}

//put https://console.huaweicloud.com/cce2.0/rest/cce/api/v2/projects/<project_id>/clusters/<cluster_id>/mastereip
//with HEADER region: cn-north-1
/* request
{
    "spec": {
        "action": "bind",
        "spec": {
            "id": "cc2c806b-6962-44a4-9f32-e6ef9346bb6b"
        },
        "elasticIp": "49.4.5.116"
    }
}
*/
/* resp
{
    "metadata": {},
    "spec": {
        "action": "bind",
        "spec": {
            "id": "cc2c806b-6962-44a4-9f32-e6ef9346bb6b",
            "eip": {
                "bandwidth": {}
            },
            "IsDynamic": false
        },
        "elasticIp": "49.4.5.116"
    },
    "status": {
        "privateEndpoint": "https://192.168.0.73:5443",
        "publicEndpoint": "https://49.4.5.116:5443"
    }
}
*/

type CCEClusterIPBindInfo struct {
	MetaData *MetaInfo       `json:"metadata,omitempty"`
	Spec     BindInfoSpec    `json:"spec,omitempty"`
	Status   *BindInfoStatus `json:"status,omitempty"`
}

type BindInfoSpec struct {
	Action     string          `json:"action,omitempty"`
	ActionSpec *BindActionSpec `json:"spec,omitempty"`
	ElasticIP  string          `json:"elasticIp,omitempty"`
}

type BindActionSpec struct {
	ID        string `json:"id,omitempty"`
	EIP       *Eip   `json:"eip,omitempty"`
	IsDynamic bool   `json:"IsDynamic,omitempty"`
}

type BindInfoStatus struct {
	PrivateEndpoint string `json:"privateEndpoint,omitempty"`
	PublicEndpoint  string `json:"publicEndpoint,omitempty"`
}

type LoadBalancerRequest struct {
	UpdatableLoadBalancerAttribute
	LoadBalancerCommonInfo
	AvailableZone string `json:"az,omitempty"`
	ChargeMode    string `json:"charge_mode,omitempty"` //bandwidth/traffic, default to bandwidth
	EIPType       string `json:"eip_type,omitempty"`    // 5_telcom/5_union/5_bgp/5_sbgp, default to 5_bgp
	TenantID      string `json:"tenantId,omitempty"`
}

type LoadBalancerJobInfo struct {
	URI   string `json:"uri,omitempty"`
	JobID string `json:"job_id,omitempty"`
}

type UpdatableLoadBalancerAttribute struct {
	AdminStateUp int32  `json:"admin_state_up,omitempty"`
	Bandwidth    int64  `json:"bandwidth,omitempty"`
	Description  string `json:"description,omitempty"`
	Name         string `json:"name,omitempty"`
}

type LoadBalancerCommonInfo struct {
	SecurityGroupID string `json:"security_group_id,omitempty"`
	Type            string `json:"type,omitempty"` //Internal or External
	VIPAddress      string `json:"vip_address,omitempty"`
	VIPSubnetID     string `json:"vip_subnet_id,omitempty"`
	VpcID           string `json:"vpc_id,omitempty"`
}

type LoadBalancerInfo struct {
	ID         string `json:"id,omitempty"`
	Status     string `json:"status,omitempty"`
	CreateTime string `json:"create_time,omitempty"`
	UpdateTime string `json:"update_time,omitempty"`

	UpdatableLoadBalancerAttribute
	LoadBalancerCommonInfo
}

type LoadBalancerList struct {
	LoadBalancers []LoadBalancerInfo `json:"loadbalancers,omitempty"`
	InstanceNum   string             `json:"instance_num,omitempty"`
}

type ELBListenerRequest struct {
	ELBListenerCommon
	UpdatableELBListenerAttribute
}

type ELBListenerCommon struct {
	LoadbalancerID    string `json:"loadbalancer_id,omitempty"`
	Protocol          string `json:"protocol,omitempty"` // HTTPS/HTTP/TCP/UDP
	BackendProtocol   string `json:"backend_protocol,omitempty"`
	SessionSticky     bool   `json:"session_sticky,omitempty"`
	StickySessionType string `json:"sticky_session_type,omitempty"`
	CookieTimeout     int32  `json:"cookie_timeout,omitempty"`
}

type ELBListenerInfo struct {
	ID         string `json:"id,omitempty"`
	Status     string `json:"status,omitempty"`
	CreateTime string `json:"create_time,omitempty"`
	UpdateTime string `json:"update_time,omitempty"`

	ELBListenerCommon
	UpdatableELBListenerAttribute
	HealthcheckID *string `json:"healthcheck_id,omitempty"`
}

type UpdatableELBListenerAttribute struct {
	BackendPort             int32  `json:"backend_port,omitempty"`
	CertificateID           string `json:"certificate_id,omitempty"`
	ClientCATLSContainerRef string `json:"client_ca_tls_container_ref,omitempty"`
	Description             string `json:"description,omitempty"`
	LBAlgorithm             string `json:"lb_algorithm,omitempty"` //roundrobin/leastconn/source
	Name                    string `json:"name,omitempty"`
	Port                    int32  `json:"port,omitempty"`
	SSLCiphers              string `json:"ssl_ciphers,omitempty"`
	SSLProtocols            string `json:"ssl_protocols,omitempty"` //TLSv1.2 TLSv1.1 TLSv1, default to TLSv1.2
	TCPTimeout              int32  `json:"tcp_timeout,omitempty"`
	TCPDraining             bool   `json:"tcp_draining,omitempty"`
	TCPDrainingTimeout      int32  `json:"tcp_draining_timeout,omitempty"`
	UDPTimeout              int32  `json:"udp_timeout,omitempty"`
}

type ELBListenerList []ELBListenerInfo

type ELBHealthCheckRequest struct {
	ListenerID string `json:"listener_id,omitempty"`
	UpdatableELBHealthCheckAttribute
}

type UpdatableELBHealthCheckAttribute struct {
	HealthcheckProtocol    string `json:"healthcheck_protocol,omitempty"` //HTTP/TCP
	HealthcheckURI         string `json:"healthcheck_uri,omitempty"`
	HealthcheckConnectPort int32  `json:"healthcheck_connect_port,omitempty"`
	HealthyThreshold       int32  `json:"healthy_threshold,omitempty"`
	UnhealthyThreshold     int32  `json:"unhealthy_threshold,omitempty"`
	HealthcheckTimeout     int32  `json:"healthcheck_timeout,omitempty"`
	HealthcheckInterval    int32  `json:"healthcheck_interval,omitempty"`
}

type ELBHealthCheckInfo struct {
	ID         string `json:"id,omitempty"`
	CreateTime string `json:"create_time,omitempty"`
	UpdateTime string `json:"update_time,omitempty"`

	ListenerID string `json:"listener_id,omitempty"`
	UpdatableELBHealthCheckAttribute
}

type ELBBackendRequestItem struct {
	ServerID string `json:"server_id,omitempty"`
	Address  string `json:"address,omitempty"`
}

type ELBBackendRequest []ELBBackendRequestItem

type ELBBackendListItem struct {
	ID         string `json:"id,omitempty"`
	Status     string `json:"status,omitempty"` //ACTIVE/PENDING/ERROR
	CreateTime string `json:"create_time,omitempty"`
	UpdateTime string `json:"update_time,omitempty"`

	Address       string `json:"address,omitempty"`
	HealthStatus  string `json:"health_status,omitempty"` //NORMAL/ABNORMAL/UNAVAILABLE
	ServerID      string `json:"server_id,omitempty"`
	ServerAddress string `json:"server_address,omitempty"`
	ServerName    string `json:"server_name,omitempty"`
	Listeners     []struct {
		ID string `json:"id,omitempty"`
	} `json:"listeners,omitempty"`
}

type ELBBackendList []*ELBBackendListItem

type ELBQuotaList struct {
	Quotas *struct {
		Resources []struct {
			Type  string `json:"type,omitempty"`
			Used  int64  `json:"used,omitempty"`
			Quota int64  `json:"quota,omitempty"`
			Max   int64  `json:"max,omitempty"`
			Min   int64  `json:"min,omitempty"`
		} `json:"resources,omitempty"`
	} `json:"quotas,omitempty"`
}

type ELBCertificateRequest struct {
	UpdatableELBCertificateAttribute
	ELBCertificateCommon
}

type ELBCertificateCommon struct {
	Domain      string `json:"domain,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
}

type UpdatableELBCertificateAttribute struct {
	Description string `json:"description,omitempty"`
	Name        string `json:"name,omitempty"`
}

type ELBCertificateInfo struct {
	ID         string `json:"id,omitempty"`
	CreateTime string `json:"create_time,omitempty"`
	UpdateTime string `json:"update_time,omitempty"`

	UpdatableELBCertificateAttribute
	ELBCertificateCommon
}

type ELBCertificateList struct {
	Certificates []ELBCertificateInfo `json:"certificates,omitempty"`
	InstanceNum  string               `json:"instance_num,omitempty"`
}

type JobInfoV1 struct {
	Status     string                 `json:"status,omitempty"`
	Entities   map[string]interface{} `json:"entities,omitempty"`
	JobID      string                 `json:"job_id,omitempty"`
	JobType    string                 `json:"job_type,omitempty"`
	ErrorCode  string                 `json:"error_code,omitempty"`
	FailReason string                 `json:"fail_reason,omitempty"`
}
