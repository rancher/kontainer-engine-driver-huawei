package main

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/cnrancher/huaweicloud-sdk/cce"
	"github.com/cnrancher/huaweicloud-sdk/common"
	"github.com/cnrancher/huaweicloud-sdk/elb"
	"github.com/cnrancher/huaweicloud-sdk/network"
	"github.com/pkg/errors"
	"github.com/rancher/kontainer-engine/types"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	"k8s.io/api/rbac/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	clusterAdmin = "cluster-admin"
	netesDefault = "netes-default"
)

var configTemplate, _ = template.New("nginx-template").Parse(nginxConfigTemplate)

// GenerateServiceAccountToken generate a serviceAccountToken for clusterAdmin given a rest clientset
func GenerateServiceAccountToken(clientset kubernetes.Interface) (string, error) {
	serviceAccount := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: netesDefault,
		},
	}

	_, err := clientset.CoreV1().ServiceAccounts(defaultNamespace).Create(serviceAccount)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("error creating service account: %v", err)
	}

	adminRole := &v1beta1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterAdmin,
		},
		Rules: []v1beta1.PolicyRule{
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
			{
				NonResourceURLs: []string{"*"},
				Verbs:           []string{"*"},
			},
		},
	}
	clusterAdminRole, err := clientset.RbacV1beta1().ClusterRoles().Get(clusterAdmin, metav1.GetOptions{})
	if err != nil {
		clusterAdminRole, err = clientset.RbacV1beta1().ClusterRoles().Create(adminRole)
		if err != nil {
			return "", fmt.Errorf("error creating admin role: %v", err)
		}
	}

	clusterRoleBinding := &v1beta1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "netes-default-clusterRoleBinding",
		},
		Subjects: []v1beta1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccount.Name,
				Namespace: "default",
				APIGroup:  v1.GroupName,
			},
		},
		RoleRef: v1beta1.RoleRef{
			Kind:     "ClusterRole",
			Name:     clusterAdminRole.Name,
			APIGroup: v1beta1.GroupName,
		},
	}
	if _, err = clientset.RbacV1beta1().ClusterRoleBindings().Create(clusterRoleBinding); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("error creating role bindings: %v", err)
	}

	start := time.Millisecond * 250
	for i := 0; i < 5; i++ {
		time.Sleep(start)
		if serviceAccount, err = clientset.CoreV1().ServiceAccounts(defaultNamespace).Get(serviceAccount.Name, metav1.GetOptions{}); err != nil {
			return "", fmt.Errorf("error getting service account: %v", err)
		}

		if len(serviceAccount.Secrets) > 0 {
			secret := serviceAccount.Secrets[0]
			secretObj, err := clientset.CoreV1().Secrets(defaultNamespace).Get(secret.Name, metav1.GetOptions{})
			if err != nil {
				return "", fmt.Errorf("error getting secret: %v", err)
			}
			if token, ok := secretObj.Data["token"]; ok {
				return string(token), nil
			}
		}
		start = start * 2
	}

	return "", errors.New("failed to fetch serviceAccountToken")
}

func ConvertToRkeConfig(config string) (v3.RancherKubernetesEngineConfig, error) {
	var rkeConfig v3.RancherKubernetesEngineConfig
	if err := yaml.Unmarshal([]byte(config), &rkeConfig); err != nil {
		return rkeConfig, err
	}
	return rkeConfig, nil
}

func fillCreateOptions(driverFlag *types.DriverFlags) {
	driverFlag.Options["display-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the name of the cluster that should be displayed to the user",
	}
	//base client parameters
	driverFlag.Options["project-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the ID of your project to use when creating a cluster",
	}
	driverFlag.Options["region"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The region to launch the cluster",
		Value: "cn-north-1",
	}
	driverFlag.Options["access-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The CCE Access Key ID to use",
	}
	driverFlag.Options["secret-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The CCE Secret Key associated with the Client ID",
	}
	//cluster parameters
	driverFlag.Options["cluster-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The cluster type, VirtualMachine or BareMetal",
		Value: "VirtualMachine",
	}
	driverFlag.Options["cluster-flavor"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The cluster flavor",
		Value: "cce.s2.small",
	}
	driverFlag.Options["cluster-billing-mode"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The bill mode of the cluster",
		Value: "0",
	}
	driverFlag.Options["description"] = &types.Flag{
		Type:  types.StringType,
		Usage: "An optional description of this cluster",
	}
	driverFlag.Options["master-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The kubernetes master version",
		Value: "v1.9.10-r0",
	}
	driverFlag.Options["node-count"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of nodes to create in this cluster",
		Value: "3",
	}
	driverFlag.Options["vpc-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of existing vpc",
	}
	driverFlag.Options["subnet-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of existing subnet",
	}
	driverFlag.Options["highway-subnet"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of existing highway subnet when the cluster-type is BareMetal",
	}
	driverFlag.Options["container-network-mode"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The network mode of container",
		Value: "overlay_l2",
	}
	driverFlag.Options["container-network-cidr"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The network cidr of container",
		Value: "172.16.0.0/16",
	}
	driverFlag.Options["cluster-labels"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "The map of Kubernetes labels (key/value pairs) to be applied to cluster",
	}
	driverFlag.Options["authentiaction-mode"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The Authentication Mode for cce cluster. rbac or authenticating_proxy, default to rbac",
		Value: "rbac",
	}
	driverFlag.Options["authenticating-proxy-ca"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The CA for authenticating proxy, it is required if authentiaction-mode is authenticating_proxy",
	}
	driverFlag.Options["cluster-eip-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of cluster eip. If set, it means that this cluster should be accessed from this eip",
	}
	driverFlag.Options["external-server-enabled"] = &types.Flag{
		Type:  types.BoolType,
		Usage: "To enable cluster elastic IP",
	}
	driverFlag.Options["api-server-elb-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of elb which use to proxy api server",
	}
	//node parameters
	//node management
	driverFlag.Options["node-flavor"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The node flavor",
		Value: "s3.large.2",
	}
	driverFlag.Options["available-zone"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The available zone which the nodes in",
		Value: "cn-north-1a",
	}
	driverFlag.Options["node-labels"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "The map of Kubernetes labels (key/value pairs) to be applied to each node",
	}
	driverFlag.Options["billing-mode"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The bill mode of the node",
		Value: "0",
	}
	driverFlag.Options["bms-period-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The period type",
		Value: "month",
	}
	driverFlag.Options["bms-period-num"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of period",
		Value: "1",
	}
	driverFlag.Options["bms-is-auto-renew"] = &types.Flag{
		Type:  types.StringType,
		Usage: "If the period is auto renew",
		Value: "false",
	}
	//node common
	driverFlag.Options["node-operation-system"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The operation system of nodes",
		Value: "EulerOS 2.2",
	}
	driverFlag.Options["ssh-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of ssh key-pair",
	}
	driverFlag.Options["user-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The user name to log in the host. This flag will be ignored if ssh-key is set.",
	}
	driverFlag.Options["password"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The password to log in the host This flag will be ignored if ssh-key is set.",
	}
	//node data
	driverFlag.Options["root-volume-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Size of the system disk attached to each node",
		Value: "40",
	}
	driverFlag.Options["root-volume-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Type of the system disk attached to each node",
		Value: "SATA",
	}
	driverFlag.Options["data-volume-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Size of the data disk attached to each node",
		Value: "100",
	}
	driverFlag.Options["data-volume-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Type of the data disk attached to each node",
		Value: "SATA",
	}
	//node network
	driverFlag.Options["eip-ids"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "The list of the exist EIPs",
	}
	driverFlag.Options["eip-count"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of eips to be created",
		Value: "3",
	}
	driverFlag.Options["eip-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The type of bandwidth",
		Value: "5-bgp",
	}
	driverFlag.Options["eip-charge-mode"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The charge mode of the bandwidth",
		Value: "traffic",
	}
	driverFlag.Options["eip-bandwidth-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The size of bandwidth",
		Value: "10",
	}
	driverFlag.Options["eip-share-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The share type of bandwidth",
		Value: "PER",
	}
}

func createVPC(ctx context.Context, networkClient *network.Client, state *state) (*common.VpcInfo, error) {
	logrus.Info("setting up vpc...")
	vpcReq := &common.VpcRequest{
		Vpc: common.VpcSt{
			Name: state.ClusterName + "-vpc",
			Cidr: common.DefaultCidr,
		},
	}
	rtn, err := networkClient.CreateVPC(ctx, vpcReq)
	if err != nil {
		return nil, errors.Wrap(err, "error creating vpc")
	}
	state.VpcID = rtn.Vpc.ID
	if err = common.WaitForCompleteWithError(ctx, func(ictx context.Context) error {
		_, err := networkClient.GetVPC(ictx, state.VpcID)
		return err
	}); err != nil {
		return nil, err
	}
	logrus.Infof("bring up vpc %s success", state.VpcID)
	return networkClient.GetVPC(ctx, state.VpcID)
}

func createSubnet(ctx context.Context, networkClient *network.Client, state *state) (*common.SubnetInfo, error) {
	logrus.Info("setting up subnet...")
	subnetReq := &common.SubnetInfo{
		Subnet: common.Subnet{
			Name:         state.ClusterName + "-subnet",
			Cidr:         common.DefaultCidr,
			GatewayIP:    common.DefaultGateway,
			VpcID:        state.VpcID,
			PrimaryDNS:   "114.114.114.114",
			SecondaryDNS: "8.8.8.8",
			DhcpEnable:   true,
		},
	}
	rtn, err := networkClient.CreateSubnet(ctx, subnetReq)
	if err != nil {
		return nil, errors.Wrap(err, "error creating subnet")
	}
	state.SubnetID = rtn.Subnet.ID
	if err = common.WaitForCompleteWithError(ctx, func(ictx context.Context) error {
		_, err := networkClient.GetSubnet(ctx, state.SubnetID)
		return err
	}); err != nil {
		return nil, err
	}
	logrus.Infof("set up subnet %s success", state.SubnetID)
	return networkClient.GetSubnet(ctx, state.SubnetID)
}

func createCluster(ctx context.Context, cceClient *cce.Client, state *state) (*common.ClusterInfo, error) {
	logrus.Info("creating cluster...")
	clusterReq := getClusterRequestFromState(*state)
	rtn, err := cceClient.CreateCluster(ctx, clusterReq)
	if err != nil {
		return nil, errors.Wrap(err, "error creating cluster")
	}
	state.ClusterID = rtn.MetaData.UID
	state.ClusterJobID = rtn.Status.JobID
	ok, _, err := cceClient.WaitForJobReadyV3(ctx, 20*time.Second, 30*time.Minute, state.ClusterJobID)
	if !ok {
		return nil, errors.Wrapf(err, "error waiting for cluster job %s", state.ClusterJobID)
	}
	logrus.Infof("cluster provisioned successfully")
	return cceClient.GetCluster(ctx, state.ClusterID)
}

func createNodes(ctx context.Context, cceClient *cce.Client, state *state) error {
	logrus.Infof("creating worker nodes...")
	nodeReq := getNodeRequirement(*state, state.NodeConfig.NodeCount)
	_, err := cceClient.AddNode(ctx, state.ClusterID, nodeReq)
	if err != nil {
		logrus.WithError(err).Warnf("trying to create node for cluster %s again", state.ClusterID)
		_, err = cceClient.AddNode(ctx, state.ClusterID, nodeReq)
		//retry fail
		if err != nil {
			return errors.Wrap(err, "error when creating node(s) for cluster")
		}
	}
	if err := common.CustomWaitForCompleteUntilTrue(ctx, 20*time.Second, 10*time.Minute, func(ictx context.Context) (bool, error) {
		nodeList, err := cceClient.GetNodes(ictx, state.ClusterID)
		if err != nil {
			return false, err
		}
		for _, node := range nodeList.Items {
			if node.Status.Phase != "Active" {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		logrus.WithError(err).Errorf("error creating nodes for cluster %s", state.ClusterID)
		return errors.Wrapf(err, "error creating nodes for cluster %s", state.ClusterID)
	}
	logrus.Info("creating worker nodes complete")
	return nil
}

func createEIP(ctx context.Context, networkClient *network.Client, state *state) (*common.EipInfo, error) {
	logrus.Info("creating EIP ...")
	eipReq := &common.EipAllocArg{
		EipDesc: common.PubIP{
			Type: "5_bgp",
		},
		BandWidth: common.BandwidthDesc{
			Name:    state.ClusterName,
			Size:    10,
			ShrType: "PER",
			ChgMode: "traffic",
		},
	}
	rtn, err := networkClient.CreateEIP(ctx, eipReq)
	if err != nil {
		return nil, fmt.Errorf("error creating eip for cluster %s", state.ClusterID)
	}
	state.ClusterEIPID = rtn.ID
	logrus.Info("create EIP success")
	return rtn, nil
}

func createELB(ctx context.Context, elbClient *elb.Client, eip *common.EipInfo, state *state) (*common.LoadBalancerInfo, error) {
	logrus.Info("creating ELB")
	input := common.LoadBalancerRequest{
		ChargeMode:    "traffic",
		AvailableZone: state.NodeConfig.AvailableZone,
		TenantID:      elbClient.ProjectID,

		UpdatableLoadBalancerAttribute: common.UpdatableLoadBalancerAttribute{
			AdminStateUp: 1,
			Name:         state.ClusterName + "-entrypoint",
			Description:  fmt.Sprintf("ELB for cce cluster %s api server", state.ClusterName),
		},
		LoadBalancerCommonInfo: common.LoadBalancerCommonInfo{
			Type:  "External",
			VpcID: state.VpcID,
		},
	}

	if eip == nil {
		input.ChargeMode = "traffic"
		input.EIPType = "5_bgp"
		input.Bandwidth = 10
	} else {
		input.VIPAddress = eip.Addr
	}

	info, err := elbClient.CreateLoadBalancer(ctx, &input)
	if err != nil {
		return nil, err
	}
	logrus.Info("create ELB success")
	state.APIServerELBID = info.ID
	return info, nil
}

func createListener(ctx context.Context, elbClient *elb.Client, state *state) (*common.ELBListenerInfo, error) {
	logrus.Infof("creating listener for %s ...", state.APIServerELBID)
	input := common.ELBListenerRequest{
		ELBListenerCommon: common.ELBListenerCommon{
			LoadbalancerID:  state.APIServerELBID,
			Protocol:        "TCP",
			BackendProtocol: "TCP",
			SessionSticky:   true,
		},
		UpdatableELBListenerAttribute: common.UpdatableELBListenerAttribute{
			BackendPort: 3389,
			LBAlgorithm: "roundrobin",
			Name:        state.ClusterName + "-apiserver",
			Port:        5443,
			TCPTimeout:  10,
			Description: fmt.Sprintf("proxy cce cluster %s apiserver", state.ClusterName),
		},
	}
	resp, err := elbClient.CreateListener(ctx, &input)
	if err != nil {
		return nil, err
	}
	logrus.Info("create listener success")
	return resp, nil
}

func getStateFromOptions(driverOptions *types.DriverOptions) (state, error) {
	state := state{
		NodeConfig: &common.NodeConfig{
			NodeLabels: map[string]string{},
			PublicIP: common.PublicIP{
				Eip: &common.Eip{},
			},
		},
		ClusterLabels: map[string]string{},
	}
	state.ClusterName = getValueFromDriverOptions(driverOptions, types.StringType, "name").(string)
	state.DisplayName = getValueFromDriverOptions(driverOptions, types.StringType, "display-name", "displayName").(string)
	state.ProjectID = getValueFromDriverOptions(driverOptions, types.StringType, "project-id", "projectId").(string)
	state.Region = getValueFromDriverOptions(driverOptions, types.StringType, "region").(string)
	state.Description = getValueFromDriverOptions(driverOptions, types.StringType, "description").(string)
	state.ClusterType = getValueFromDriverOptions(driverOptions, types.StringType, "cluster-type", "clusterType").(string)
	state.ClusterFlavor = getValueFromDriverOptions(driverOptions, types.StringType, "cluster-flavor", "clusterFlavor").(string)
	state.ClusterVersion = getValueFromDriverOptions(driverOptions, types.StringType, "master-version", "masterVersion").(string)
	state.AccessKey = getValueFromDriverOptions(driverOptions, types.StringType, "access-key", "accessKey").(string)
	state.SecretKey = getValueFromDriverOptions(driverOptions, types.StringType, "secret-key", "secretKey").(string)
	state.ClusterBillingMode = getValueFromDriverOptions(driverOptions, types.IntType, "cluster-billing-mode", "clusterBillingMode").(int64)
	state.VpcID = getValueFromDriverOptions(driverOptions, types.StringType, "vpc-id", "vpcId").(string)
	state.SubnetID = getValueFromDriverOptions(driverOptions, types.StringType, "subnet-id", "subnetId").(string)
	state.ContainerNetworkMode = getValueFromDriverOptions(driverOptions, types.StringType, "container-network-mode", "containerNetworkMode").(string)
	state.ContainerNetworkCidr = getValueFromDriverOptions(driverOptions, types.StringType, "container-network-cidr", "containerNetworkCidr").(string)
	state.HighwaySubnet = getValueFromDriverOptions(driverOptions, types.StringType, "highway-subnet", "highwaySubnet").(string)
	state.NodeConfig.NodeFlavor = getValueFromDriverOptions(driverOptions, types.StringType, "node-flavor", "nodeFlavor").(string)
	state.NodeConfig.AvailableZone = getValueFromDriverOptions(driverOptions, types.StringType, "available-zone", "availableZone").(string)
	state.NodeConfig.SSHName = getValueFromDriverOptions(driverOptions, types.StringType, "ssh-key", "sshKey").(string)
	state.NodeConfig.RootVolumeSize = getValueFromDriverOptions(driverOptions, types.IntType, "root-volume-size", "rootVolumeSize").(int64)
	state.NodeConfig.RootVolumeType = getValueFromDriverOptions(driverOptions, types.StringType, "root-volume-type", "rootVolumeType").(string)
	state.NodeConfig.DataVolumeSize = getValueFromDriverOptions(driverOptions, types.IntType, "data-volume-size", "dataVolumeSize").(int64)
	state.NodeConfig.DataVolumeType = getValueFromDriverOptions(driverOptions, types.StringType, "data-volume-type", "dataVolumeType").(string)
	state.NodeConfig.BillingMode = getValueFromDriverOptions(driverOptions, types.IntType, "billing-mode", "billingMode").(int64)
	state.NodeConfig.NodeCount = getValueFromDriverOptions(driverOptions, types.IntType, "node-count", "nodeCount").(int64)
	state.NodeConfig.PublicIP.Count = getValueFromDriverOptions(driverOptions, types.IntType, "eip-count", "eipCount").(int64)
	state.NodeConfig.PublicIP.Eip.Iptype = getValueFromDriverOptions(driverOptions, types.StringType, "eip-type", "eipType").(string)
	state.NodeConfig.PublicIP.Eip.Bandwidth.Size = getValueFromDriverOptions(driverOptions, types.IntType, "eip-bandwidth-size", "eipBandwidthSize").(int64)
	state.NodeConfig.PublicIP.Eip.Bandwidth.ShareType = getValueFromDriverOptions(driverOptions, types.StringType, "eip-share-type", "eipShareType").(string)
	state.NodeConfig.PublicIP.Eip.Bandwidth.ChargeMode = getValueFromDriverOptions(driverOptions, types.StringType, "eip-charge-mode", "eipChargeMode").(string)
	state.NodeConfig.NodeOperationSystem = getValueFromDriverOptions(driverOptions, types.StringType, "node-operation-system", "nodeOperationSystem").(string)
	state.NodeConfig.ExtendParam.BMSPeriodType = getValueFromDriverOptions(driverOptions, types.StringType, "bms-period-type", "bmsPeriodType").(string)
	state.NodeConfig.ExtendParam.BMSPeriodNum = getValueFromDriverOptions(driverOptions, types.IntType, "bms-period-num", "bmsPeriodNum").(int64)
	state.NodeConfig.ExtendParam.BMSIsAutoRenew = getValueFromDriverOptions(driverOptions, types.StringType, "bms-is-auto-renew", "bmsIsAutoRenew").(string)
	state.NodeConfig.UserPassword.UserName = getValueFromDriverOptions(driverOptions, types.StringType, "user-name", "userName").(string)
	state.NodeConfig.UserPassword.Password = getValueFromDriverOptions(driverOptions, types.StringType, "password").(string)
	state.AuthenticatingProxyCa = getValueFromDriverOptions(driverOptions, types.StringType, "authenticating-proxy-ca", "authenticatingProxyCa").(string)
	state.ExternalServerEnabled = getValueFromDriverOptions(driverOptions, types.BoolType, "external-server-enabled", "externalServerEnabled").(bool)
	state.ClusterEIPID = getValueFromDriverOptions(driverOptions, types.StringType, "cluster-eip-id", "clusterEipId").(string)
	state.AuthMode = getValueFromDriverOptions(driverOptions, types.StringType, "authentiaction-mode", "authentiactionMode").(string)
	state.APIServerELBID = getValueFromDriverOptions(driverOptions, types.StringType, "api-server-elb-id", "apiServerELBId").(string)

	eipIDs := getValueFromDriverOptions(driverOptions, types.StringSliceType, "eip-ids", "eipIds").(*types.StringSlice)
	for _, eipID := range eipIDs.Value {
		logrus.Debugf("Eip: %s", eipID)
		state.NodeConfig.PublicIP.Ids = append(state.NodeConfig.PublicIP.Ids, eipID)
	}
	nodeLabels := getValueFromDriverOptions(driverOptions, types.StringSliceType, "node-labels", "nodeLabels").(*types.StringSlice)
	for _, nodeLabel := range nodeLabels.Value {
		kv := strings.Split(nodeLabel, "=")
		if len(kv) == 2 {
			state.NodeConfig.NodeLabels[kv[0]] = kv[1]
		}
	}
	clusterLabels := getValueFromDriverOptions(driverOptions, types.StringSliceType, "labels").(*types.StringSlice)
	for _, clusterLabel := range clusterLabels.Value {
		kv := strings.Split(clusterLabel, "=")
		if len(kv) == 2 {
			state.ClusterLabels[kv[0]] = kv[1]
		}
	}
	logrus.Debugf("state is %#v", state)
	logrus.Debugf("node config is %#v", *state.NodeConfig)
	return state, state.validate()
}

func getNodeRequirement(state state, count int64) *common.NodeInfo {
	nodeconf := &common.NodeInfo{
		Kind:       "Node",
		APIVersion: "v3",
		MetaData: common.NodeMetaInfo{
			Labels: state.NodeConfig.NodeLabels,
		},
		Spec: common.NodeSpecInfo{
			Flavor:        state.NodeConfig.NodeFlavor,
			AvailableZone: state.NodeConfig.AvailableZone,
			Login: common.NodeLogin{
				SSHKey: state.NodeConfig.SSHName,
				UserPassword: common.UserPassword{
					UserName: state.NodeConfig.UserPassword.UserName,
					Password: state.NodeConfig.UserPassword.Password,
				},
			},
			RootVolume: common.NodeVolume{
				Size:       state.NodeConfig.RootVolumeSize,
				VolumeType: state.NodeConfig.RootVolumeType,
			},
			DataVolumes: []common.NodeVolume{
				{
					Size:       state.NodeConfig.DataVolumeSize,
					VolumeType: state.NodeConfig.DataVolumeType,
				},
			},
			PublicIP:        common.PublicIP{},
			Count:           count,
			BillingMode:     state.NodeConfig.BillingMode,
			OperationSystem: state.NodeConfig.NodeOperationSystem,
			ExtendParam:     nil,
		},
	}

	extendParam := common.ExtendParam{
		BMSPeriodType:  state.NodeConfig.ExtendParam.BMSPeriodType,
		BMSPeriodNum:   state.NodeConfig.ExtendParam.BMSPeriodNum,
		BMSIsAutoRenew: state.NodeConfig.ExtendParam.BMSIsAutoRenew,
	}

	if state.NodeConfig.ExtendParam.BMSPeriodType != "" &&
		state.NodeConfig.ExtendParam.BMSPeriodNum != 0 &&
		state.NodeConfig.ExtendParam.BMSIsAutoRenew != "" {
		nodeconf.Spec.ExtendParam = &extendParam
	}

	if len(state.NodeConfig.PublicIP.Ids) > 0 {
		nodeconf.Spec.PublicIP.Ids = state.NodeConfig.PublicIP.Ids
	}
	if nodeconf.Spec.PublicIP.Count > 0 {
		nodeconf.Spec.PublicIP.Count = state.NodeConfig.PublicIP.Count
		nodeconf.Spec.PublicIP.Eip = &common.Eip{
			Iptype: state.NodeConfig.PublicIP.Eip.Iptype,
			Bandwidth: common.Bandwidth{
				ChargeMode: state.NodeConfig.PublicIP.Eip.Bandwidth.ChargeMode,
				Size:       state.NodeConfig.PublicIP.Eip.Bandwidth.Size,
				ShareType:  state.NodeConfig.PublicIP.Eip.Bandwidth.ShareType,
			},
		}
	}

	return nodeconf
}

func createDefaultNamespace(client *cce.K8sClient) error {
	if _, err := client.CoreV1Client.Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultNamespace,
		},
	}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func createNginxConfig(client *cce.K8sClient, apiserver string) (*v1.ConfigMap, error) {
	logrus.Info("creating nginx config for cluster apiserver proxy..")
	entry := nginxConfig{
		APIServerHost: apiserver,
	}
	var configBuf bytes.Buffer
	if err := configTemplate.Execute(&configBuf, entry); err != nil {
		return nil, err
	}
	rtn := v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-conf",
			Namespace: defaultNamespace,
		},
		Data: map[string]string{
			"nginx.conf": configBuf.String(),
		},
	}
	if _, err := client.CoreV1Client.ConfigMaps(defaultNamespace).Create(&rtn); err != nil {
		return nil, err
	}
	logrus.Infof("create nginx proxy config[%s/%s] success", rtn.Namespace, rtn.Name)
	return &rtn, nil
}

func createNginxDaemonSet(client *cce.K8sClient, config *v1.ConfigMap) error {
	logrus.Info("creating nginx proxy daemon set...")
	labels := map[string]string{
		"app": "apiserver-proxy",
	}
	daemonSet := appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "apiserver-proxy",
			Namespace: defaultNamespace,
			Labels:    labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: v1.PodSpec{
					HostNetwork: true,
					Volumes: []v1.Volume{
						v1.Volume{
							Name: "conf",
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{
										Name: config.Name,
									},
								},
							},
						},
					},
					Containers: []v1.Container{
						v1.Container{
							Name:  "apiserver-proxy",
							Image: "nginx",
							Ports: []v1.ContainerPort{
								v1.ContainerPort{
									Name:          "nginx",
									Protocol:      v1.ProtocolTCP,
									ContainerPort: 3389,
									HostPort:      3389,
								},
							},
							VolumeMounts: []v1.VolumeMount{
								v1.VolumeMount{
									Name:      "conf",
									MountPath: "/etc/nginx/nginx.conf",
									SubPath:   "nginx.conf",
								},
							},
						},
					},
				},
			},
		},
	}
	if _, err := client.AppsV1Client.DaemonSets(defaultNamespace).Create(&daemonSet); err != nil {
		return err
	}
	logrus.Info("create nginx proxy daemon set success")
	return nil
}

func createProxyDaemonSets(ctx context.Context, client *cce.Client, clusterInfo *common.ClusterInfo, state *state) ([]common.NodeInfo, error) {
	k8sClient, err := cce.GetClusterClient(clusterInfo, client)
	if err != nil {
		return nil, err
	}

	if err := createDefaultNamespace(k8sClient); err != nil {
		return nil, err
	}

	var config *v1.ConfigMap
	address := ""
	for _, endpoint := range clusterInfo.Status.Endpoints {
		if endpoint.Type == "Internal" {
			u, err := url.Parse(endpoint.URL)
			if err != nil {
				return nil, err
			}
			address = u.Host
		}
	}
	if config, err = createNginxConfig(k8sClient, address); err != nil {
		return nil, err
	}

	if err := createNginxDaemonSet(k8sClient, config); err != nil {
		return nil, err
	}

	nodes, err := client.GetNodes(ctx, clusterInfo.MetaData.UID)
	if err != nil {
		return nil, err
	}

	return nodes.Items, nil
}

func addBackends(ctx context.Context, listenerID string, elbClient *elb.Client, backends []common.NodeInfo) (common.ELBBackendList, error) {
	logrus.Infof("creating backends for listener %s", listenerID)
	input := common.ELBBackendRequest{}
	for _, backend := range backends {
		input = append(input, common.ELBBackendRequestItem{
			ServerID: backend.Status.ServerID,
			Address:  backend.Status.PrivateIP,
		})
	}
	list, err := elbClient.AddBackends(ctx, listenerID, input)
	if err != nil {
		return nil, err
	}
	logrus.Info("create backend success")
	return list, err
}

func deleteBackendForELB(ctx context.Context, elbID string, elbClient *elb.Client) error {
	listeners, err := elbClient.GetListeners(ctx)
	if err != nil {
		return err
	}
	var toDelete []string
	for _, l := range *listeners {
		if l.LoadbalancerID == elbID {
			toDelete = append(toDelete, l.ID)
		}
	}
	for _, id := range toDelete {
		backends, err := elbClient.GetBackends(ctx, id)
		if err != nil {
			return err
		}
		for _, backend := range backends {
			if err := elbClient.RemoveBackend(ctx, id, backend.ID); err != nil {
				return err
			}
		}
	}
	return nil
}
