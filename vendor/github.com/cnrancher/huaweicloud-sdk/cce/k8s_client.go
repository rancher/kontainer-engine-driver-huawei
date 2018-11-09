package cce

import (
	"errors"
	"fmt"

	"github.com/cnrancher/huaweicloud-sdk/common"
	"k8s.io/client-go/dynamic"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

type K8sClient struct {
	cceClient    *Client
	CoreV1Client *corev1.CoreV1Client
	AppsV1Client *appsv1.AppsV1Client
}

func GetClusterClient(cluster *common.ClusterInfo, cceClient *Client) (*K8sClient, error) {
	if cluster == nil || cceClient == nil {
		return nil, errors.New("cluster or cce client is nil")
	}
	var err error
	rtn := &K8sClient{
		cceClient: cceClient,
	}
	conf := rest.Config{
		Host:          fmt.Sprintf("https://%s.%s", cluster.MetaData.UID, cceClient.GetAPIHostnameFunc()),
		Transport:     cceClient.GetSigner(),
		ContentConfig: dynamic.ContentConfig(),
	}
	if rtn.CoreV1Client, err = corev1.NewForConfig(&conf); err != nil {
		return nil, err
	}
	if rtn.AppsV1Client, err = appsv1.NewForConfig(&conf); err != nil {
		return nil, err
	}
	return rtn, nil
}
