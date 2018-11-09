package cce

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cnrancher/huaweicloud-sdk/common"
	"github.com/sirupsen/logrus"
)

type Client struct {
	common.Client
}

func (c *Client) CreateCluster(ctx context.Context, cluster *common.ClusterInfo) (*common.ClusterInfo, error) {
	logrus.Info("Creating Cluster")
	var clusterResp common.ClusterInfo
	_, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("clusters"),
		cluster,
		&clusterResp,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating cluster: %v", err)
	}

	return &clusterResp, nil
}

func (c *Client) UpdateCluster(ctx context.Context, id string, info *common.ClusterInfo) (*common.ClusterInfo, error) {
	return nil, nil
}

func (c *Client) GetCluster(ctx context.Context, id string) (*common.ClusterInfo, error) {
	rtn := common.ClusterInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("clusters", id),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, fmt.Errorf("error deleting cluster: %v", err)
	}
	return &rtn, nil
}

func (c *Client) GetClusters(ctx context.Context) (*common.ClusterListInfo, error) {
	rtn := common.ClusterListInfo{}
	_, err := c.DoRequest(ctx,
		http.MethodGet,
		c.GetURL("clusters"),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, fmt.Errorf("error getting clusters")
	}
	return &rtn, err
}

func (c *Client) DeleteCluster(ctx context.Context, id string) error {
	logrus.Infof("Deleting Cluster %s", id)
	_, err := c.DoRequest(
		ctx,
		http.MethodDelete,
		c.GetURL("clusters", id),
		nil,
		nil,
	)
	if err != nil {
		return fmt.Errorf("error deleting cluster: %v", err)
	}

	return common.WaitForDeleteComplete(ctx, func(ictx context.Context) error {
		_, err := c.GetCluster(ctx, id)
		return err
	})
}

//Just not working
// func (c *Client) CreatePublicEndpoint(clusterid string, info *common.CCEClusterIPBindInfo) (*common.CCEClusterIPBindInfo, error) {
// 	urlPrefix := "/cce2.0/rest/cce/api/v2"
// 	endpoint := "console.huaweicloud.com"
// 	url := c.GetURL(endpoint, urlPrefix, clusterid, "mastereip")
// 	body, err := json.Marshal(info)
// 	if err != nil {
// 		return nil, err
// 	}
// 	resp, err := c.Client.DoRequest(http.MethodPut, url, bytes.NewBuffer(body))
// 	if err != nil {
// 		return nil, err
// 	}
// 	rtndata, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, err
// 	}
// 	infoRtn := common.CCEClusterIPBindInfo{}
// 	if err = json.Unmarshal(rtndata, &infoRtn); err != nil {
// 		return nil, err
// 	}

// 	return &infoRtn, nil
// }

// func (c *Client) AddMasterIP(ctx context.Context, clusterID string, input *common.CCEClusterIPBindInfo) (*common.CCEClusterIPBindInfo, error) {
// 	rtn := common.CCEClusterIPBindInfo{}
// 	if _, err := c.DoRequest(
// 		ctx,
// 		http.MethodPut,
// 		c.GetURL("clusters", clusterID, "mastereip"),
// 		input,
// 		&rtn,
// 	); err != nil {
// 		return nil, err
// 	}

// 	return &rtn, nil
// }
