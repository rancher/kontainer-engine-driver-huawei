package cce

import (
	"context"
	"net/http"

	"github.com/cnrancher/huaweicloud-sdk/common"
)

func (c *Client) GetClusterCert(ctx context.Context, clusterid string) (*common.ClusterCert, error) {
	rtn := common.ClusterCert{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("clusters", clusterid, "clustercert"),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}
