package elb

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cnrancher/huaweicloud-sdk/common"
)

func (c *Client) AddBackends(ctx context.Context, listenerID string, backends common.ELBBackendRequest) (common.ELBBackendList, error) {
	backendMap := map[string]bool{}
	for _, backend := range backends {
		backendMap[backend.Address] = false
	}
	job := common.LoadBalancerJobInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("listeners", listenerID, "members"),
		backends,
		&job,
	)
	if err != nil {
		return nil, err
	}
	if _, _, err = c.WaitForELBJob(ctx, common.DefaultDuration, common.DefaultTimeout, job.JobID); err != nil {
		return nil, err
	}
	returns, err := c.GetBackends(ctx, listenerID)
	if err != nil {
		return nil, err
	}
	var rtn common.ELBBackendList
	for _, b := range returns {
		if _, ok := backendMap[b.ServerAddress]; ok {
			backendMap[b.ServerAddress] = true
			rtn = append(rtn, b)
		}
	}
	for address, b := range backendMap {
		if !b {
			return nil, fmt.Errorf("backend created for listener %s but not found, job id: %s", listenerID, address)
		}
	}
	return rtn, nil
}

func (c *Client) RemoveBackend(ctx context.Context, listenerID string, backendID string) error {
	job := common.LoadBalancerJobInfo{}
	input := map[string][]map[string]string{}
	input["removeMember"] = []map[string]string{
		map[string]string{"id": backendID},
	}
	if _, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("listeners", listenerID, "members", "action"),
		&input,
		&job,
	); err != nil {
		return err
	}
	if _, _, err := c.WaitForELBJob(ctx, common.DefaultDuration, common.DefaultTimeout, job.JobID); err != nil {
		return err
	}
	return nil
}

func (c *Client) GetBackends(ctx context.Context, listenerID string) ([]*common.ELBBackendListItem, error) {
	rtn := []*common.ELBBackendListItem{}
	if _, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("listeners", listenerID, "members"),
		nil,
		&rtn,
	); err != nil {
		return nil, err
	}
	return rtn, nil
}
