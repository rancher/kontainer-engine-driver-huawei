package elb

import (
	"context"
	"net/http"

	"github.com/cnrancher/huaweicloud-sdk/common"
)

func (c *Client) CreateHealthcheck(ctx context.Context, input *common.ELBHealthCheckRequest) (*common.ELBHealthCheckInfo, error) {
	rtn := common.ELBHealthCheckInfo{}
	if _, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("healthcheck"),
		input,
		&rtn,
	); err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) DeleteHealthcheck(ctx context.Context, healthcheckID string) error {
	if _, err := c.DoRequest(
		ctx,
		http.MethodDelete,
		c.GetURL("healthcheck", healthcheckID),
		nil,
		nil,
	); err != nil {
		return err
	}
	return nil
}

func (c *Client) UpdateHealthcheck(ctx context.Context, healthcheckID string, input *common.UpdatableELBHealthCheckAttribute) (*common.ELBHealthCheckInfo, error) {
	rtn := common.ELBHealthCheckInfo{}
	if _, err := c.DoRequest(
		ctx,
		http.MethodPut,
		c.GetURL("healthcheck", healthcheckID),
		input,
		&rtn,
	); err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) GetHealthcheck(ctx context.Context, healthcheckID string) (*common.ELBHealthCheckInfo, error) {
	rtn := common.ELBHealthCheckInfo{}
	if _, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("healthcheck", healthcheckID),
		nil,
		&rtn,
	); err != nil {
		return nil, err
	}
	return &rtn, nil
}
