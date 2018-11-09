package elb

import (
	"context"
	"net/http"

	"github.com/cnrancher/huaweicloud-sdk/common"
)

func (c *Client) CreateListener(ctx context.Context, request *common.ELBListenerRequest) (*common.ELBListenerInfo, error) {
	rtn := common.ELBListenerInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("listeners"),
		request,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) GetListeners(ctx context.Context) (*common.ELBListenerList, error) {
	rtn := common.ELBListenerList{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("listeners"),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) GetListener(ctx context.Context, id string) (*common.ELBListenerInfo, error) {
	rtn := common.ELBListenerInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("listeners", id),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) UpdateListener(ctx context.Context, id string, request *common.UpdatableELBListenerAttribute) (*common.ELBListenerInfo, error) {
	rtn := common.ELBListenerInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodPut,
		c.GetURL("listeners", id),
		request,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) DeleteListener(ctx context.Context, id string) error {
	_, err := c.DoRequest(
		ctx,
		http.MethodDelete,
		c.GetURL("listeners"),
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	return nil
}
