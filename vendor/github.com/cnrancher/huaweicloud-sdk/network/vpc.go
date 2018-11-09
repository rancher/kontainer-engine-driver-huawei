package network

import (
	"context"
	"net/http"

	"github.com/cnrancher/huaweicloud-sdk/common"
)

func (c *Client) CreateVPC(ctx context.Context, request *common.VpcRequest) (*common.VpcInfo, error) {
	rtn := common.VpcInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("vpcs"),
		request,
		&rtn,
	)
	if err != nil {
		return nil, err
	}

	return &rtn, nil
}

func (c *Client) GetVPC(ctx context.Context, id string) (*common.VpcInfo, error) {
	rtn := common.VpcInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("vpcs", id),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, err
	}

	return &rtn, nil
}

func (c *Client) DeleteVPC(ctx context.Context, id string) error {
	_, err := c.DoRequest(
		ctx,
		http.MethodDelete,
		c.GetURL("vpcs", id),
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	return common.WaitForDeleteComplete(ctx, func(ictx context.Context) error {
		_, err := c.GetVPC(ictx, id)
		return err
	})
}

func (c *Client) GetVPCs(ctx context.Context) (*common.VpcListInfo, error) {
	var rtn common.VpcListInfo
	if _, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("vpcs"),
		nil,
		&rtn,
	); err != nil {
		return nil, err
	}
	return &rtn, nil
}
