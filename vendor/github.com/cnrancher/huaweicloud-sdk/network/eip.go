package network

import (
	"context"
	"net/http"

	"github.com/cnrancher/huaweicloud-sdk/common"
)

func (c *Client) CreateEIP(ctx context.Context, info *common.EipAllocArg) (*common.EipInfo, error) {
	rtn := common.EipInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("publicips"),
		info,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) GetEIP(ctx context.Context, id string) (*common.EipInfo, error) {
	rtn := common.EipInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("publicips", id),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) UpdateEIP(ctx context.Context, id string, info *common.EipAssocArg) (*common.EipInfo, error) {
	rtn := common.EipInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodPut,
		c.GetURL("publicips", id),
		info,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) DeleteEIP(ctx context.Context, id string) error {
	_, err := c.DoRequest(
		ctx,
		http.MethodDelete,
		c.GetURL("publicips", id),
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	return nil
}
