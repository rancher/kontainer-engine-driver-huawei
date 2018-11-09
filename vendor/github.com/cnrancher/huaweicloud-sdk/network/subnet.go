package network

import (
	"context"
	"net/http"

	"github.com/cnrancher/huaweicloud-sdk/common"
	"github.com/sirupsen/logrus"
)

func (c *Client) CreateSubnet(ctx context.Context, request *common.SubnetInfo) (*common.SubnetInfo, error) {
	logrus.Info("Creating subnet")
	rtn := common.SubnetInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("subnets"),
		request,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) GetSubnet(ctx context.Context, id string) (*common.SubnetInfo, error) {
	rtn := common.SubnetInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("subnets", id),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) DeleteSubnet(ctx context.Context, id string) error {
	logrus.Infof("Deleting subnet %s", id)
	_, err := c.DoRequest(
		ctx,
		http.MethodDelete,
		c.GetURL("subnets", id),
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	return common.WaitForDeleteComplete(ctx, func(ictx context.Context) error {
		_, err := c.GetSubnet(ictx, id)
		return err
	})
}

func (c *Client) GetSubnets(ctx context.Context) (*common.SubnetListInfo, error) {
	var rtn common.SubnetListInfo
	if _, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("subnets"),
		nil,
		&rtn,
	); err != nil {
		return nil, err
	}
	return &rtn, nil
}
