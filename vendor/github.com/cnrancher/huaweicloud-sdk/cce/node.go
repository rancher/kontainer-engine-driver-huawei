package cce

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"

	"github.com/cnrancher/huaweicloud-sdk/common"
	"golang.org/x/sync/errgroup"
)

func (c *Client) AddNode(ctx context.Context, clusterid string, info *common.NodeInfo) (*common.NodeInfo, error) {
	rtn := common.NodeInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodPost,
		c.GetURL("clusters", clusterid, "nodes"),
		info,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) GetNodes(ctx context.Context, clusterid string) (*common.NodeListInfo, error) {
	rtn := common.NodeListInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("clusters", clusterid, "nodes"),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) GetNode(ctx context.Context, clusterid, id string) (*common.NodeInfo, error) {
	rtn := common.NodeInfo{}
	_, err := c.DoRequest(
		ctx,
		http.MethodGet,
		c.GetURL("clusters", clusterid, "nodes", id),
		nil,
		&rtn,
	)
	if err != nil {
		return nil, err
	}
	return &rtn, nil
}

func (c *Client) DeleteNode(ctx context.Context, clusterid, id string) error {
	_, err := c.DoRequest(
		ctx,
		http.MethodDelete,
		c.GetURL("clusters", clusterid, "nodes", id),
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) DeleteNodes(ctx context.Context, clusterid string, count int) (int64, error) {
	var deletedCount int64
	list, err := c.GetNodes(ctx, clusterid)
	if err != nil {
		return deletedCount, err
	}
	if len(list.Items) < count {
		return deletedCount, errors.New("delete node count is greater than current nodes count")
	}
	eg, subctx := errgroup.WithContext(ctx)
	for i := len(list.Items) - 1; i >= len(list.Items)-count; i-- {
		id := list.Items[i].MetaData.UID
		eg.Go(func() error {
			err := c.DeleteNode(subctx, clusterid, id)
			if err != nil {
				return err
			}
			atomic.AddInt64(&deletedCount, 1)
			return nil
		})
	}
	err = eg.Wait()
	return deletedCount, err
}
