package network

import (
	"fmt"

	"github.com/cnrancher/huaweicloud-sdk/common"
)

type Client struct {
	common.Client
}

func NewClient(baseClient *common.Client) *Client {
	c := &Client{
		Client: *baseClient,
	}
	c.GetBaseURLFunc = c.GetBaseURL
	c.SetServiceNameFunc(serviceName)
	c.GetAPIPrefixFunc = prefix
	c.GetAPIEndpointFunc = c.GetAPIEndpoint
	c.GetAPIHostnameFunc = c.GetAPIHostname
	return c
}

func (c *Client) GetBaseURL() string {
	return fmt.Sprintf("%s%s/%s", c.GetAPIEndpointFunc(), c.GetAPIPrefixFunc(), c.ProjectID)
}

func serviceName() string {
	return "vpc"
}

func prefix() string {
	return "/v1"
}
