package cce

import "github.com/cnrancher/huaweicloud-sdk/common"

func NewClient(baseClient *common.Client) *Client {
	client := Client{}
	client.Client = *baseClient
	client.SetServiceNameFunc(serviceName)
	client.GetAPIPrefixFunc = client.GetAPIPrefix
	client.GetAPIEndpointFunc = client.GetAPIEndpoint
	client.GetAPIHostnameFunc = client.GetAPIHostname
	client.GetBaseURLFunc = client.GetBaseURL
	return &client
}

func serviceName() string {
	return "cce"
}
