package elb

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cnrancher/huaweicloud-sdk/common"
	"github.com/sirupsen/logrus"
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
	return fmt.Sprintf("%s%s/%s/elbaas", c.GetAPIEndpointFunc(), c.GetAPIPrefixFunc(), c.ProjectID)
}

func serviceName() string {
	return "elb"
}

func prefix() string {
	return "/v1.0"
}

func (c *Client) WaitForELBJob(ctx context.Context, duration, timeout time.Duration, jobID string) (bool, *common.JobInfoV1, error) {
	var lastJobInfo *common.JobInfoV1
	err := common.CustomWaitForCompleteUntilTrue(ctx, duration, timeout, func(ictx context.Context) (bool, error) {
		logrus.Infof("Querying job %s for %s", jobID, "elb")
		var jobInfo common.JobInfoV1
		_, err := c.DoRequest(
			ictx,
			http.MethodGet,
			strings.Replace(c.GetURL("jobs", jobID), "/elbaas", "", -1),
			nil,
			&jobInfo,
		)
		if err != nil {
			return false, err
		}
		lastJobInfo = &jobInfo
		switch strings.ToLower(jobInfo.Status) {
		case common.JobSuccess:
			return true, nil
		case common.JobRunning:
			logrus.Debugf("job %s is still running", jobID)
			return false, nil
		default:
			return false, fmt.Errorf("error for waiting %s job for %s", "elb", jobID)
		}
	})
	logrus.Debugf("%#v\n", *lastJobInfo)
	return err == nil, lastJobInfo, err
}
