package common

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	JobSuccess = "success"
	JobRunning = "running"
	JobFail    = "fail"
	JobInit    = "init"
)

func (c *Client) WaitForJobReadyV3(ctx context.Context, duration, timeout time.Duration, jobID string) (bool, *JobInfo, error) {
	var lastJobInfo *JobInfo
	err := CustomWaitForCompleteUntilTrue(ctx, duration, timeout, func(ictx context.Context) (bool, error) {
		logrus.Infof("Querying job %s for %s", jobID, c.getServiceFunc())
		var jobInfo JobInfo
		_, err := c.DoRequest(
			ictx,
			http.MethodGet,
			c.GetURL("jobs", jobID),
			nil,
			&jobInfo,
		)
		if err != nil {
			return false, err
		}
		lastJobInfo = &jobInfo
		switch strings.ToLower(jobInfo.Status.Phase) {
		case JobSuccess:
			return true, nil
		case JobRunning:
			logrus.Debugf("job %s is still running", jobID)
			return false, nil
		default:
			return false, fmt.Errorf("error for waiting %s job for %s", c.getServiceFunc(), jobID)
		}
	})
	return err == nil, lastJobInfo, err
}
