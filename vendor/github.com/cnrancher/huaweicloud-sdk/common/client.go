package common

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cnrancher/huaweicloud-sdk/signer"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Client struct {
	AccessKey   string
	SecretKey   string
	ProjectID   string
	Region      string
	APIEndpoint string
	HTTPClient  http.Client
	dryRun      bool
	signer      *signer.Signer

	GetAPIEndpointFunc func() string
	GetAPIHostnameFunc func() string
	GetAPIPrefixFunc   func() string
	GetBaseURLFunc     func() string
	getServiceFunc     func() string
}

func (c *Client) GetAPIHostname() string {
	list := []string{}
	serviceName := c.getServiceFunc()
	if serviceName != "" {
		list = append(list, serviceName)
	}

	list = append(list, c.Region)

	endpoint := DefaultAPIEndpoint
	if c.APIEndpoint != "" {
		endpoint = c.APIEndpoint
	}
	list = append(list, endpoint)

	return strings.Join(list, ".")
}

func (c *Client) GetAPIEndpoint() string {
	return fmt.Sprintf("%s://%s", DefaultSchema, c.GetAPIHostnameFunc())
}

func (c *Client) GetBaseURL() string {
	return fmt.Sprintf("%s%s/%s/%s", c.GetAPIEndpointFunc(), c.GetAPIPrefixFunc(), "projects", c.ProjectID)
}

func (c *Client) DoRequest(ctx context.Context, method, url string, input, output interface{}) (*http.Response, error) {
	var body io.Reader
	var jsondata []byte
	var err error
	if input == nil {
		body = nil
	} else {
		jsondata, err = json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(jsondata)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	logrus.Debugf("request is: url:%s method:%s body:[%s]", url, method, string(jsondata))
	if c.dryRun {
		return nil, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	byteData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(byteData))

	requestOK := resp.StatusCode >= 200 && resp.StatusCode < 300
	// switch method {
	// case http.MethodGet, http.MethodPut:
	// 	requestOK = resp.StatusCode == 200
	// case http.MethodPost:
	// 	requestOK = resp.StatusCode == 201
	// case http.MethodDelete:
	// 	requestOK = resp.StatusCode == 200
	// }

	if !requestOK {
		logrus.Debugf("response raw data: %s", string(byteData))
		einfo := ErrorInfo{}
		if err = json.Unmarshal(byteData, &einfo); err != nil {
			return nil, errors.Wrap(err, "error when unmarshaling error info of huawei api")
		}
		einfo.StatusCode = resp.StatusCode
		//to error v1
		if einfo.ErrorV1 != nil {
			einfo.Description = einfo.ErrorV1["message"].(string)
			einfo.Code = einfo.ErrorV1["code"].(string)
		}
		return nil, &einfo
	}

	if output != nil {
		if err = json.Unmarshal(byteData, output); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (c *Client) GetSigner() *signer.Signer {
	return c.signer
}

func getTimeoutTransporter() http.RoundTripper {
	return &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   120 * time.Second,
			KeepAlive: 120 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}
}

func NewClient(ak, sk, endpoint, region, projectID string) *Client {
	client := &Client{
		AccessKey:   ak,
		SecretKey:   sk,
		APIEndpoint: endpoint,
		Region:      region,
		ProjectID:   projectID,
		HTTPClient:  http.Client{},
		dryRun:      false,
		signer: &signer.Signer{
			AccessKey:     ak,
			SecretKey:     sk,
			Region:        region,
			NextTransport: getTimeoutTransporter(),
		},
	}
	client.HTTPClient.Transport = client.signer
	client.GetAPIEndpointFunc = client.GetAPIEndpoint
	client.GetAPIHostnameFunc = client.GetAPIHostname
	client.GetBaseURLFunc = client.GetBaseURL
	client.GetAPIPrefixFunc = client.GetAPIPrefix
	client.getServiceFunc = EmptyString
	client.signer.GetServiceNameFunc = EmptyString
	return client
}

func (c *Client) SetServiceNameFunc(f func() string) {
	c.getServiceFunc = f
	c.signer.GetServiceNameFunc = f
}

func (c *Client) GetSignerServiceName() string {
	if c.signer != nil {
		return c.signer.GetServiceNameFunc()
	}
	return "not set"
}

//GetURL resourceType, resourceID, subresourceType, subresourceID
func (c *Client) GetURL(paths ...string) string {
	return fmt.Sprintf("%s/%s", c.GetBaseURLFunc(), strings.Join(paths, "/"))
}

func WaitForDeleteComplete(ctx context.Context, getResourceFunc func(context.Context) error) error {
	return WaitForCompleteWithError(ctx, func(ictx context.Context) error {
		if err := getResourceFunc(ictx); err != nil {
			eInfo, ok := err.(*ErrorInfo)
			if ok && eInfo.StatusCode == 404 {
				return nil
			}
		}
		return errors.New("delete not complete")
	})
}

func WaitForCompleteUntilTrue(ctx context.Context, conditionFunc func(context.Context) (bool, error)) error {
	return waitForCompleteUntilTrue(ctx, DefaultDuration, DefaultTimeout, conditionFunc)
}

func CustomWaitForCompleteUntilTrue(ctx context.Context, duration time.Duration, timeout time.Duration, conditionFunc func(context.Context) (bool, error)) error {
	return waitForCompleteUntilTrue(ctx, duration, timeout, conditionFunc)
}

func WaitForCompleteWithError(ctx context.Context, conditionFunc func(context.Context) error) error {
	t := time.NewTicker(DefaultDuration)
	defer t.Stop()
	timoutCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	var lastErr error
	for {
		select {
		case <-t.C:
			err := conditionFunc(timoutCtx)
			lastErr = err
			if err == nil {
				return nil
			}
		case <-timoutCtx.Done():
			return errors.Wrap(lastErr, "time out waiting delete with last error")
		}
	}
}

func waitForCompleteUntilTrue(ctx context.Context, duration time.Duration, timeout time.Duration, conditionFunc func(context.Context) (bool, error)) error {
	t := time.NewTicker(duration)
	defer t.Stop()
	timoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case <-t.C:
			logrus.Debug("wait function ticking")
			ok, err := conditionFunc(timoutCtx)
			if err != nil {
				logrus.Debugf("wait function gets error: %s", err.Error())
				return err
			}
			if ok {
				return nil
			}
		case <-timoutCtx.Done():
			return errors.New("time out waiting condition with last error")
		}
	}
}

func EmptyString() string {
	return ""
}

func (c *Client) GetAPIPrefix() string {
	return "/api/v3"
}

func GetBaseClientFromENV() (*Client, error) {
	debug := os.Getenv("DEBUG")
	if debug == "true" {
		logrus.SetLevel(logrus.DebugLevel)
	}
	AK := os.Getenv("ACCESS_KEY")
	SK := os.Getenv("SECRET_KEY")
	Region := os.Getenv("REGION")
	ProjectID := os.Getenv("PROJECT_ID")
	if AK == "" ||
		SK == "" ||
		Region == "" ||
		ProjectID == "" {
		return nil, errors.New("Not testing cce client because ak/sk/region/projectid are not set")
	}
	return NewClient(AK, SK, DefaultAPIEndpoint, Region, ProjectID), nil
}
