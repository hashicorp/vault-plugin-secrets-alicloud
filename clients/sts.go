package clients

import (
	"fmt"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/go-ping/ping"
)

func NewSTSClient(sdkConfig *sdk.Config, key, secret string) (*STSClient, error) {
	creds, err := chainedCreds(key, secret)
	if err != nil {
		return nil, err
	}
	// We hard-code a region here because there's only one RAM endpoint regardless of the
	// region you're in.
	regionId := os.Getenv("STS_REGION_ID")
	if len(regionId) == 0 {
		regionId = "us-east-1"
	}
	client, err := sts.NewClientWithOptions(regionId, sdkConfig, creds)
	if err != nil {
		return nil, err
	}
	vpcEndpoint := fmt.Sprintf("sts-vpc.%s.aliyuncs.com", regionId)
	if pingVpcEndpoint(vpcEndpoint) {
		client.Domain = vpcEndpoint
	}
	return &STSClient{client: client}, nil
}

func pingVpcEndpoint(endpoint string) bool {
	pinger, err := ping.NewPinger(endpoint)
	if err != nil {
		return false
	}
	pinger.Count = 1
	return pinger.Run() == nil
}

type STSClient struct {
	client *sts.Client
}

func (c *STSClient) AssumeRole(roleSessionName, roleARN string) (*sts.AssumeRoleResponse, error) {
	assumeRoleReq := sts.CreateAssumeRoleRequest()
	assumeRoleReq.RoleArn = roleARN
	assumeRoleReq.RoleSessionName = roleSessionName
	return c.client.AssumeRole(assumeRoleReq)
}
