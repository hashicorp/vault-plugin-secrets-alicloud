// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package clients

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

func NewSTSClient(sdkConfig *sdk.Config, region, key, secret string) (*STSClient, error) {
	creds, err := chainedCreds(key, secret)
	if err != nil {
		return nil, err
	}
	client, err := sts.NewClientWithOptions(region, sdkConfig, creds)
	if err != nil {
		return nil, err
	}
	return &STSClient{client: client}, nil
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
