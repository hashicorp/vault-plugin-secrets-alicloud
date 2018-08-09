package clients

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
)

func NewRAMClient(sdkConfig *sdk.Config, key, secret string) (*RAMClient, error) {
	cred := credentials.NewAccessKeyCredential(key, secret)
	client, err := ram.NewClientWithOptions("us-east-1", sdkConfig, cred)
	if err != nil {
		return nil, err
	}
	return &RAMClient{client: client}, nil
}

type RAMClient struct {
	client *ram.Client
}

func (c *RAMClient) CreateAccessKey(userName string) (*ram.CreateAccessKeyResponse, error) {
	accessKeyReq := ram.CreateCreateAccessKeyRequest()
	accessKeyReq.UserName = userName
	return c.client.CreateAccessKey(accessKeyReq)
}

func (c *RAMClient) DeleteAccessKey(userName, accessKeyID string) error {
	req := ram.CreateDeleteAccessKeyRequest()
	req.UserAccessKeyId = accessKeyID
	req.UserName = userName
	if _, err := c.client.DeleteAccessKey(req); err != nil {
		return err
	}
	return nil
}

func (c *RAMClient) CreatePolicy(policyName, policyDoc string) (*ram.CreatePolicyResponse, error) {
	createPolicyReq := ram.CreateCreatePolicyRequest()
	createPolicyReq.PolicyName = policyName
	createPolicyReq.Description = "Created by Vault."
	createPolicyReq.PolicyDocument = policyDoc
	return c.client.CreatePolicy(createPolicyReq)
}

func (c *RAMClient) DeletePolicy(policyName string) error {
	req := ram.CreateDeletePolicyRequest()
	req.PolicyName = policyName
	if _, err := c.client.DeletePolicy(req); err != nil {
		return err
	}
	return nil
}

func (c *RAMClient) AttachPolicy(userName, policyName, policyType string) error {
	attachPolReq := ram.CreateAttachPolicyToUserRequest()
	attachPolReq.UserName = userName
	attachPolReq.PolicyName = policyName
	attachPolReq.PolicyType = policyType
	if _, err := c.client.AttachPolicyToUser(attachPolReq); err != nil {
		return err
	}
	return nil
}

func (c *RAMClient) DetachPolicy(userName, policyName, policyType string) error {
	req := ram.CreateDetachPolicyFromUserRequest()
	req.UserName = userName
	req.PolicyName = policyName
	req.PolicyType = policyType
	if _, err := c.client.DetachPolicyFromUser(req); err != nil {
		return err
	}
	return nil
}

func (c *RAMClient) CreateUser(userName string) (*ram.CreateUserResponse, error) {
	createUserReq := ram.CreateCreateUserRequest()
	createUserReq.UserName = userName
	createUserReq.DisplayName = userName
	return c.client.CreateUser(createUserReq)
}

// Note: deleteUser will fail if the user is presently associated with anything
// in Alibaba.
func (c *RAMClient) DeleteUser(userName string) error {
	req := ram.CreateDeleteUserRequest()
	req.UserName = userName
	if _, err := c.client.DeleteUser(req); err != nil {
		return err
	}
	return nil
}
