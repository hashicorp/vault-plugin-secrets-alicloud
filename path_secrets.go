package alicloud

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault-plugin-secrets-alicloud/clients"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const secretType = "alicloud"

func (b *backend) pathSecrets() *framework.Secret {
	return &framework.Secret{
		Type: secretType,
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access Key",
			},
			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret Key",
			},
		},
		Renew:  b.operationRenew,
		Revoke: b.operationRevoke,
	}
}

func (b *backend) operationRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if isSTSRaw, ok := req.Secret.InternalData["is_sts"]; !ok {
		return nil, errors.New("is_sts missing from secret")
	} else {
		isSTS, ok := isSTSRaw.(bool)
		if !ok {
			return nil, fmt.Errorf("unable to read is_sts: %+v", isSTSRaw)
		}
		if isSTS {
			// STS already has a lifetime, and we don't support renewing it.
			return nil, nil
		}
	}

	roleName, err := getStringValue(req.Secret.InternalData, "role_name")
	if err != nil {
		return nil, err
	}

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		// The role has been deleted since the secret was issued or last renewed.
		// The user's expectation is probably that the caller won't continue being
		// able to perform renewals.
		return nil, fmt.Errorf("role %s has been deleted so no further renewals are allowed", roleName)
	}

	resp := &logical.Response{Secret: req.Secret}
	if role.TTL != 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL != 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}

func (b *backend) operationRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if isSTSRaw, ok := req.Secret.InternalData["is_sts"]; !ok {
		return nil, errors.New("is_sts missing from secret")
	} else {
		isSTS, ok := isSTSRaw.(bool)
		if !ok {
			return nil, fmt.Errorf("unable to read is_sts: %+v", isSTSRaw)
		}
		if isSTS {
			// STS cleans up after itself so we can skip this if is_sts internal data
			// element set to true.
			return nil, nil
		}
	}

	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, errors.New("unable to delete access key because no credentials are configured")
	}
	client, err := clients.NewRAMClient(b.sdkConfig, creds.AccessKey, creds.SecretKey)
	if err != nil {
		return nil, err
	}

	userName, err := getStringValue(req.Secret.InternalData, "username")
	if err != nil {
		return nil, err
	}

	accessKeyID, err := getStringValue(req.Secret.InternalData, "access_key_id")
	if err != nil {
		return nil, err
	}

	// Delete the access key first so if all else fails, the access key is revoked.
	if err := client.DeleteAccessKey(userName, accessKeyID); err != nil {
		return nil, err
	}

	// Inline policies are currently stored as remote policies, because they have been
	// instantiated remotely and we need their name and type to now detach and delete them.
	inlinePolicies, err := getRemotePolicies(req.Secret.InternalData, "inline_policies")
	if err != nil {
		return nil, err
	}
	for _, inlinePolicy := range inlinePolicies {
		if err := client.DetachPolicy(userName, inlinePolicy.Name, inlinePolicy.Type); err != nil {
			return nil, err
		}
		if err := client.DeletePolicy(inlinePolicy.Name); err != nil {
			return nil, err
		}
	}

	// These just need to be detached, but we're not going to delete them because they're
	// supposed to be longstanding.
	remotePolicies, err := getRemotePolicies(req.Secret.InternalData, "remote_policies")
	if err != nil {
		return nil, err
	}
	for _, remotePolicy := range remotePolicies {
		if err := client.DetachPolicy(userName, remotePolicy.Name, remotePolicy.Type); err != nil {
			return nil, err
		}
	}

	// Finally, delete the user. Note: this will fail if any other new associations have been
	// created with the user out of band from Vault. For example, if a new API key had been
	// manually created for them in their console that Vault didn't know about, or some other
	// thing had been created. Luckily the err returned is pretty explanatory so that will
	// help with debugging.
	if err := client.DeleteUser(userName); err != nil {
		return nil, err
	}
	return nil, nil
}

func getStringValue(internalData map[string]interface{}, key string) (string, error) {
	valueRaw, ok := internalData[key]
	if !ok {
		return "", fmt.Errorf("secret is missing %s internal data", key)
	}
	value, ok := valueRaw.(string)
	if !ok {
		return "", fmt.Errorf("secret is missing %s internal data", key)
	}
	return value, nil
}

func getRemotePolicies(internalData map[string]interface{}, key string) ([]*remotePolicy, error) {
	valuesRaw, ok := internalData[key]
	if !ok {
		return nil, fmt.Errorf("secret is missing %s internal data", key)
	}
	policies, ok := valuesRaw.([]*remotePolicy)
	if !ok {
		return nil, fmt.Errorf("secret is missing %s internal data", key)
	}
	return policies, nil
}
