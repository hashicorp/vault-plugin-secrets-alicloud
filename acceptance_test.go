// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	envVarRunAccTests = "VAULT_ACC"
	envVarAccessKey   = "VAULT_ACC_TEST_ACCESS_KEY_ID"
	envVarSecretKey   = "VAULT_ACC_TEST_SECRET_KEY"
	envVarRoleARN     = "VAULT_ACC_TEST_ROLE_ARN"
	// Please note: the role arn used here for acceptance tests must have been set up as
	// allowing trusted actors, as mentioned here: https://www.alibabacloud.com/help/en/resource-access-management/latest/edit-the-trust-policy-of-a-ram-role.
	// Also, the access key and secret in use must qualify as a trusted actor. If you're
	// unsure of how to set up a trusted actor, please create a new role in Alibaba's RAM UI,
	// as its role creation wizard asks you whether you want to create trusted actors and how
	// they should be configured. Trusted actors can only be added at the time of role creation.
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

func TestAcceptanceDynamicPolicyBasedCreds(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add policy-based role", acceptanceTestEnv.AddPolicyBasedRole)
	t.Run("read policy-based creds", acceptanceTestEnv.ReadPolicyBasedCreds)
	t.Run("renew policy-based creds", acceptanceTestEnv.RenewPolicyBasedCreds)
	t.Run("revoke policy-based creds", acceptanceTestEnv.RevokePolicyBasedCreds)
}

func TestAcceptanceDynamicRoleBasedCreds(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add arn-based role", acceptanceTestEnv.AddARNBasedRole)
	t.Run("read arn-based creds", acceptanceTestEnv.ReadARNBasedCreds)
	t.Run("renew arn-based creds", acceptanceTestEnv.RenewARNBasedCreds)
	t.Run("revoke arn-based creds", acceptanceTestEnv.RevokeARNBasedCreds)
}

func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     time.Hour,
		},
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		AccessKey: os.Getenv(envVarAccessKey),
		SecretKey: os.Getenv(envVarSecretKey),
		RoleARN:   os.Getenv(envVarRoleARN),
		Backend:   b,
		Context:   ctx,
		Storage:   &logical.InmemStorage{},
	}, nil
}
