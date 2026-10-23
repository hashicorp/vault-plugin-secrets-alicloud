// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package alicloud

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/hashicorp/vault/sdk/logical"
)

// TestGenerateNameWithTemplate verifies default and custom name templates.
func TestGenerateNameWithTemplate(t *testing.T) {
	t.Run("default STS template succeeds within 32 chars", func(t *testing.T) {
		result, err := generateNameWithTemplate("", "displayName", "roleName", sessionUserType)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) > 32 {
			t.Fatal("too long: " + result)
		}
		if !strings.HasPrefix(result, "vault-") {
			t.Fatalf("unexpected default STS session name: %s", result)
		}
	})

	t.Run("default RAM template succeeds within 64 chars", func(t *testing.T) {
		result, err := generateNameWithTemplate("", "displayName", "roleName", ramUserType)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) > 64 {
			t.Fatal("too long: " + result)
		}
		if !strings.HasPrefix(result, "vault-") {
			t.Fatalf("unexpected default RAM username: %s", result)
		}
	})

	t.Run("default STS template succeeds within very long displayName", func(t *testing.T) {
		result, err := generateNameWithTemplate("", strings.Repeat("x", 65), "roleName", sessionUserType)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) > 32 {
			t.Fatal("too long: " + result)
		}
		if !strings.HasPrefix(result, "vault-") {
			t.Fatalf("unexpected default STS session name: %s", result)
		}
	})

	t.Run("default RAM template succeeds within very long displayName", func(t *testing.T) {
		result, err := generateNameWithTemplate("", strings.Repeat("x", 65), "roleName", ramUserType)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) > 64 {
			t.Fatal("too long: " + result)
		}
		if !strings.HasPrefix(result, "vault-") {
			t.Fatalf("unexpected default RAM username: %s", result)
		}
	})

	t.Run("custom template generates a valid RAM username", func(t *testing.T) {
		result, err := generateNameWithTemplate("{{.RoleName}}_{{random 20}}", "displayName", "roleName", ramUserType)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 29 {
			t.Fatal("error length: " + result)
		}
		if !strings.HasPrefix(result, "roleName_") {
			t.Fatalf("unexpected custom RAM username: %s", result)
		}
	})

	t.Run("custom template rejects an oversized display name", func(t *testing.T) {
		if _, err := generateNameWithTemplate("{{.DisplayName}}_{{random 20}}", strings.Repeat("x", 65), "roleName", ramUserType); err == nil {
			t.Fatal("expected RAM length error")
		}
	})

	t.Run("invalid template returns error", func(t *testing.T) {
		if _, err := generateNameWithTemplate("{{", "displayName", "roleName", ramUserType); err == nil {
			t.Fatal("expected invalid template error")
		}
	})

	t.Run("plain string template rejects a value over the RAM limit", func(t *testing.T) {
		if _, err := generateNameWithTemplate(strings.Repeat("x", 65), "displayName", "roleName", ramUserType); err == nil {
			t.Fatal("expected RAM length error")
		}
	})
}

// TestRoleUsernameTemplateRoundTripAndUpdate verifies template persistence and updates.
func TestRoleUsernameTemplateRoundTripAndUpdate(t *testing.T) {
	b := newBackend(sdk.NewConfig())
	ctx := context.Background()
	if err := b.Setup(ctx, &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     time.Hour,
		},
	}); err != nil {
		t.Fatalf("setup backend failed: %v", err)
	}
	storage := &logical.InmemStorage{}

	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/policy-based",
		Storage:   storage,
		Data: map[string]interface{}{
			"remote_policies": []string{
				"name:AliyunOSSReadOnlyAccess,type:System",
				"name:AliyunRDSReadOnlyAccess,type:System",
			},
			"username_template": "{{.RoleName}}_{{random 20}}",
		},
	}
	resp, err := b.HandleRequest(ctx, createReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create role failed: resp=%#v err=%v", resp, err)
	}

	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/policy-based",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("read role failed: resp=%#v err=%v", resp, err)
	}
	if got, ok := resp.Data["username_template"].(string); !ok || got != "{{.RoleName}}_{{random 20}}" {
		t.Fatalf("expected persisted username_template but got %#v", resp.Data["username_template"])
	}

	updateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/policy-based",
		Storage:   storage,
		Data: map[string]interface{}{
			"remote_policies": []string{
				"name:AliyunOSSReadOnlyAccess,type:System",
			},
			"username_template": "{{.RoleName}}_{{random 10}}",
		},
	}
	resp, err = b.HandleRequest(ctx, updateReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("update role failed: resp=%#v err=%v", resp, err)
	}

	resp, err = b.HandleRequest(ctx, readReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("read updated role failed: resp=%#v err=%v", resp, err)
	}
	if got, ok := resp.Data["username_template"].(string); !ok || got != "{{.RoleName}}_{{random 10}}" {
		t.Fatalf("expected updated username_template but got %#v", resp.Data["username_template"])
	}
}

// TestRoleUsernameTemplateRequiresPolicies verifies roles require at least one policy.
func TestRoleUsernameTemplateRequiresPolicies(t *testing.T) {
	b := newBackend(sdk.NewConfig())
	ctx := context.Background()
	if err := b.Setup(ctx, &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     time.Hour,
		},
	}); err != nil {
		t.Fatalf("setup backend failed: %v", err)
	}
	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/empty-policy",
		Storage:   storage,
		Data: map[string]interface{}{
			"username_template": "{{.RoleName}}_{{random 20}}",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected role creation without policies to fail")
	}
}
