package alicloud

import (
	"testing"
)

func TestGenerateUsername(t *testing.T) {
	result := generateUsername("displayName", "roleName")
	if len(result) > 64 {
		t.Fatal("too long: " + result)
	}
	result = generateUsername("displayNamedisplayNamedisplayNamedisplayNamedisplayNamedisplayNamedisplayNamedisplayNamedisplayNamedisplayName", "roleName")
	if len(result) > 64 {
		t.Fatal("too long: " + result)
	}
	result = generateUsername("displayName", "roleNameroleNameroleNameroleNameroleNameroleNameroleNameroleNameroleNameroleName")
	if len(result) > 64 {
		t.Fatal("too long: " + result)
	}
}
