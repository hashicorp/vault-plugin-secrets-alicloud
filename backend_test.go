package alicloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/hashicorp/vault/sdk/logical"
)

func setup() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// All responses below are directly from AliCloud's documentation
		// and none reflect real values.
		action := r.URL.Query().Get("Action")
		switch action {

		case "CreateUser":
			w.WriteHeader(200)
			w.Write([]byte(`{
				"RequestId": "04F0F334-1335-436C-A1D7-6C044FE73368",
				"User": {
					"UserId": "1227489245380721",
					"UserName": "zhangqiang",
					"DisplayName": "zhangqiang",
					"MobilePhone": "86-18600008888",
					"Email": "zhangqiang@example.com",
					"Comments": "This is a cloud computing engineer.",
					"CreateDate": "2015-01-23T12:33:18Z"
				}
			}`))

		case "DeleteUser":
			w.WriteHeader(200)
			w.Write([]byte(`{
				"RequestId": "1C488B66-B819-4D14-8711-C4EAAA13AC01"
			}`))

		case "CreatePolicy":
			w.WriteHeader(200)
			w.Write([]byte(`{
				"RequestId": "9B34724D-54B0-4A51-B34D-4512372FE1BE",
				"Policy": {
					"PolicyName": "OSS-Administrator",
					"PolicyType": "Custom",
					"Description": "OSS administrator permission",
					"DefaultVersion": "v1",
					"CreateDate": "2015-01-23T12:33:18Z"
				}
			}`))

		case "DeletePolicy":
			w.WriteHeader(200)
			w.Write([]byte(`{
				"RequestId": "898FAB24-7509-43EE-A287-086FE4C44394"
			}`))

		case "AttachPolicyToUser":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"RequestId": "697852FB-50D7-44D9-9774-530C31EAC572"
			}`))

		case "DetachPolicyFromUser":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"RequestId": "697852FB-50D7-44D9-9774-530C31EAC572"
			}`))

		case "CreateAccessKey":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"RequestId": "04F0F334-1335-436C-A1D7-6C044FE73368",
				"AccessKey": {
					"AccessKeyId": "0wNEpMMlzy7szvai",
					"AccessKeySecret": "PupkTg8jdmau1cXxYacgE736PJj4cA",
					"Status": "Active",
					"CreateDate": "2015-01-23T12:33:18Z"
				}
			}`))

		case "DeleteAccessKey":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"RequestId": "04F0F334-1335-436C-A1D7-6C044FE73368"
			}`))

		case "AssumeRole":
			w.WriteHeader(200)
			w.Write([]byte(`    {
				"Credentials": {
					"AccessKeyId": "STS.L4aBSCSJVMuKg5U1vFDw",
					"AccessKeySecret": "wyLTSmsyPGP1ohvvw8xYgB29dlGI8KMiH2pKCNZ9",
					"Expiration": "2015-04-09T11:52:19Z",
					"SecurityToken": "CAESrAIIARKAAShQquMnLIlbvEcIxO6wCoqJufs8sWwieUxu45hS9AvKNEte8KRUWiJWJ6Y+YHAPgNwi7yfRecMFydL2uPOgBI7LDio0RkbYLmJfIxHM2nGBPdml7kYEOXmJp2aDhbvvwVYIyt/8iES/R6N208wQh0Pk2bu+/9dvalp6wOHF4gkFGhhTVFMuTDRhQlNDU0pWTXVLZzVVMXZGRHciBTQzMjc0KgVhbGljZTCpnJjwySk6BlJzYU1ENUJuCgExGmkKBUFsbG93Eh8KDEFjdGlvbkVxdWFscxIGQWN0aW9uGgcKBW9zczoqEj8KDlJlc291cmNlRXF1YWxzEghSZXNvdXJjZRojCiFhY3M6b3NzOio6NDMyNzQ6c2FtcGxlYm94L2FsaWNlLyo="
				},
				"AssumedRoleUser": {
					"arn": "acs:sts::1234567890123456:assumed-role/AdminRole/alice",
					"AssumedRoleUserId":"344584339364951186:alice"
					},
				"RequestId": "6894B13B-6D71-4EF5-88FA-F32781734A7F"
			}`))
		}
	}))
}

func teardown(ts *httptest.Server) {
	ts.Close()
}

func newIntegrationTestEnv(testURL string) (*testEnv, error) {
	ctx := context.Background()
	b, err := proxiedTestBackend(ctx, testURL)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		AccessKey: "fizz",
		SecretKey: "buzz",
		RoleARN:   "acs:ram::5138828231865461:role/hastrustedactors",
		Backend:   b,
		Context:   ctx,
		Storage:   &logical.InmemStorage{},
	}, nil
}

// This test thoroughly exercises all endpoints, and tests the policy-based creds
// sunny path.
func TestDynamicPolicyBasedCreds(t *testing.T) {
	ts := setup()
	defer teardown(ts)

	integrationTestEnv, err := newIntegrationTestEnv(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", integrationTestEnv.AddConfig)
	t.Run("read config", integrationTestEnv.ReadFirstConfig)
	t.Run("update config", integrationTestEnv.UpdateConfig)
	t.Run("read config", integrationTestEnv.ReadSecondConfig)
	t.Run("delete config", integrationTestEnv.DeleteConfig)
	t.Run("read config", integrationTestEnv.ReadEmptyConfig)
	t.Run("add config", integrationTestEnv.AddConfig)

	t.Run("add policy-based role", integrationTestEnv.AddPolicyBasedRole)
	t.Run("read policy-based role", integrationTestEnv.ReadPolicyBasedRole)
	t.Run("add arn-based role", integrationTestEnv.AddARNBasedRole)
	t.Run("read arn-based role", integrationTestEnv.ReadARNBasedRole)
	t.Run("update arn-based role", integrationTestEnv.UpdateARNBasedRole)
	t.Run("read updated role", integrationTestEnv.ReadUpdatedRole)
	t.Run("list two roles", integrationTestEnv.ListTwoRoles)
	t.Run("delete arn-based role", integrationTestEnv.DeleteARNBasedRole)
	t.Run("list one role", integrationTestEnv.ListOneRole)

	t.Run("read policy-based creds", integrationTestEnv.ReadPolicyBasedCreds)
	t.Run("renew policy-based creds", integrationTestEnv.RenewPolicyBasedCreds)
	t.Run("revoke policy-based creds", integrationTestEnv.RevokePolicyBasedCreds)
}

// Since all endpoints were exercised in the previous test, we just need one that
// gets straight to the point testing the STS creds sunny path.
func TestDynamicSTSCreds(t *testing.T) {
	ts := setup()
	defer teardown(ts)

	integrationTestEnv, err := newIntegrationTestEnv(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", integrationTestEnv.AddConfig)
	t.Run("add arn-based role", integrationTestEnv.AddARNBasedRole)
	t.Run("read arn-based creds", integrationTestEnv.ReadARNBasedCreds)
	t.Run("renew arn-based creds", integrationTestEnv.RenewARNBasedCreds)
	t.Run("revoke arn-based creds", integrationTestEnv.RevokeARNBasedCreds)
}

func proxiedTestBackend(context context.Context, testURL string) (logical.Backend, error) {
	clientConfig := sdk.NewConfig()

	// Our test server doesn't use TLS, so we need to set the scheme to match that.
	clientConfig.Scheme = "http"

	// Use a URL updater configured to point all requests at
	// our local test server.
	clientConfig.HttpTransport = &http.Transport{}
	updater, err := newURLUpdater(testURL)
	if err != nil {
		return nil, err
	}
	clientConfig.HttpTransport.Proxy = updater.Proxy

	b := newBackend(clientConfig)
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     time.Hour,
		},
	}
	if err := b.Setup(context, conf); err != nil {
		panic(err)
	}
	return b, nil
}

/*
	The URL updater uses the Proxy on outbound requests to swap
	a real URL with one generated by httptest. This points requests
	at a local test server, and allows us to return expected
	responses.
*/
func newURLUpdater(testURL string) (*urlUpdater, error) {
	// Example testURL: https://127.0.0.1:46445
	u, err := url.Parse(testURL)
	if err != nil {
		return nil, err
	}
	return &urlUpdater{u}, nil
}

type urlUpdater struct {
	testURL *url.URL
}

func (u *urlUpdater) Proxy(req *http.Request) (*url.URL, error) {
	req.URL.Scheme = u.testURL.Scheme
	req.URL.Host = u.testURL.Host
	return u.testURL, nil
}
