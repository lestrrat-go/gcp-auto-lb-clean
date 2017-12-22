package autolbclean_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	autolbclean "github.com/lestrrat/gcp-auto-lb-clean"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2/google"
	compute "google.golang.org/api/compute/v1"
)

var tOAuthClient *http.Client
var tProjectID string
var tReady bool

func init() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := google.DefaultClient(ctx, compute.ComputeScope); err != nil {
		return
	}

	tProjectID = os.Getenv("GCP_PROJECT_ID")
	if len(tProjectID) == 0 {
		return
	}

	tReady = true
}

func dump(t *testing.T, v interface{}) {
	buf, _ := json.MarshalIndent(v, "", "  ")
	t.Logf("%s", buf)
}

func testReady() bool {
	return tReady
}

func TestParseTargetProxy(t *testing.T) {
	type parseTargetProxyResult struct {
		Error   bool
		Input   string
		IsHTTPs bool
		Name    string
		Region  string
	}
	list := []parseTargetProxyResult{
		{
			Input:  `https://www.googleapis.com/compute/v1/projects/builderscon-1248/global/targetHttpProxies/k8s-tp-default-apiserver--c4f34d3824aedd50`,
			Name:   `k8s-tp-default-apiserver--c4f34d3824aedd50`,
			Region: `global`,
		},
		{
			Input:   `https://www.googleapis.com/compute/v1/projects/builderscon-1248/global/targetHttpsProxies/k8s-tps-default-builderscon--c4f34d3824aedd50`,
			Name:    `k8s-tps-default-builderscon--c4f34d3824aedd50`,
			IsHTTPs: true,
			Region:  `global`,
		},
	}

	for _, data := range list {
		t.Run(fmt.Sprintf("Parse %s", data.Input), func(t *testing.T) {
			name, region, isHTTPs, err := autolbclean.ParseTargetProxy(data.Input)
			if data.Error {
				if !assert.Error(t, err, `should fail`) {
					return
				}
			} else {
				if !assert.NoError(t, err, `should succeed`) {
					return
				}
				if !assert.Equal(t, data.Name, name, `name should match`) {
					return
				}
				if !assert.Equal(t, data.Region, region, `region should match`) {
					return
				}
				if !assert.Equal(t, data.IsHTTPs, isHTTPs, `isHTTPs should match`) {
					return
				}
			}
		})
	}
}

func TestParseUrlMap(t *testing.T) {
	type parseUrlMapResult struct {
		Input  string
		Name   string
		Region string
		Error  bool
	}

	list := []parseUrlMapResult{
		{
			Input:  `https://www.googleapis.com/compute/v1/projects/builderscon-1248/global/urlMaps/k8s-um-default-builderscon--c4f34d3824aedd50`,
			Name:   `k8s-um-default-builderscon--c4f34d3824aedd50`,
			Region: `global`,
		},
	}

	for _, data := range list {
		t.Run(fmt.Sprintf("Parse %s", data.Input), func(t *testing.T) {
			name, region, err := autolbclean.ParseUrlMap(data.Input)
			if data.Error {
				if !assert.Error(t, err, `ParseUrlMap should fail`) {
					return
				}
			} else {
				if !assert.NoError(t, err, `ParseUrlMap should succeed`) {
					return
				}

				if !assert.Equal(t, data.Name, name, `name should match`) {
					return
				}
				if !assert.Equal(t, data.Region, region, `region should match`) {
					return
				}
			}
		})
	}
}

func TestIngress(t *testing.T) {
	t.Run("TestListIngressForwardingRules", func(t *testing.T) {
		if !testReady() {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cl, err := google.DefaultClient(ctx, compute.ComputeScope)
		if !assert.NoError(t, err, `google.DefaultClient should succeed`) {
			return
		}

		app, err := autolbclean.New(tProjectID, cl)
		if !assert.NoError(t, err, `New should succeed`) {
			return
		}

		fwrs, err := app.ListIngressForwardingRules()
		if !assert.NoError(t, err, `ListIngressForwardingRules should succeed`) {
			return
		}

		for _, fwr := range fwrs {
			t.Logf("Forwarding rule: %s", fwr.SelfLink)
			t.Run("ParseTargetProxy", func(t *testing.T) {
				tpname, region, isHTTPs, err := autolbclean.ParseTargetProxy(fwr.Target)
				if !assert.NoError(t, err, `ParseTargetProxy should succeed`) {
					return
				}

				_ = region
				var urlMapURL string
				if isHTTPs {
					tp, err := app.GetTargetHttpsProxy(tpname)
					if !assert.NoError(t, err, `GetTargetHttpsProxy should succeed`) {
						return
					}
					urlMapURL = tp.UrlMap
					dump(t, tp)
				} else {
					tp, err := app.GetTargetHttpProxy(tpname)
					if !assert.NoError(t, err, `GetTargetHttpProxy should succeed`) {
						return
					}
					urlMapURL = tp.UrlMap
					dump(t, tp)
				}

				t.Run("ParseUrlMap", func(t *testing.T) {
					umname, region, err := autolbclean.ParseUrlMap(urlMapURL)
					if !assert.NoError(t, err, `ParseUrlMap should succeed`) {
						return
					}

					_ = region
					um, err := app.GetUrlMap(umname)
					if !assert.NoError(t, err, `GetUrlMap should succeed`) {
						return
					}

					t.Run("FindBackendServices", func(t *testing.T) {
						services, err := app.FindBackendServices(um)
						if !assert.NoError(t, err, `FindBackendServices should succeed`) {
							return
						}

						for _, service := range services {
							instances, err := app.ListInstancesForService(service)
							if !assert.NoError(t, err, `ListInstancesForService should succeed`) {
								return
							}
							t.Logf("service: %s", service.Name)
							dump(t, instances)
						}
					})
				})
			})
		}
	})
}
