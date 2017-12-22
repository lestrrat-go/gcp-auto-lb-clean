package autolbclean

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
	compute "google.golang.org/api/compute/v1"
)

func New(project string, oauthClient *http.Client) (*App, error) {
	s, err := compute.New(oauthClient)
	if err != nil {
		return nil, errors.Wrap(err, `failed to create compute.Service`)
	}

	return &App{
		project: project,
		service: s,
	}, nil
}

// Lists HTTP(s) forwarding rules, whose names match "k8s-fw"
func (app *App) ListIngressForwardingRules() ([]*compute.ForwardingRule, error) {
	l, err := app.service.ForwardingRules.AggregatedList(app.project).Do()
	if err != nil {
		return nil, errors.Wrap(err, `failed to list forwarding rules`)
	}

	var result []*compute.ForwardingRule
	for _, scopedList := range l.Items {
		for _, fr := range scopedList.ForwardingRules {
			if strings.HasPrefix(fr.Name, "k8s-fw") {
				result = append(result, fr)
			}
		}
	}

	return result, nil
}

func ParseTargetProxy(s string) (name string, region string, isHTTPs bool, err error) {
	var pos int
	if i := strings.Index(s, `/targetHttpProxies`); i >= 0 {
		pos = i
	} else if i := strings.Index(s, `/targetHttpsProxies`); i >= 0 {
		isHTTPs = true
		pos = i
	} else {
		err = errors.New(`failed to find keywords targetHttpProxies or targetHttpsProxies`)
		return
	}

	// find the region region and the name
	// /$region/targetHttp(s)Proxy/$name$
	if i := strings.LastIndex(s[:pos], "/"); i >= 0 {
		region = s[i+1 : pos]
	} else {
		err = errors.New(`failed to find region`)
		return
	}

	if i := strings.LastIndex(s[pos:], "/"); i >= 0 {
		name = s[pos+i+1:]
	} else {
		err = errors.New(`failed to find name`)
		return
	}

	return
}

func (app *App) GetTargetHttpsProxy(name string) (*compute.TargetHttpsProxy, error) {
	return app.service.TargetHttpsProxies.Get(app.project, name).Do()
}

func (app *App) GetTargetHttpProxy(name string) (*compute.TargetHttpProxy, error) {
	return app.service.TargetHttpProxies.Get(app.project, name).Do()
}

func ParseUrlMap(s string) (name string, region string, err error) {
	var pos int
	if i := strings.Index(s, `/urlMaps`); i >= 0 {
		pos = i
	} else {
		err = errors.New(`failed to find keyword urlMaps`)
		return
	}

	// find the region region and the name
	// /$region/urlMaps/$name$
	if i := strings.LastIndex(s[:pos], "/"); i >= 0 {
		region = s[i+1 : pos]
	} else {
		err = errors.New(`failed to find region`)
		return
	}

	if i := strings.LastIndex(s[pos:], "/"); i >= 0 {
		name = s[pos+i+1:]
	} else {
		err = errors.New(`failed to find name`)
		return
	}

	return
}

func (app *App) GetUrlMap(name string) (*compute.UrlMap, error) {
	return app.service.UrlMaps.Get(app.project, name).Do()
}

func parseURL(s, keyword string) (name string, region string, err error) {
	var pos int
	if i := strings.Index(s, `/`+keyword); i >= 0 {
		pos = i
	} else {
		err = errors.Errorf(`failed to find keyword %s`, keyword)
		return
	}

	// find the region region and the name
	// /$region/backendServices/$name$
	if i := strings.LastIndex(s[:pos], "/"); i >= 0 {
		region = s[i+1 : pos]
	} else {
		err = errors.New(`failed to find region`)
		return
	}

	if i := strings.LastIndex(s[pos:], "/"); i >= 0 {
		name = s[pos+i+1:]
	} else {
		err = errors.New(`failed to find name`)
		return
	}

	return
}

func ParseService(s string) (name string, region string, err error) {
	return parseURL(s, `backendServices`)
}

func (app *App) FindBackendServices(um *compute.UrlMap) ([]*compute.BackendService, error) {
	var list []*compute.BackendService
	for _, pm := range um.PathMatchers {
		for _, pr := range pm.PathRules {
			sname, region, err := ParseService(pr.Service)
			if err != nil {
				return nil, errors.Wrap(err, `failed to parse backend service url`)
			}
			_ = region
			s, err := app.service.BackendServices.Get(app.project, sname).Do()
			if err != nil {
				return nil, errors.Wrap(err, `failed to get backend service`)
			}

			list = append(list, s)
		}
	}
	return list, nil
}

func ParseInstanceGroup(s string) (name string, zone string, err error) {
	var pos int
	if i := strings.Index(s, `/instanceGroups`); i >= 0 {
		pos = i
	} else {
		err = errors.New(`failed to find keyword instanceGroups`)
		return
	}

	// find the region region and the name
	// /$zone/instanceGroups/$name$
	if i := strings.LastIndex(s[:pos], "/"); i >= 0 {
		zone = s[i+1 : pos]
	} else {
		err = errors.New(`failed to find zone`)
		return
	}

	if i := strings.LastIndex(s[pos:], "/"); i >= 0 {
		name = s[pos+i+1:]
	} else {
		err = errors.New(`failed to find name`)
		return
	}

	return
}

func (app *App) ListInstancesForService(s *compute.BackendService) ([]string, error) {
	var list []string
	for _, backend := range s.Backends {
		name, zone, err := ParseInstanceGroup(backend.Group)
		if err != nil {
			return nil, errors.Wrap(err, `failed to parse instance group url`)
		}

		instances, err := app.service.InstanceGroups.ListInstances(app.project, zone, name,
			&compute.InstanceGroupsListInstancesRequest{
				InstanceState: "ALL",
			},
		).Do()
		// For this operation, we ignore errors
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			list = append(list, instance.Instance)
		}
	}
	return list, nil
}

func ParseSslCertificates(s string) (name string, region string, err error) {
	return parseURL(s, `sslCertificates`)
}

func ParseBackendServices(s string) (name string, region string, err error) {
	return parseURL(s, `backendServices`)
}

func ParseHealthChecks(s string) (name string, region string, err error) {
	return parseURL(s, `healthChecks`)
}
