package autolbclean

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2/google"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/taskqueue"
)

var muApp sync.Mutex
var app *App

func AppengineApp(ctx context.Context) (*App, error) {
	muApp.Lock()
	defer muApp.Unlock()
	if app != nil {
		return app, nil
	}

	cl, err := google.DefaultClient(ctx, compute.ComputeScope)
	if err != nil {
		return nil, errors.Wrap(err, `failed to create google default client`)
	}
	id := appengine.AppID(ctx)
	if i := strings.Index(id, `:`); i > 0 {
		id = id[i:]
	}
	return New(id, cl)
}

var queueName = `default`

func init() {
	if v := os.Getenv(`QUEUE_NAME`); len(v) > 0 {
		queueName = v
	}

	// list all forwarding rules, and start "check" jobs
	http.HandleFunc(`/job/forwarding-rules/check`, httpForwardingRulesCheck)

	// checks for dangling firewall rules
	http.HandleFunc(`/job/firewall-rules/check`, httpFirewallsCheck)

	http.HandleFunc(`/job/forwarding-rules/delete`, httpForwardingRulesDelete)
	http.HandleFunc(`/job/url-maps/delete`, httpUrlMapsDelete)
	http.HandleFunc(`/job/ssl-certificates/delete`, httpBackendServicesDelete)
	http.HandleFunc(`/job/backend-services/delete`, httpBackendServicesDelete)
	http.HandleFunc(`/job/target-pools/check`, httpTargetPoolCheck)
	http.HandleFunc(`/job/target-pools/delete`, httpTargetPoolsDelete)
	http.HandleFunc(`/job/target-http-proxies/delete`, httpTargetProxiesDelete)
	http.HandleFunc(`/job/health-checks/delete`, httpHealthChecksDelete)
}

func handleJobError(w http.ResponseWriter, r *http.Request, e error) {
	ge, ok := e.(*googleapi.Error)
	if !ok || ge.Code != http.StatusNotFound {
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}

	// if the google api return 404, then there's nothing more we can
	// do for this job. we should just return a 2XX status and prevent
	// the taskqueue from retrying
	ctx := appengine.NewContext(r)
	log.Debugf(ctx, "Resource was not found, signaling end of this job: %s", e)
	http.Error(w, `abort job`, http.StatusNoContent)
}

func httpForwardingRulesCheck(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	fwrs, err := app.ListIngressForwardingRules()
	if err != nil {
		http.Error(w, `failed to list ingress resources`, http.StatusOK)
		return
	}

	log.Debugf(ctx, "Loaded %d forwarding rules", len(fwrs))

	seenHttpProxies := make(map[string]struct{})
	seenHttpsProxies := make(map[string]struct{})
	for _, fwr := range fwrs {
		log.Debugf(ctx, "Checking forwarding rule %s", fwr.Name)
		tpname, region, isHTTPs, err := ParseTargetProxy(fwr.Target)
		if err != nil {
			continue
		}

		if isHTTPs {
			seenHttpsProxies[tpname] = struct{}{}
		} else {
			seenHttpProxies[tpname] = struct{}{}
		}

		t := taskqueue.NewPOSTTask("/job/target-pools/check", url.Values{
			"forwarding_rule": {fwr.Name},
			"tp_name":         {tpname},
			"region":          {region},
			"https":           {strconv.FormatBool(isHTTPs)},
		})
		taskqueue.Add(ctx, t, queueName)
	}

	// We're done checking for load balancers that have a forwarding rule,
	// but we may have target proxies without load balancers, which were
	// created by GKE
	if l, err := app.service.TargetHttpProxies.List(app.project).Do(); err == nil {
		for _, tp := range l.Items {
			if !strings.HasPrefix(tp.Name, `k8s-tp`) {
				continue
			}
			if _, ok := seenHttpProxies[tp.Name]; !ok {
				checkAndDeleteTargetProxiesIfApplicable(ctx, app, "", "", tp.Name, false)
			}
		}
	}
	if l, err := app.service.TargetHttpsProxies.List(app.project).Do(); err == nil {
		for _, tp := range l.Items {
			if !strings.HasPrefix(tp.Name, `k8s-tp`) {
				continue
			}
			if _, ok := seenHttpsProxies[tp.Name]; !ok {
				checkAndDeleteTargetProxiesIfApplicable(ctx, app, "", "", tp.Name, true)
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func httpTargetPoolCheck(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	tpname := r.FormValue("tp_name")
	fwname := r.FormValue("forwarding_rule")
	region := r.FormValue("region")
	isHTTPs, _ := strconv.ParseBool(r.FormValue("https"))

	if err := checkAndDeleteTargetProxiesIfApplicable(ctx, app, fwname, region, tpname, isHTTPs); err != nil {
		http.Error(w, err.Error(), http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func checkAndDeleteTargetProxiesIfApplicable(ctx context.Context, app *App, fwname, region, tpname string, isHTTPs bool) error {
	var urlMapURL string
	var certificates []string
	var tpName string
	var timestamp string
	if isHTTPs {
		tp, err := app.GetTargetHttpsProxy(tpname)
		if err != nil {
			return errors.Wrap(err, `failed to get target https proxy`)
		}
		tpName = tp.Name
		certificates = tp.SslCertificates
		urlMapURL = tp.UrlMap
		timestamp = tp.CreationTimestamp
	} else {
		tp, err := app.GetTargetHttpProxy(tpname)
		if err != nil {
			return errors.Wrap(err, `failed to get target http proxy`)
		}
		tpName = tp.Name
		urlMapURL = tp.UrlMap
		timestamp = tp.CreationTimestamp
	}

	if t, _ := time.Parse(time.RFC3339, timestamp); t.After(time.Now().Add(-1 * time.Hour)) {
		// if it's pretty new, that's OK. it may still be initializing,
		// for all I care
		return nil
	}

	umname, _, err := ParseUrlMap(urlMapURL)
	if err != nil {
		return errors.Wrap(err, `failed to parse url map selflink`)
	}

	um, err := app.GetUrlMap(umname)
	if err != nil {
		return errors.Wrap(err, `failed to get url map`)
	}

	services, err := app.FindBackendServices(um)
	if err != nil {
		return errors.Wrap(err, `failed to find backend services`)
	}

	var total int
	for _, service := range services {
		instances, err := app.ListInstancesForService(service)
		if err != nil {
			return errors.Wrap(err, `failed to list instances for service`)
		}
		total = total + len(instances)
	}

	// Cowardly refuse to delete resources if at least 1 instance
	// exist somewhere
	if total > 0 {
		return nil
	}

	expires := time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339)

	var tasks []*taskqueue.Task

	tasks = append(tasks, taskqueue.NewPOSTTask(`/job/target-http-proxies/delete`, url.Values{
		"name":    {tpName},
		"https":   {strconv.FormatBool(isHTTPs)},
		"expires": {expires},
	}))

	if isHTTPs {
		for _, cert := range certificates {
			certName, _, err := ParseSslCertificates(cert)
			if err != nil {
				continue
			}

			// delete the certificates
			tasks = append(tasks, taskqueue.NewPOSTTask(`/job/ssl-certificates/delete`, url.Values{
				"name":    {certName},
				"expires": {expires},
			}))
		}
	}

	// delete backend services
	for _, service := range services {
		_, bsRegion, _ := ParseBackendServices(service.SelfLink)
		tasks = append(tasks, taskqueue.NewPOSTTask(`/job/backend-services/delete`, url.Values{
			"name":    {service.Name},
			"region":  {bsRegion},
			"expires": {expires},
		}))

		for _, hc := range service.HealthChecks {
			name, _, _ := ParseHealthChecks(hc)
			tasks = append(tasks, taskqueue.NewPOSTTask(`/job/health-checks/delete`, url.Values{
				"name":    {name},
				"expires": {expires},
			}))
		}
	}

	tasks = append(tasks, taskqueue.NewPOSTTask(`/job/url-maps/delete`, url.Values{
		"name":    {umname},
		"expires": {expires},
	}))

	if len(fwname) > 0 {

		tasks = append(tasks, taskqueue.NewPOSTTask("/job/forwarding-rules/delete", url.Values{
			"name":    {fwname},
			"region":  {region},
			"expires": {expires},
		}))
	}

	for _, t := range tasks {
		taskqueue.Add(ctx, t, queueName)
	}

	return nil
}

func isExpired(r *http.Request) bool {
	expires, err := time.Parse(time.RFC3339, r.FormValue(`expires`))
	return err != nil || time.Now().UTC().After(expires)
}

func httpForwardingRulesDelete(w http.ResponseWriter, r *http.Request) {
	if isExpired(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	name := r.FormValue(`name`)
	region := r.FormValue(`region`)
	log.Debugf(ctx, `Request to delete forwarding rule %s (region = %s)`, name, region)
	if region == `global` {
		if _, err := app.service.GlobalForwardingRules.Delete(app.project, name).Context(ctx).Do(); err != nil {
			log.Debugf(ctx, `failed to delete global forwarding rule %s`, err)
			handleJobError(w, r, err)
			return
		}
	} else {
		if _, err := app.service.ForwardingRules.Delete(app.project, region, name).Context(ctx).Do(); err != nil {
			log.Debugf(ctx, `failed to delete region (%s) forwarding rule %s`, region, err)
			handleJobError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func httpUrlMapsDelete(w http.ResponseWriter, r *http.Request) {
	if isExpired(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	name := r.FormValue(`name`)
	log.Debugf(ctx, `Request to delete url map %s`, name)
	if _, err := app.service.UrlMaps.Delete(app.project, name).Context(ctx).Do(); err != nil {
		log.Debugf(ctx, `Failed to delete url map: %s`, err)
		handleJobError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func httpBackendServicesDelete(w http.ResponseWriter, r *http.Request) {
	if isExpired(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	name := r.FormValue(`name`)
	region := r.FormValue(`region`)
	log.Debugf(ctx, `Request to delete backend service %s (region = %s)`, name, region)
	if region == `global` {
		if _, err := app.service.BackendServices.Delete(app.project, name).Context(ctx).Do(); err != nil {
			log.Debugf(ctx, `failed to delete global backend service %s`, err)
			handleJobError(w, r, err)
			return
		}
	} else {
		if _, err := app.service.RegionBackendServices.Delete(app.project, region, name).Context(ctx).Do(); err != nil {
			log.Debugf(ctx, `failed to delete regional (%s) backend service %s`, region, err)
			handleJobError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func httpSslCertificatesDelete(w http.ResponseWriter, r *http.Request) {
	if isExpired(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	name := r.FormValue(`name`)
	log.Debugf(ctx, `Request to delete ssl certificate %s`, name)
	if _, err := app.service.SslCertificates.Delete(app.project, name).Context(ctx).Do(); err != nil {
		log.Debugf(ctx, `Failed to delete ssl certificate %s`, err)
		handleJobError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func httpTargetPoolsDelete(w http.ResponseWriter, r *http.Request) {
	if isExpired(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	name := r.FormValue(`name`)
	region := r.FormValue(`region`)
	log.Debugf(ctx, `Request to delete target pool %s (region = %s)`, name, region)
	if _, err := app.service.TargetPools.Delete(app.project, region, name).Context(ctx).Do(); err != nil {
		log.Debugf(ctx, `Failed to delete target pool %s`, err)
		handleJobError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func httpHealthChecksDelete(w http.ResponseWriter, r *http.Request) {
	if isExpired(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	name := r.FormValue(`name`)
	log.Debugf(ctx, `Request to delete health check %s`, name)
	if _, err := app.service.HealthChecks.Delete(app.project, name).Context(ctx).Do(); err != nil {

		log.Debugf(ctx, `Failed to delete health check %s`, err)
		handleJobError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func httpTargetProxiesDelete(w http.ResponseWriter, r *http.Request) {
	if isExpired(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	name := r.FormValue(`name`)
	isHTTPs, _ := strconv.ParseBool(r.FormValue("https"))
	log.Debugf(ctx, `Request to delete target http proxy %s (HTTPs = %t)`, name, isHTTPs)

	if isHTTPs {
		if _, err := app.service.TargetHttpsProxies.Delete(app.project, name).Context(ctx).Do(); err != nil {
			log.Debugf(ctx, `Failed to delete target https proxy %s`, err)
			handleJobError(w, r, err)
			return
		}
	} else {
		if _, err := app.service.TargetHttpProxies.Delete(app.project, name).Context(ctx).Do(); err != nil {
			log.Debugf(ctx, `Failed to delete target http proxy %s`, err)
			handleJobError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func httpFirewallsCheck(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	app, err := AppengineApp(ctx)
	if err != nil {
		http.Error(w, `failed to get app`, http.StatusOK)
		return
	}

	firewalls, err := app.ListDanglingFirewalls(ctx)
	if err != nil {
		log.Debugf(ctx, `Failed to list dangling firewall rules %s`, err)
		handleJobError(w, r, err)
		return
	}

	for _, fw := range firewalls {
		log.Debugf(ctx, `Deleting firewall %s`, fw.Name)

		if _, err := app.service.Firewalls.Delete(app.project, fw.Name).Do(); err != nil {
			log.Debugf(ctx, `Failed to delete dangling firewall rule %s: %s`, fw.Name, err)
			handleJobError(w, r, err)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}
