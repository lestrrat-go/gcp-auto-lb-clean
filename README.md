# auto-lb-clean

GAE appliation to automatically clean up after dangling GCP load balancers

# CAVEAT EMPTOR

BEWARE! DELETES GCP RESOURCES!
USE AT YOUR OWN PERIL!

# DESCRIPTION

As of this writing (Dec 2017), the following steps almost always leave
dangling HTTP(s) LBs (dangling meaning the backend instances/instance groups are
long gone, but resources such as the forwarding rules and target proxies are still
alive):

1. Create a GKE cluster
2. Create Ingress resources in said cluster (note: I create them through kube-lego)
3. Delete the GKE cluster (either via CLI or Web Console)

The dangling load balancers are there because when a GKE cluster is deleted, the
VMs and the master nodes are just killed without allowing Kubernetes to gracefully
clean up after itself (I'm not even sure if it's possible for GKE to perform a
global destruction type of unloading).

This is my attempt to not having to worry about this anymore. I hope Google fix things
so I no longer have to worry about somebody (myself included) randomly decides to
delete a cluster used for development, only to find that dangling load balancers
were adding up to your monthly bill.

# DELETING HTTP(s) LOAD BALANCERS

The basic mode of operations is as follows:

1. Look for forwarding rules that starts with "k8s-fw"
2. Find the corresponding target http(s) proxies
3. Find the corresponding url maps
4. Find the corresponding backend services
5. Find the corresponding instance groups
6. Find the corresponing instances

If the instances list comes up empty, we declare this url map "dead".
If all the url maps in the target proxy are dead, then we declared this target proxy "dead".
If all the target proxies are dead, we declare this forwarding rule "dead".

We delete the corresponding forwarding rule, backend services, healthchecks, and SSL certificates along with it.

There's another possibility: We could have load balancers dangling while it failed
to properly initialize and there are no corresponding forwarding rules. In order to
catch these, we look for target http(s) proxies that have not yet been found during
the search in the above operation, and check those as well.

Both of these combined will cover

# DELETING SERVICE LOAD BALANCERS

(UNIMPLEMENTED)

Sometimes Service resources are also left dangling (probably when "LoadBalancer" mode is used).

1. Look for forwarding rules with description matching "kubernets.io/service-name"
2. Find the corresponding target pool
3. Find the corresponding instances

If there are no active instances in the target pool, then the target pool is delcared "dead", and so is the forwarding rule.

We delete the corresponding forwarding rule and target pool.

# INSTALLATION

```
gcloud app deploy .
```

You should probably deploy the contents of `cron.yaml`, but note that if you just do
`gcloud app deploy cron.yaml`, it will overwrite any existing cron configuration.
If you have a main cron.yaml that you already use, merge the contents of this `cron.yaml`
to that file and deploy from there.
