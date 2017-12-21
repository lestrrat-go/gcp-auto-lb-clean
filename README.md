# DESCRIPTION

As of this writing (Dec 2017), the following steps almost always leave
dangling HTTP(s) LBs:

1. Create a GKE cluster
2. Create Ingress resources in said cluster (note: I create them through kube-lego)
3. Delete the GKE cluster (either via CLI or Web Console)

I then go to the Network settings, and find that I have forwarding rules and http(s)-backends and what not dangling, even when the underlying GCE instances have long been deleted.

If they are just there, it's not that much of a problem, but there are two problems here:

1. Sometimes they are still associated with a reserved static IP (i.e. new ingresses can't take them over)
2. You get charged for those danling HTTPs by the hour.

This is my attempt to not having to worry about this anymore. I hope they fix it soon.

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


# DELETING SERVICE LOAD BALANCERS

Sometimes Service resources are also left dangling (probably when "LoadBalancer" mode is used).

1. Look for forwarding rules with description matching "kubernets.io/service-name"
2. Find the corresponding target pool
3. Find the corresponding instances

If there are no active instances in the target pool, then the target pool is delcared "dead", and so is the forwarding rule.

We delete the corresponding forwarding rule and target pool.

# ARCHITECTURE

The handler to perform the above task is implemented as a Google AppEngine (Standard) application, which is invoked via cron.
