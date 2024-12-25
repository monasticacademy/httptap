<h1 align="center">
  <img src="./.github/banner.webp" alt="httptap" height="450px">
  <br>
  httptap
  </br>
</h1>
<p align="center">
  <a href="https://pkg.go.dev/github.com/monasticacademy/httptap"><img src="https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square" alt="Documentation"></a>
  <a href="https://github.com/monasticacademy/httptap/actions"><img src="https://github.com/monasticacademy/httptap/workflows/Test/badge.svg" alt="Build Status"></a>
</p>
<br>

View the HTTP and HTTPS requests made by a linux program:

```shell
$ httptap -- curl https://monasticacademy.org
---> GET https://monasticacademy.org/
<--- 308 https://monasticacademy.org/ (15 bytes)
```

```shell
httptap -- python -c "import requests; requests.get('https://monasticacademy.org')"
---> GET https://monasticacademy.org/
<--- 308 https://monasticacademy.org/ (15 bytes)
---> GET https://www.monasticacademy.org/
<--- 200 https://www.monasticacademy.org/ (5796 bytes)
```

Httptap runs the requested command in an isolated network namespace, injecting a certificate authority created on-the-fly in order to decrypt HTTPS traffic. If you can run `<command>` on your shell, you can likely also run `httptap -- <command>`. You do not need to be the root user, nor set up any kind of daemon, nor make any system-wide changes to your system. The `httptap` executable is a static Go binary that runs without dependencies. You can install it with:

```shell
go install github.com/monasticacademy/httptap@latest
```

or download a pre-built release with:

```shell
curl -L https://github.com/monasticacademy/httptap/releases/download/v0.0.3/httptap_Linux_x86_64.tar.gz | tar xzf -
```

Httptap is linux-only. It makes extensive use of linux-specific system calls and is unlikely to be ported to other operating systems.

# Install pre-built binary

```shell
curl -L https://github.com/monasticacademy/httptap/releases/download/v0.0.3/httptap_Linux_x86_64.tar.gz | tar xzf -
```

For all versions and CPU architectures see the [releases page](https://github.com/monasticacademy/httptap/releases/).

# Install with Go

```shell
go install github.com/monasticacademy/httptap@latest
```

# Quickstart

Let's run a simple test:

```shell
httptap -- curl -s https://buddhismforai.sutra.co -o /dev/null
---> GET https://buddhismforai.sutra.co/
<--- 302 https://buddhismforai.sutra.co/ (117 bytes)
```

What happened here is that we ran `curl -s https://buddhismforai.sutra.co -o /dev/null` and it received a 302 redirect from the server. `httptap` printed summaries of the HTTP requests and their responses. Let's see how it changes if we tell curl to follow redirects by adding `-L`:

```shell
httptap -- curl -sL https://buddhismforai.sutra.co -o /dev/null
---> GET https://buddhismforai.sutra.co/
<--- 302 https://buddhismforai.sutra.co/ (117 bytes)
---> GET https://buddhismforai.sutra.co/space/cbodvy/content
<--- 200 https://buddhismforai.sutra.co/space/cbodvy/content (6377 bytes)
```

Now we can see that after receiving the 302 redirect, curl made an additional HTTP request to the URL to which it was redirected, which is what you expect when using `-L` with curl.

Let's see what HTTP endpoints the Google Cloud command line interface uses to list compute resources (this requires that you have gcloud installed and are signed in):

```shell
$ httptap gcloud compute instances list
---> POST https://oauth2.googleapis.com/token
<--- 200 https://oauth2.googleapis.com/token (997 bytes)
---> GET https://compute.googleapis.com/compute/v1/projects/maple-public-website/aggregated/instances?alt=json&includeAllScopes=True&maxResults=500&returnPartialSuccess=True
<--- 200 https://compute.googleapis.com/compute/v1/projects/maple-public-website/aggregated/instances?alt=json&includeAllScopes=True&maxResults=500&returnPartialSuccess=True (19921 bytes)
NAME       ZONE        MACHINE_TYPE  PREEMPTIBLE  INTERNAL_IP  EXTERNAL_IP     STATUS
<your cloud instances listed here>
```

What happened here is that we ran `gcloud compute instances list`, which lists the compute instances that the signed-in user has on Google Cloud. The bottom two lines of output were printed by `gcloud`; the rest were printed by `httptap` and show what HTTP requests `gcloud` used to get the information it printed.

Let's see what HTTP endpoints kubectl uses in a "get all" (this requires that you have kubectl installed and are authenticated to a cluster):

```shell
$ httptap --https 443 6443 -- kubectl get all --insecure-skip-tls-verify
---> GET https://cluster:6443/api/v1/namespaces/default/pods?limit=500
<--- 200 https://cluster:6443/api/v1/namespaces/default/pods?limit=500 (38345 bytes)
---> GET https://cluster:6443/api/v1/namespaces/default/replicationcontrollers?limit=500
<--- 200 https://cluster:6443/api/v1/namespaces/default/replicationcontrollers?limit=500 (2509 bytes)
---> GET https://cluster:6443/api/v1/namespaces/default/services?limit=500
<--- 200 https://cluster:6443/api/v1/namespaces/default/services?limit=500 (5586 bytes)
---> GET https://cluster:6443/apis/apps/v1/namespaces/default/daemonsets?limit=500
<--- 200 https://cluster:6443/apis/apps/v1/namespaces/default/daemonsets?limit=500 (3052 bytes)
---> GET https://cluster:6443/apis/apps/v1/namespaces/default/deployments?limit=500
<--- 200 https://cluster:6443/apis/apps/v1/namespaces/default/deployments?limit=500 (7438 bytes)
---> GET https://cluster:6443/apis/apps/v1/namespaces/default/replicasets?limit=500
<--- 200 https://cluster:6443/apis/apps/v1/namespaces/default/replicasets?limit=500 (47211 bytes)
---> GET https://cluster:6443/apis/apps/v1/namespaces/default/statefulsets?limit=500
<--- 200 https://cluster:6443/apis/apps/v1/namespaces/default/statefulsets?limit=500 (1416 bytes)
---> GET https://cluster:6443/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers?limit=500
<--- 200 https://cluster:6443/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers?limit=500 (2668 bytes)
---> GET https://cluster:6443/apis/batch/v1/namespaces/default/cronjobs?limit=500
<--- 200 https://cluster:6443/apis/batch/v1/namespaces/default/cronjobs?limit=500 (3134 bytes)
---> GET https://cluster:6443/apis/batch/v1/namespaces/default/jobs?limit=500
<--- 200 https://cluster:6443/apis/batch/v1/namespaces/default/jobs?limit=500 (2052 bytes)
<kubectl output will be here>
```

In the above, `--insecure-skip-tls-verify` is necessary because kubectl doesn't use the httptap-generated certificate authority, and `--https 443 6443` says to treat TCP connections on ports 443 and 6443 as HTTPS connections, which is needed because my cluter's API endpoint uses port 6443.

Let's see how DNS-over-HTTP works:

```shell
$ httptap -- curl -sL --doh-url https://cloudflare-dns.com/dns-query https://buddhismforai.sutra.co -o /dev/null
---> POST https://cloudflare-dns.com/dns-query
<--- 200 https://cloudflare-dns.com/dns-query (149 bytes)
---> POST https://cloudflare-dns.com/dns-query
<--- 200 https://cloudflare-dns.com/dns-query (150 bytes)
---> GET https://buddhismforai.sutra.co/
<--- 302 https://buddhismforai.sutra.co/ (117 bytes)
---> GET https://buddhismforai.sutra.co/space/cbodvy/content
<--- 200 https://buddhismforai.sutra.co/space/cbodvy/content (6377 bytes)
```

What happened here is that we told `curl` to request the url "https://buddhismforai.sutra.co", using the cloudflare DNS-over-HTTP service for DNS queries. In the output we see that `curl` made 4 HTTP requests in total; the first two were DNS lookups, and then the second two were the HTTP requests for buddhismforai.sutra.co, making use of the IP addresses obtained in the DNS queries.

Let's see how the DNS-over-HTTP payloads look:

```shell
$ httptap --head --body -- curl -sL --doh-url https://cloudflare-dns.com/dns-query https://buddhismforai.sutra.co -o /dev/null
---> POST https://cloudflare-dns.com/dns-query
> Accept: */*
> Content-Type: application/dns-message
> Content-Length: 40
buddhismforaisutraco
<--- 200 https://cloudflare-dns.com/dns-query (149 bytes)
< Alt-Svc: h3=":443"; ma=86400
< Server: cloudflare
< Date: Tue, 24 Dec 2024 18:13:12 GMT
< Content-Type: application/dns-message
< Access-Control-Allow-Origin: *
< Content-Length: 149
< Cf-Ray: 8f7290631e334211-EWR
buddhismforaisutraco�
��w�4+#G�.           <wildcardsutraco	herokudnscom�4+!�=�4+
...
```

Here the `--head` option tells httptap to print the HTTP headers, and `--body` tells it to print the raw HTTP payloads. To keep it short I'm showing just the first request/response pair above.

# How it works

In linux, there is a kernel API for creating and configuring network interfaces. Conventionally, a network interface would be a physical ethernet or WiFi controller in your computer, but it is possible to create a special kind of network interface called a TUN device. A TUN device shows up to the system in the way that any network interface shows up, but any traffic written to it will be delivered to a file descriptor held by the process that created it. Httptap creates a TUN device and runs the subprocess in an environment in which all network traffic is routed through that device.

There is also a kernel API in linux for creating network namespaces. A network namespace is a list of network interfaces and routing rules. When a process is started in linux, it can be run in a specified network namespace. By default, processes run in a root network namespace that we do not want to make chagnes to because doing so would affect all network traffic on the system. Instead, we create a network namespace in which there are only two network interfaces: a loopback device (127.0.0.1) and a TUN device that delivers traffic to us. Then we run the subprocess in that namespace.

The traffic from the network device is delivered to us as raw IP packets. We must parse the IP packets as well as the inner TCP and UDP packets, and write raw IP packets back to the subprocess. This requires a software implementation of the TCP/IP protocol, which is by far the most difficult part of httptap. The TCP/IP implementation in httptap is missing many aspects of the full TCP protocol, but still works reasonably well for its purpose.

Suppose the subprocess makes an HTTP request to www.example.com. The first thing we receive is a TCP SYN packet addressed to 93.184.215.14 (the current IP address of example.com). We respond with a SYN+ACK packet with source address 93.184.215.14, though in truth the packet did not come from 93.184.215.14, but from us. Separately, we establish our own TCP connection to 93.184.215.14 using the ordinary sockets API in the linux kernel. When the subprocess sends data to 93.184.215.14 we relay it over our separate TCP connection, and vice versa for return data. This is a traditional transparent TCP proxy, and in this way we can view all data flowing to and from the subprocess, though we won't be able to decrypt HTTPS traffic without a bit more work.

When a client makes an HTTPS request, it asks the server for evidence that it is who it says it is. If the server has a certificate signed by a certificate authority, it can use that certificate to prove that it is who it says it is. The client will only accept such a certificate if it trusts the certificate authority that signed the certificate. Operating systems, web browsers, and many other pieces of software come with a list of a few hundred certificate authorities that they trust. Many of these pieces of software have ways for users to add additional certificate authorities to this list. We make use of this.

When httptap starts, it creates a certificate authority (actually a private key plus a corresponding x509 certificate), writes it to a file on the filesystem visible only to the subprocess, and sets a few environment variables -- again only visible to the subprocess being run -- that add this certificate authority to the list of trusted certificate authorities. Since the subprocess trusts this certificate authority, and httptap holds the private key for the certificate authority, it can prove to the subprocess that it is the server which which the subprocess was trying to communicate. In this way we can read the plaintext HTTP requests.

# Caveats

- The process cannot listen for incoming network connections
- You need access to `/dev/net/tun`
