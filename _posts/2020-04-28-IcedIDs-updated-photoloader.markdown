---
layout: post
title:  "IcedID PhotoLoader evolution"
date:   2020-04-28	 07:33:40 -1010
categories: malware, icedid
---

 
IcedID continues to evolve but yet not a lot of attention is given it, Joshua Platt, Vitali Kremez and 
myself recently released a report[[1]] detailing how they have been targeting and continue to target 
tax season in the midst of the Covid-19 pandemic which has extended tax season in the US to July.

In light of this they are also continuing to innovate on their malware tools including their PhotoLoader which was 
detailed by MalwareBytes previously[[2]]. The loader has recently had a number of additions added to it which appear to be designed 
towards protecting the payloads and also evading network detection.

# Config

The loader comes with an onboard configuration which will be decoded:


![Decode onboard config]({{ site.url }}/assets/photoloader_update/decode_config.png "Decode onboard config")


Decoding this config shows some hex data and a number of domains:


![Decoded config]({{ site.url }}/assets/photoloader_update/decoded_config.png "Decoded config")


Some of these domains are legit and one of them stands out as suspect, the loader enumerates these domains and makes requests to them in a loop.


![Make request and look for url tag]({{ site.url }}/assets/photoloader_update/make_req_look_for_url.png "Make request and look for url tag")


After retrieving the content it will look for the first occurrence of ‘url(“‘ or ‘src=”’.


![Initial landing page]({{ site.url }}/assets/photoloader_update/initial_lp.png "Initial landing page")


It will then build another request for this resource from the same domain but depending on the flag value before the domain will determine whether or not the second request will have a callback function set on the request for the retrieved resource.


![Flag check to set callback]({{ site.url }}/assets/photoloader_update/flag_check_for_callback.png "Flag check to set callback")


The callback will add cookie values to the request headers.


![Build cookie header]({{ site.url }}/assets/photoloader_update/build_cookie_add_header.png "Build cookie header")


The cookie values built are based on various information from the infected system.


![Overview of cookies built]({{ site.url }}/assets/photoloader_update/build_cookies_overview.png "Overview of cookies built")


An example of the request can be seen from this sandbox detonation[[3]]:


![Image request]({{ site.url }}/assets/photoloader_update/sandbox_request.png "Image request")


The _u cookie value holds the username and computername hexlified.


![Building the _u cookie]({{ site.url }}/assets/photoloader_update/build_cookie_u.png "Building the _u cookie")


Inspecting the data from the sandbox detonation:


```python
>>> binascii.unhexlify('4445534B544F502D4A474C4C4A4C44')
'DESKTOP-JGLLJLD'
>>> binascii.unhexlify('61646D696E')
'admin'
```


A breakdown of what the cookie values are:


Cookie | Value
--- | ---
_gid | Based on physical address of NIC
_io | Domain identifier from SID
_u | Username and Computername
_gat | Windows version info
_ga | Processor info via CPUID including hypervisor brand if available
_gads | First DWORD from decoded config data, flag from inspecting server certificate, a random DWORD or number passed as parameter with -id=, number of processes


After pulling down the fake image file it will look for ‘IDAT’.


![Look for IDAT]({{ site.url }}/assets/photoloader_update/idat.png "Look for IDAT")


Uses a byte value to determine the size of the RC4 key before RC4 decrypting the data:


![RC4 decode]({{ site.url }}/assets/photoloader_update/rc4_decode.png "RC4 decode")


Then will perform a hash check on the decoded data to determine if it was correct.


![Hash check]({{ site.url }}/assets/photoloader_update/hash_check.png "Hash check")


If the hash check fails it will just continue performing this enumeration through the domain list, effectively turning this process into a checkin loop with fake traffic mixed in.

Many of these added features to their photo loader appear to be designed for evading researchers and detections, 
this gives us insights into their operations as what their customers are asking for dictates what their development team will prioritize. 
With the previous photo loader being blogged about and signatures being released, it was only a few months before a new updated system was created to replace it.





# IOCs
1a4408ff606936ba91fa759414f1c6dd8b27e825

ca792a5d30d3ca751c4486e2d26c828a542a001a

zajjizev[.]club 

hxxp://45.147.231[.]107/ldr.exe

hxxps://customscripts[.]us/ldr_2817175199.exe

karantino[.]xyz

hinkaly[.]club


# Signatures

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"IcedID PhotoLoader Ver2"; flow:established,to_server; content:".png"; http_uri; content:"__gads="; http_cookie; content:"gat="; http_cookie; content:"_ga="; http_cookie; content:"_u="; http_cookie; content:"__io="; http_cookie; content:"_gid="; http_cookie; classtype:trojan-activity; sid:9000030; rev:1; metadata:author Jason Reaves;)
```






References:  
 1. https://labs.sentinelone.com/icedid-botnet-the-iceman-goes-phishing-for-us-tax-returns/  
 2. https://blog.malwarebytes.com/threat-analysis/2019/12/new-version-of-icedid-trojan-uses-steganographic-payloads/  
 3. https://app.any.run/tasks/d092cd7a-3e1c-479f-93e0-6494e464f44e/   


[1]:https://labs.sentinelone.com/icedid-botnet-the-iceman-goes-phishing-for-us-tax-returns/  
[2]:https://blog.malwarebytes.com/threat-analysis/2019/12/new-version-of-icedid-trojan-uses-steganographic-payloads/  
[3]:https://app.any.run/tasks/d092cd7a-3e1c-479f-93e0-6494e464f44e/  


