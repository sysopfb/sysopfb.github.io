---
layout: post
title:  "GoLang dropper with a Gravity RAT"
date:   2019-09-26 10:31:12 -0600
categories: malware
---


# Intro

GoLang dropper that uses some fun techniques to perform checkins and meta data collection before delivering Gravity RAT.

Sample: 395ca4b330486479ee1b851d50fd160fedee2649e48b0de9c2f1b271732cf700



# Technical Overview

This dropper is pretty simplistic as most dropper variants are, it's job is to deliver an onboard piece of malware for detonation. Before getting to the delivery code though the malware has some interesting code for checkin traffic. The first thing it does is get what filename it's running as and then performs an API request using the service PipeDream.

![PipeDream call]({{ site.url }}/assets/golang_loader/loader_pipedream_api_filename_checkin.png "PipeDream call")

After sending off it's name via PipeDream, the malware enters a loop that will also perform an HTTP request. This request however isn't designed to succeed, it is using the DNSBin service at hxxp://dnsbin[.]zhack[.]ca which can be utilized for DNS exfiltration of data but appears to be more used as a metrics and checkin piece here. Generating the URL and making the GET request is enough to kick off the DNS resolution which will then show up on the DNSBin side.


![DNSbin Checkin]({{ site.url }}/assets/golang_loader/goloader_checkin_over_dnsin_zhack.png "DNSbin Checkin")

After performing the above the loop will fall through to a function that is simply designed to decode and drop an onboard PE file.

![Base64 encoded PE file]({{ site.url }}/assets/golang_loader/goloader_base64_gravityrat.png "Base64 encoded PE file")


After being decoded the file will be dropped as a random named executable, however the exe file extension in the binary is surrounded by a multitude of extensions so perhaps any number of file types could be delivered using this malware. For this sample however the file being delivered is Gravity RAT which was previously written about by Talos, the RATs configuration lines up with the Talos report for the GX version

PDB:
```
C:\Users\The Invincible\Desktop\gx\gx-current-program\LSASS\obj\Release\LSASS.pdb
```

Config:
```
/GX/GX-Server.php
/GX/GX-Server.php?VALUE=2&Type=
&SIGNATUREHASH=
/GetActiveDomains.php
http://cone.msoftupdates.com:46769
http://ctwo.msoftupdates.com:46769
http://cthree.msoftupdates.com:46769
http://eone.msoftupdates.eu:46769
http://etwo.msoftupdates.eu:46769
```








References:  
 1. https://github.com/sibears/IDAGolangHelper  
 2. https://twitter.com/omespino/status/996091344845262848  
 3. https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html  


 
 
 


[1]:https://github.com/sibears/IDAGolangHelper  
[2]:https://twitter.com/omespino/status/996091344845262848  
[3]:https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html  






