---
layout: post
title:  "Loaders loading loaders, Buer to Smoke"
date:   2020-03-18 10:31:12 -0600
categories: malware, buer, smokeloader
---


After finding a collection of samples I noticed they were in a report: https://securelist.com/mokes-and-buerak-distributed-under-the-guise-of-security-certificates/96324/

Buer loader: 1e37cf52cafb1f3e6eea67caa620379f37e5bd271fa21786ee33ad000164da83

The Buer loader is crypted with a NSIS based crypter that will load a DLL to decrypt the unpacked malware.

Decoded Buer config:
```
{'RC4': 'YwDTTaRqUdxR2VvmxgfSsZEx2UM9fqF3wL2x2MrjMmuCY', 'C2': ['hxxps://oderstrg.site/', 'hxxps://kkjjhhdff.site/']}
```

Another sample: 09b454c55823b836d30fd5330f3408f6622e0c2d9d720712bcf1def0eaed9ed9
```
{'RC4': 'YwDTTaRqUdxR2VvmxgfSsZEx2UM9fqF3wL2x2MrjMmuCY', 'C2': ['hxxps://oderstrg.site/', 'hxxps://kkjjhhdff.site/']}
```

SmokeLoader: baf3dafaf808746d9e3c5ed0c12fcb6e332c0f378e52e8fb50e1c05d14775614

UPX packed, unpacked: 250ea14911f24c0a3e0605f9bfbbde5d


We can xor the entire binary by 0x4c and see some unicode strings related to anti-analysis functionality:
 
```
 process call create "%s"
runas
wmic
qemu
virtio
vmware
vbox
9C99.vmt
\REGISTRY\MACHINE\System\CurrentControlSet\Enum\IDE
\REGISTRY\MACHINE\System\CurrentControlSet\Enum\SCSI
%systemroot%\system32\ntdll.dll
kernel32
user32
advapi32
shell32

```


Looks like some new checks were added that I don't recall seeing before to SmokeLoader. The major version of the OS is checked:

![Major OS Version Check]({{ site.url }}/assets/smokeloader/smoke_major_version_check.png "Major OS Version Check")

A language check using GetKeyboardLayout:

![Keyboard Language Check]({{ site.url }}/assets/smokeloader/keyboardlayout_ida.png "Keyboard Language Check")


Ultimately this is a wrapper that performs a number of checks such as the IsBeingDebugged flag and the NtGlobalFlag and will eventually decode the next layer which will be injected into explorer. The DLL still has its headers stripped which has been covered by hasherzade previously[1].
This sample comes with both a 32 bit and a 64 bit version, the loader checks the GS segment register to determine which one to load[2].


![Bit check]({{ site.url }}/assets/smokeloader/64bit_gs_check_ida.png "Bit Check")


After being XOR decoded and LZNT decompressed the DLL has its headers stripped and the first byte is a offset to where the NT Headers would start.

```
00000000: c000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 4c01 0200 0000 0000 0000 0000  ....L...........
000000d0: 0000 0000 e000 0221 0b01 0c00 0036 0000  .......!.....6..
000000e0: 0002 0000 0000 0000 3417 0000 0010 0000  ........4.......
000000f0: 0050 0000 0000 0010 0010 0000 0002 0000  .P..............
00000100: 0600 0000 0000 0000 0600 0000 0000 0000  ................
00000110: 0060 0000 0004 0000 0000 0000 0200 0004  .`..............
00000120: 0000 1000 0010 0000 0000 1000 0010 0000  ................
00000130: 0000 0000 1000 0000 0000 0000 0000 0000  ................
00000140: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000160: 0050 0000 6000 0000 0000 0000 0000 0000  .P..`...........

```

So we can reconstruct pretty easily and rebuild both the 32 bit and 64 bit DLLs. This will be mapped into explorer by using resolved functions from a manually loaded copy of NTDLL, a technique that isn't new but was previously seen being used by SmokeLoader by CheckPoint[3].
It finds explorer by using GetShellWindow -> GetWindowThreadProcessId and then begins mapping in the DLL.

The strings in the DLL are decoded in a similar manner as I have previously written about[4] but instead of decoding the entire block the strings are decoded in sequence with each string being decoded using RC4 the block of strings then is an array of structures like so:

```
struct encoded_string
{
	unsigned char sLength;
	unsigned char encoded_string[sLength];
}

struct encoded_string block[0x3f6];
```

Decoded strings:
```
https://dns.google/resolve?name=microsoft.com
Software\Microsoft\Internet Explorer
advapi32.dll
Location:
plugin_size
\explorer.exe
user32
advapi32
urlmon
ole32
winhttp
ws2_32
dnsapi
shell32
svcVersion
Version
<?xml version="1.0"?><scriptlet><registration classid="{00000000-0000-0000-0000-00000000%04X}"><script language="jscript"><![CDATA[GetObject("winmgmts:Win32_Process").Create("%ls",null,null,null);]]></script></registration></scriptlet>
.bit
%sFF
%02x
%s%08X%08X
%s\%hs
%s%s
regsvr32 /s %s
regsvr32 /s /n /u /i:"%s" scrobj
%APPDATA%
%TEMP%
.exe
.dll
.bat
:Zone.Identifier
POST
Content-Type: application/x-www-form-urlencoded
open
Host: %s
PT10M
1999-11-30T00:00:00
{% raw %}
NvNgxUpdateCheckDaily_{%08X-%04X-%04X-%04X-%08X%04X}
{% endraw %}
Accept: */*
Referer: %S
```

The C2 URL encoding was also changed as mentioned by CheckPoint[3].

![C2 Decoding]({{ site.url }}/assets/smokeloader/decode_c2s.png "C2 Decoding")

Using the same routine from Cert-PLs blog on SmokeLoader[5] we can slightly modify it to decoded out the C2 URLs:

```
def smoke_unxor(enc_buf, dwordv):
  key_dword = struct.pack("<I", dwordv)
  r = reduce(lambda x,y:ord(y)^x, key_dword, 0xe4)
  return ''.join(chr(ord(a) ^ r) for a in enc_buf)
```

Decoded C2 URLs:

```
hxxp://iknocjtoid.pw/
hxxp://obstratorvv.pw/
hxxp://gameonfagpsf.pw/
```

References:  
 1. https://blog.malwarebytes.com/threat-analysis/2016/08/smoke-loader-downloader-with-a-smokescreen-still-alive/  
 2. https://osandamalith.com/2017/09/24/detecting-architecture-in-windows/  
 3. https://research.checkpoint.com/2019/2019-resurgence-of-smokeloader/  
 4: https://www.fidelissecurity.com/threatgeek/threat-intelligence/smokeloader-downloader/  
 5: https://www.cert.pl/en/news/single/dissecting-smoke-loader/  


[1]:https://blog.malwarebytes.com/threat-analysis/2016/08/smoke-loader-downloader-with-a-smokescreen-still-alive/  
[2]:https://osandamalith.com/2017/09/24/detecting-architecture-in-windows/  
[3]:https://research.checkpoint.com/2019/2019-resurgence-of-smokeloader/  
[4]:https://www.fidelissecurity.com/threatgeek/threat-intelligence/smokeloader-downloader/  
[5]:https://www.cert.pl/en/news/single/dissecting-smoke-loader/  

