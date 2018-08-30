---
layout: post
title:  "Manually unpacking Anubis APK"
date:   2018-08-30 10:31:12 -0600
categories: malware, reverse-engineering
---


I've been seeing people talk about Anubis lately so I decided to take a look at it, unfortunately these led me to a whole bunch of packed APK files. Obviously there are blog posts describing the unpack files but all the hashes are leading me to the packed versions. So what do you do in this situation? Well you learn how to search basically, just like you have to learn how to use your favorite search engine if you have a virustotal account you end up having to figure out how to search for whatever you're looking for. Take a look at the jadx-gui picture in this phishlabs writeup[[1]], in this writeup we can see a number of strings but if we search for the twitter address on VirusTotal[[2]] then we come up with a number of classes.dex files.

Example hash:  7118e74f6a1bad86fa0a72c3e5e424c36c11087c4e369b09dcb7bf5c3ace78fa

Searching for the twitter address from the aforementioned writeup leads us to a number of dex files in VirusTotal

![Anubis Class Dex]({{ site.url }}/assets/anubis_unpack/anubis_dex_file.png "Anubis DEX File")


We can then pivot backwards from this file to see where this dex file came from by utilizing the ITW(In The Wild) tab which will show that it came from a file bundle.

![Anubis Dex file bundle]({{ site.url }}/assets/anubis_unpack/dex_itw.png "Anubis DEX File ITW")

This file bundle is just a zipped up classes.dex file, using the ITW tab again we see it was created during the execution of another file.

![Anubis ITW execution]({{ site.url }}/assets/anubis_unpack/zip_execution_parent.png "Anubis DEX parent")

This parent file is an APK with a similar looking obfuscation as the other files I had looked at from reading reports! So these obfuscated APKs are creating these Anubis DEX files which is actually a common occurrence with packed APK files that keep an encoded DEX file on board as a resource.

Another hint that this is packed is by taking a look at the manifest inside this APK.

![Anubis Manifest]({{ site.url }}/assets/anubis_unpack/1_Manifest_shows_other_calls.png "Odd calls in Manifest")

We can see lots of referenced code in the manifest which doesn't actually exist in the current decompiled DEX file, this is another very big indicator that we're dealing with an encoded DEX file in this APK. So the idea is that initial execution in this APK will decode the hidden classes.dex file and replace the current one with that one. Since the resources has a file called 'files' which is just binary data I assume all my theories up until now are true, we could then just execute the APK and catch the decoded classes.dex file like how sandboxes do but that's not really any fun. 

So a few possible ways to attack finding the relevant code section that will be responsible for decoding the dex file, we can trace execution through the obfuscated code of the current dex file and look for possibilities or interesting functions, you can look for where the resource object gets loaded and then trace that, or you can just blindly look for functions that might appear to be doing something interesting and then backtrack. You'd actually be surprised how often number 3 works after you have a few years experience with reverse engineering malware.

For this one however because of all the garbage code that's been addded I just literally searched the decompiled code for "^ " and ended up finding an interesting little function that was being called with an array of integers over and over again by the int values were changing(obfuscated strings?).


![Anubis XOR data]({{ site.url }}/assets/anubis_unpack/6_xor_data.png "Data being XORd")

If you've spent much time reversing encoding and encryption algorithms you might recognize the general flow of that code block but I won't ruin the surprise for now for the rest of you.

Backtracking we can see this function and others named the same, this is basically an overloaded function which can make tracing execution a little painful as you have to match up which function does what based on which parameters are passed. Ofcourse since there's garbage code and obfuscation that can be easier said than done sometimes.

![Anubis overloaded function]({{ site.url }}/assets/anubis_unpack/3_Call_uses_another_variable.png "Anubis overloaded function")

So this function takes an array and then it sets the byte array that it ends up XORing so what is this 'OAeAqJYuzXcD'? Searching for it shows that it's built as a byte array.

![Anubis build byte array]({{ site.url }}/assets/anubis_unpack/4_Created_256_byte_array.png "Anubis build byte array")

The value being passed in for the length of the array is 256 so this a byte array of length 256. Searching for this array some more shows that it's also used with the same 256 value and filled with data based on a byte array passed in. So this looks like it's building an SBOX similar to RC4. Looking for how this all gets called shows that it ends up being called near the top of the 'com.lpapxwl.bemtobai.SVBkpSlwf' class.

![Anubis build RC4 SBOX]({{ site.url }}/assets/anubis_unpack/5_build_rc4_sbox.png "Anubis build RC4 SBOX")

We can continue to follow that plus the previously identified function that was XORing the SBOX back to a section of code near the top of the same code page.

![Anubis Decoding overview]({{ site.url }}/assets/anubis_unpack/2_anubis_call_with_key.png "Anubis Decode overview")

What stands out there is that another 256 byte array is being built and then passed in to the 'dlPiWCFOIB' function and then passed into the overloaded function that builds the SBOX like we previously found. Looking up the 'dlPiWCFOIB' function shows that it is initializing the SBOX.


![Anubis Init SBOX]({{ site.url }}/assets/anubis_unpack/anubis_init_sbox.png "Anubis Init SBOX")

So could the array of integers at the top of the decoding overview screenshot be the RC4 key then? Let's test it on the binary data blob we found in the resources.

```python
>>> a = "(byte) 75, (byte) 41, (byte) -22, (byte) 1, (byte) -99, (byte) -118, (byte) 73, (byte) 34, (byte) 71, (byte) -89, (byte) -26, (byte) 11, (byte) -21, (byte) 24, (byte) -108, (byte) -24, (byte) 24, (byte) 89, (byte) 20, (byte) 91, (byte) -49, (byte) 104, (byte) -99, (byte) -16, (byte) 27, (byte) 73, (byte) 38, (byte) -123, (byte) -60, (byte) 14, (byte) -71, (byte) -4, (byte) 102, (byte) -96, (byte) 37, (byte) 46, (byte) -101, (byte) -13, (byte) 24, (byte) -44, (byte) -56, (byte) -95"
>>> a.split('(byte) ')
['', '75, ', '41, ', '-22, ', '1, ', '-99, ', '-118, ', '73, ', '34, ', '71, ', '-89, ', '-26, ', '11, ', '-21, ', '24, ', '-108, ', '-24, ', '24, ', '89, ', '20, ', '91, ', '-49, ', '104, ', '-99, ', '-16, ', '27, ', '73, ', '38, ', '-123, ', '-60, ', '14, ', '-71, ', '-4, ', '102, ', '-96, ', '37, ', '46, ', '-101, ', '-13, ', '24, ', '-44, ', '-56, ', '-95']
>>> b = a.split('(byte) ')
>>> b
['', '75, ', '41, ', '-22, ', '1, ', '-99, ', '-118, ', '73, ', '34, ', '71, ', '-89, ', '-26, ', '11, ', '-21, ', '24, ', '-108, ', '-24, ', '24, ', '89, ', '20, ', '91, ', '-49, ', '104, ', '-99, ', '-16, ', '27, ', '73, ', '38, ', '-123, ', '-60, ', '14, ', '-71, ', '-4, ', '102, ', '-96, ', '37, ', '46, ', '-101, ', '-13, ', '24, ', '-44, ', '-56, ', '-95']
>>> b = b[1:]
>>> b
['75, ', '41, ', '-22, ', '1, ', '-99, ', '-118, ', '73, ', '34, ', '71, ', '-89, ', '-26, ', '11, ', '-21, ', '24, ', '-108, ', '-24, ', '24, ', '89, ', '20, ', '91, ', '-49, ', '104, ', '-99, ', '-16, ', '27, ', '73, ', '38, ', '-123, ', '-60, ', '14, ', '-71, ', '-4, ', '102, ', '-96, ', '37, ', '46, ', '-101, ', '-13, ', '24, ', '-44, ', '-56, ', '-95']
>>> b[-1].split(',')
['-95']
>>> map(lambda x: x.split(', '),b)
[['75', ''], ['41', ''], ['-22', ''], ['1', ''], ['-99', ''], ['-118', ''], ['73', ''], ['34', ''], ['71', ''], ['-89', ''], ['-26', ''], ['11', ''], ['-21', ''], ['24', ''], ['-108', ''], ['-24', ''], ['24', ''], ['89', ''], ['20', ''], ['91', ''], ['-49', ''], ['104', ''], ['-99', ''], ['-16', ''], ['27', ''], ['73', ''], ['38', ''], ['-123', ''], ['-60', ''], ['14', ''], ['-71', ''], ['-4', ''], ['102', ''], ['-96', ''], ['37', ''], ['46', ''], ['-101', ''], ['-13', ''], ['24', ''], ['-44', ''], ['-56', ''], ['-95']]
>>> map(lambda x: x.split(', ')[0],b)
['75', '41', '-22', '1', '-99', '-118', '73', '34', '71', '-89', '-26', '11', '-21', '24', '-108', '-24', '24', '89', '20', '91', '-49', '104', '-99', '-16', '27', '73', '38', '-123', '-60', '14', '-71', '-4', '102', '-96', '37', '46', '-101', '-13', '24', '-44', '-56', '-95']
>>> c = map(lambda x: x.split(', ')[0],b)
>>> c
['75', '41', '-22', '1', '-99', '-118', '73', '34', '71', '-89', '-26', '11', '-21', '24', '-108', '-24', '24', '89', '20', '91', '-49', '104', '-99', '-16', '27', '73', '38', '-123', '-60', '14', '-71', '-4', '102', '-96', '37', '46', '-101', '-13', '24', '-44', '-56', '-95']
>>> map(int,c)
[75, 41, -22, 1, -99, -118, 73, 34, 71, -89, -26, 11, -21, 24, -108, -24, 24, 89, 20, 91, -49, 104, -99, -16, 27, 73, 38, -123, -60, 14, -71, -4, 102, -96, 37, 46, -101, -13, 24, -44, -56, -95]
>>> d = map(int,c)
>>> map(lambda x: x & 0xff, d)
[75, 41, 234, 1, 157, 138, 73, 34, 71, 167, 230, 11, 235, 24, 148, 232, 24, 89, 20, 91, 207, 104, 157, 240, 27, 73, 38, 133, 196, 14, 185, 252, 102, 160, 37, 46, 155, 243, 24, 212, 200, 161]
>>> e = map(lambda x: x & 0xff, d)
>>> map(chr,e)
['K', ')', '\xea', '\x01', '\x9d', '\x8a', 'I', '"', 'G', '\xa7', '\xe6', '\x0b', '\xeb', '\x18', '\x94', '\xe8', '\x18', 'Y', '\x14', '[', '\xcf', 'h', '\x9d', '\xf0', '\x1b', 'I', '&', '\x85', '\xc4', '\x0e', '\xb9', '\xfc', 'f', '\xa0', '%', '.', '\x9b', '\xf3', '\x18', '\xd4', '\xc8', '\xa1']
>>> ''.join(map(chr,e))
'K)\xea\x01\x9d\x8aI"G\xa7\xe6\x0b\xeb\x18\x94\xe8\x18Y\x14[\xcfh\x9d\xf0\x1bI&\x85\xc4\x0e\xb9\xfcf\xa0%.\x9b\xf3\x18\xd4\xc8\xa1'
>>> f = ''.join(map(chr,e))
>>> rc4 = ARC4.new(f)
>>> rc4.decrypt(data)[:500]
'\x88P\xe3"\x8d\xfa{A\x9d\xe2\xf3\xd67\x80\x0f(\xfc\xf8\'\xff\xe7\xf9Ul\xff\x9b\x9eQ{\xa1\xde\xad6\xd1\xb0Y9\xf9r\'\x05\xb6\xcen\xfa\xf7Q\xc7`\x02\xd8r\xf1\x88\x7f\xfb\t%@;\xda\xbd\xf1nI\x81-!\xac\xa2\xe3!X\xb8\r=;\xd53 \xb8\xf4\xbbT\xfca\xf4\x10\xd0\t\xf2\x12;\xbc\x8b\x0b\x89\x99K\xc5s\xf7\x8fN\x0c3vc\xa6\x92i\xbc\n\x88\xdf%D\x0e\xbc\x91Q0RA\xf59\xc1\xb8]\xdf<hut\xeb\xe3\\G\xa5/| \xdd\x987zMl\x03\xf1?\xb1\x82}m\x02\x14|\\\x01\xc8\xc8\xec<.\xf0;\xd4#\xac\xe8j\x01]\xf6W\xa6\x86\xf7\xa5\x13\xa9\x8e\x84\x87\xbf\xfat\xb8\x02\xdb\xfb\x91\xed\xf2n\xf8\xb8\xa9n\xad\xa15E4\x0e$\xabu\xda*\xe7\xf8?\x8d\xdb\xb4\x16<n2\x13c\xb6W\x90\xa5\x12\xeb\x92\x8e\x1e\t`Y\xcfr\xb0yt\x94\xe6S\xc6u_\nC\xe2\x91:r\x85\x84i#\xd2\xe7\x89\xf1\x96\'%\x08l\n\x8d\xcc\xc9\xc6\x81\xe5\xd2E\x81\xfa\xa7c\xb74v\xc7\xfc,\x99\xcd\xae?\xde\x08[\x9b\xe0\x9e\x86.\x8f\xfa\x84\xbb\x82"\xe7u\xd8\xa9\xfe\x96\xa5@\xdf\x9b\xfe\x843\xb4/[\xcd"<\x9e\x1e\xd2\xcc\xb2\x99Y\x18d\x98\xcc\x10\xc0P!\xc7(\x179&b*\x8d\xfeTU\xd3\x18"9Y--\xa9e|\x92\xeb*\xa0F\xc5}x$\x82jdm!*\xceH\xb1\xedb\xd0Q1w\xe3O\xf5.\xf7\xeb\x84\xa1*W\xc0\xd1\xf6\xc71U\xfdw\xa1.\x0b\xd6S\xc3eZ\xe5xSl\xb7\xaf_\xcfN\xb4\x08\x07?\xe8\xac\xb0c\xdc\xe9+\xe0\xc1\x03\xcc\xc5\xff\xe7\xc8\'Y\xa6\x8f\xb9\xc0\x81\nl5\xc3\xb2$\xbeI*<\xe8\xf8\xd1\xff\xad7>Tb\\\x1c\x0c\xed\xa2\xf0J\x12\xd7\x07+ \xb2\xba\xac\x1bL,\xef\x8f@Ia\t\xe8\xc3\xbb\xa9\x1az\xe8\xee\xb4\xa7\xfe\t\xce"('
```

Well that didn't work, so let's take a look at the binary data a little closer.

```python
>>> data[:100]
'\x9a\xb8\x01\x00B\xa3\xe1&\xdbY\x9agN\xbb\xc44vv\x8ch?\x12\x89/\xd9\xeb(N"p\xbd\x1fY\xd1\x00\xde\x0es\xc3\xe2D\xa4\xd5\xa09\x8e\x86\xc7\xa3m\x92\xd6\x04\x04r\xb65w\xb3\xf8\x81W\xb0\xd3\xe7\xab\x1c\xbe\xaa"\xb5\x8fO8\xdbv\x8ei\x1a\x7f,7\x10-}-\xb9w\xc0M\x02\xf7CJ\x15\xa3X*\x7f\xf6'
```

The first four bytes could be an integer, maybe a length value?
```python
>>> import struct
>>> struct.unpack_from('<I', data)
(112794,)
>>> len(data)
225596
```

It's definately possible, so let's try decrypting past that.


```python
>>> rc4 = ARC4.new(f)
>>> rc4.decrypt(data[4:])[:500]
'PK\x03\x04\x14\x00\x00\x00\x08\x00\xad\x85\x0fMGt\xb5\x9c"\xb8\x01\x00\xf4\r\x04\x00\x0b\x00\x00\x00classes.dex\x9c\x9d\t`\x14E\xd6\xc7k8\x12\xc0\xfb\xbe\xb5\xbd\x05C\x10\xbcA]\x03\x04\x08\x84\x10I\xb8\x8d\xd8\x99\xe9\xcc4\x99\x8b9r\xe9\xee\x12\x0eA\x01O\x90S\x0e\xe5F \xdc\xe1^7\xb8\xde\x18D\x04V]\'\xa2x\x1f\xab\xebz\xa0\xeb\xf7\x7fU\xafgz\xc2\x04\xe2\'\xfe\xf2\xaa\xeb\xea\xea\xea\xaaz\xaf\xaa{\xba\\FE\xbb\x1bn\xbcYl|\xdd\x7f\xd1\x94\xd1\xff\xaa-\xdfz\xe3\xd2N\x97\xf4\xd8vQ\x9b\x17\xa7\x1f\xcd\xee\xf5\xb7\xff\x9c\xd2J\x04\x85\x10\x15\x83o:S\xf0\x7f7\xc0\xaf\xa2\xad\x90\xfe\x1e\x87\x10\xf9\xd7\x08\xb1\x1e\xf2\xdb\xeb\x85\xf8\xb9\x85\x10\x85w\x0b\xf1`k!.\x1e*\xc4x\xc4\xf9u\x1c\xd2W\xb6\x14\x0fN\x13\x92\xbf\x80j0\x01L\x02S\xc140\x13\xcc\x05\x0b\xc1\x12\xb0\n\xac\x07\xb5`\x07x\x05\x1c\x02_\x81\x1f\xc1\xaf\xe0\xc2\xe9B\\\x06n\x06\xdd@\x16\xe8\t\x06\x82A`\x04\x18\x05"`\x1cx\x02L\x033\xc0\x1c\xf0,X\nV\x81\x8d`\x17x\x15\xbc\x01\xde\x06\xdf\x83\x1f\xc1/\xe0\x7f\xa0\xf5\xd3B\x9c\t.\x01\xd7\x82\xdbA\x0e\x18\x00\x06\x83a\xe0^p?p\x027(\x05\x0f\x82\xa9\xe0\x19\xb0\x00\xac\x06\x1b\xc0V\xf07\xf0\nx\x13\xbc\x05\x0e\x80\xc3\xe0;\xf0?\xd0n\x06\xce\x07\xae\x06\xd7\x83\x1bA\x0e\x18\t*\xc04\xf0<x\x05\xc4\xc0\x0f\xe0\xe4\x99B\\\x01\xfe\x04\x86\x00?x\x18,\x00\x1b\xc0K\xe0}\xf0\x11\xf8\x01\xa4\xcf\x12\xe2\\p-\xb8\x01t\x05w\x82\xee\xa07\xe8\x0b\xf2\x80\x1f\x94\x83\x07\xc0_\xc1x\xf00\x98\n\x9e\x04s\xc1B\xb0\x18\xac\x00\x1b\xc0\x16\xb0\x03\xfc\x1d\xbc\x0e\xf6\x82\xfd\xe0\x10\xf8\x17h\x00\x1f\x83\xcf\xc0w\xe0\x07\xf03\xf8\r8f\xa3\xceA\x1bp28\x1d'
```

There we go, a zip file header and the name of the zipped file is classes.dex!

A quick look at the decoded dex file shows lots of interesting data including our twitter string from earlier.

![Anubis config data]({{ site.url }}/assets/anubis_unpack/unpacked/1_config_data.png "Anubis config data")

Looking around at some of the other code shows a few interesting routines.

RC4:

![Anubis RC4]({{ site.url }}/assets/anubis_unpack/unpacked/2_rc4.png "Anubis RC4")

Hexlify:

![Anubis Hexlify]({{ site.url }}/assets/anubis_unpack/unpacked/3_hexlify.png "Anubis Hexlify")

So going off prior research into Anubis we know that the twitter data is then base64 decode to a hexlified string, so let's find where that twitter string gets used.

![Anubis twitter string]({{ site.url }}/assets/anubis_unpack/unpacked/4_twitter_string_used.png "Anubis twitter string")

Here we can see the twitter string being used along with it referencing the <zero> tags for pulling out the data, following one of the later function calls if we're assuming it's first going to base64 decode and unhexlify leads us to the following function.

![Anubis Decode data]({{ site.url }}/assets/anubis_unpack/unpacked/5_rc4_key.png "Anubis Decode data")

So could this be the RC4 key then? Let's test with the hexlified string from the phishlabs report.

```python
>>> m = "3090c08a8f3c3950d98c612399622d02057bce22a5b8b01e4dc3960fa03648c822f3"
>>> a = binascii.unhexlify(m)
>>> a
'0\x90\xc0\x8a\x8f<9P\xd9\x8ca#\x99b-\x02\x05{\xce"\xa5\xb8\xb0\x1eM\xc3\x96\x0f\xa06H\xc8"\xf3'
>>> l = ARC4.new('flash1')
>>> w = l.decrypt(a)
>>> w
'hxxps://lukasstefankotiywlepok.com'
```

It works! That's it, hope it helps! For further reading I've included a number of references to android unpacking articles.


References:
1. https://info.phishlabs.com/blog/bankbot-anubis-threat-upgrade
2. https://www.virustotal.com/#/intelligence-overview
3. https://www.fortinet.com/blog/threat-research/unmasking-android-malware-a-deep-dive-into-a-new-rootnik-variant-part-i.html
4. https://link.springer.com/article/10.1186/s13638-016-0720-3
5. https://link.springer.com/article/10.1186/s13638-016-0720-3


[1]:https://info.phishlabs.com/blog/bankbot-anubis-threat-upgrade
[2]:https://www.virustotal.com/#/intelligence-overview
