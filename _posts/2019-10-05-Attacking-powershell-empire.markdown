---
layout: post
title:  "Research into Attacking Powershell Empire"
date:   2019-10-05 10:31:12 -0600
categories: malware
---


Powershell empire is a post-exploitation framework that premiered at BsidesLV in 2015, developed by some all around great individuals whos work I would highly recommend following and reading. It's a framework that is used pretty frequently by pentesters, however like all good pentester tools the better it is the more likely it will end up being used by the bad guys. However I'm not here to debate any of that or even talk about detecting a framework versus detecting TTPs or any of that, today I'm going to go over my research into attacking the Empire C2s in various ways. Some of the work ended up showing some interesting avenues and some of the work didn't really amount to anything but hopefully you find it useful.

For attacking I'll be visiting a few scenarios:
1. Spamming new client registrations
2. Sending corrupted or large blocks of data

For the first attack we simply need the staging key and the profile data. For powershell empire you normally have a base64 encoded initial stager string which would be executed on a system.

Example:

![Base64 Powershell]({{ site.url }}/assets/empire_attack/pshell_empire_base64.png "Base64 Powershell")

After base64 decoding with are left with the decoded version of the initial stager which has the aforementioned information we require.

![Empire initial stager]({{ site.url }}/assets/empire_attack/empire_initial_stager.png "Empire initial stager")

This initial stager will actually end up downloading the agent code, the agent is then responsible for performing checkins to look for new taskings to execute.
To understand exactly what's going on here we can simply review the code from github, doing this allows us to figure out exactly how much information we need in order to register as an agent.

The stagingKey is actually the RC4 key from the initial stager, this initial stager also normally has a cookie which is the sessionID. For the initial stager the sessionID in the cookie is just 00000000 which has been RC4 encrypted, the other data also informs the server about the system such as whether or not it's running powershell or python version. 

After the initial layer checks in the server will send back the appropriate agent code that has been RC4 encrypted with a randomly generated IV attached that is added to the key from the initial stager. After getting to the agent code it will register itself with the server as a new ID instaed of 00000000.

So then in order to checkin to the server we need a few specific things:
* UserAgent
* RC4 key
* URI list

Luckily for us it appears all of these things needed are in the initial stager piece of the code so we can actually craft a script to generated and checkin to a C2 over and over again.

![Empire flooding]({{ site.url }}/assets/empire_attack/empire_spam_bots.png "Empire flooding")


Powershell Empires interface however has a cool option that lets you delete 'stale' bots, or basically bots that haven't checked in recently. So while we can flood the server with bots if we aren't actually continuing the checkin process for each bot then they will all go stale and easily be deleted. 

![Empire stale bots]({{ site.url }}/assets/empire_attack/empire_stale_bots.png "Empire stale bots")

So a few possible scenarios:
* We use a producer and consumer approach with threading to keep a certain number of bots active which would then require manual interaction from the operator or simply to delete all the bots and start over. The operator can simply block your IP and wait for your bots to stale however as a countermeasure.
* We can setup a distributed approach to have groups of bots exit from certain VPN or TOR IPs using the same approach above but making the process of blocking us more complicated. 

This means to perform actual flooding we need to use a producer and consumer approach via threading, then we can have a target number of bots we are pretending to be. This would force the person running the server to block our IP and then delete the stale 

For a quick demonstration of this we'll simply add in the stager checkin portion to stager code and have it do a checkin and a tasks request for every bot it creates.

![Empire agent checkin and tasks]({{ site.url }}/assets/empire_attack/empire_checkin_and_tasks.png "Empire agent checkin and tasks")


So spamming is definately a possibility as long as you prevent the bots from going stale too frequently. What about attacking Empires using abnormal data?

The first thing that comes to my mind is what about a very large computername?


![Empire very large computername]({{ site.url }}/assets/empire_attack/empire_very_large_computername.png "Empire very large computername")


Injecting null bytes causes strings to be cut short and if you send the wrong language Empire will happily record it but not let you interact with the bot anymore.

![Empire prevent bot interaction]({{ site.url }}/assets/empire_attack/empire_prevent_bot_interaction.png "Empire prevent bot interaction")


At this point I decided to look at the code on GitHub and noticed a few locations where you can cause some decoding errors. For example sending a crafted session key:


![Empire break decoding]({{ site.url }}/assets/empire_attack/empire_break_decoder.png "Empire break decoding")

This doesn't seem to cause anything but lots of error messages on the attackers screen however.

# Results

1. Setting up fake bots is possible, not only is it possible but incredibly interesting as you could potentially provide a 'juicy' target for an attacker and possibly get secondary or tertiary information about their motives.
2. Messing with Empire servers is also possible in regards to causing problems for the actor by bot flooding with messed up data could potentially throw a wrench in an actors plans.



References:  
 1. https://github.com/EmpireProject/Empire  

 
 
 


[1]:https://github.com/EmpireProject/Empire  




