---
title: "Ide Tryhackme Writeup"
date: 2021-10-22T21:19:37+05:30
draft: false
---

![](/images/img-ide-tryhackme-writeup-0.png)

Hi all, today we will take on the [IDE](https://tryhackme.com/room/ide) room in TryHackMe. It is rated Easy and the room description says: “An easy box to polish your enumeration skills!”

# Enumeration
## Nmap

So, in the nmap scan, we get four services:

![](/images/img-ide-tryhackme-writeup-1.png)
Nmap Output

# FTP server:

Anonymous login is allowed according to the nmap scan. Login with the following creds: **anonymous** : **anonymous**.

After logging in, we have to traverse to the `...` directory and then download the file named `-`. To download that file, simply use `get ./-` command.

I have renamed it to ftp-file after downloading for convenience. Contents of ftp-file:

![](/images/img-ide-tryhackme-writeup-2.png)

It hints us about two things:

1.  There are atleast two different users named `drac` and `john`.
2.  The password of the user `john` is a default password (which will be easy to crack because of it)

# The Web Server

-   Port 80: It has the default Apache webpage. After directory busting, there we couldn’t find anything useful.
-   Port 62337: We get a login page of Codiad (version: 2.8.4). Codiad is a web-based IDE and code editor.

![](/images/img-ide-tryhackme-writeup-3.png)

From above, we know that the user `john` has default password. I tried some passwords and was able to login with the creds: **john** : **password**.

While exploring the website, I created a project with the absolute path `/var/www/html/codiad/xplo1t`

# Searching for exploits:

I used searchsploit to search for any known exploits in Codiad.

![](/images/img-ide-tryhackme-writeup-4.png)

For me, the last exploit worked after some tweaking.

![](/images/img-ide-tryhackme-writeup-5.png)
Had to change these on the exploit

Run the exploit.

![](/images/img-ide-tryhackme-writeup-6.png)

Set the path for Codiad as `/` and the name of the actual project as `xplo1t` (we have already created a project of this name earlier. Remember?) This will upload a webshell `shell.php` in `/xplo1t/shell.php`

![](/images/img-ide-tryhackme-writeup-7.png)

We get a pretty webshell

We now have a shell as `www-data` To get a proper shell, I used one of the reverse shells from [revshells.com](https://www.revshells.com/).  
In the `.bash_history` file of the user `drac` , I found the password.

![](/images/img-ide-tryhackme-writeup-8.png)

Switch to drac with this password (Password reuse). User `drac` can run as sudo the following:

![](/images/img-ide-tryhackme-writeup-9.png)

User drac can restart the vsftpd service. To abuse this functionality, we can check for files related to the vsftpd service:

![](/images/img-ide-tryhackme-writeup-10.png)

The file `/lib/systemd/system/vsftpd.service` is writable by `drac`. Let's change the service file and make `/bin/bash` a SUID so that we can get root.

This is how we can do it:

![](/images/img-ide-tryhackme-writeup-11.png)

Pwned!

We now own the system. Hope it helped you if you got stuck in this room. If you have any problems in following this walkthrough or have any suggestions, let me know.

Connect with me on Twitter at [@manash036](https://twitter.com/manash036)

Adios 👋
