---
title: Try Hack Me - Chocolate Factory
date: 2021-05-09 16:42 +0300
categories: [Try Hack Me]
tags: [linux, stego, vi]     # TAG names should always be lowercase
---

# Welcome

Hey there! Glad to see you. It was funny box for me because i did everything in another order ;-)

# Nmap

Start scanning!

<pre class="highlighter-rouge highlight">
nmap -sC -sV -O 10.10.198.143

Nmap scan report for 10.10.198.143
Host is up (0.10s latency).
Not shown: 989 closed ports
PORT    STATE SERVICE    VERSION
21/tcp  open  ftp        vsftpd 3.0.3
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.43.228
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| ssh-hostkey: 
|   2048 16:31:bb:b5:1f:cc:cc:12:14:8f:f0:d8:33:b0:08:9b (RSA)
|   256 e7:1f:c9:db:3e:aa:44:b6:72:10:3c:ee:db:1d:33:90 (ECDSA)
|_  256 b4:45:02:b6:24:8e:a9:06:5f:6c:79:44:8a:06:55:5e (ED25519)
80/tcp  open  http       Apache httpd 2.4.29 ((Ubuntu))
|_auth-owners: ERROR: Script execution failed (use -d to debug)
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
100/tcp open  newacct?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GetRequest, SMBProgNeg: 
|     "Welcome to chocolate room!! 
	...
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
106/tcp open  pop3pw?
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     "Welcome to chocolate room!! 
	...
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
109/tcp open  pop2?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     "Welcome to chocolate room!! 
	...
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
110/tcp open  pop3?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GetRequest, X11Probe: 
|     "Welcome to chocolate room!! 
	...
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
111/tcp open  rpcbind?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, X11Probe: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
	...
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
113/tcp open  ident?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   FourOhFourRequest, GenericLines, NULL, RPCCheck: 
|_    http://localhost/key_rev_key <- You will find the key here!!!
119/tcp open  nntp?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
	...
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
125/tcp open  locus-map?
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
	...
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
8 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
	...
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
</pre>

The nmap output was so huge! There are lots of ports. But also pay attention with description near nmap result <code class="language-plaintext highlighter-rouge">small hint from Mr.Wonka<code>. 

At first I checked ftp connection and found jpg image, but the result of web page enumeration was more interesting for me so i forgot about it. I will add what i could get from ftp on the end of write up.

Now go to web page.

# Gobuster

We can see the login page

<img src="/assets/img/chocolatefactory_img/login_page.jpg">

<pre>
gobuster dir -w /opt/directory-list-2.3-medium.txt -u http://10.10.198.143/ -x php,js,txt,sh

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.198.143/
[+] Threads:        10
[+] Wordlist:       /opt/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,js,txt,sh
[+] Timeout:        10s
===============================================================
/home.php (Status: 200)
/validate.php (Status: 200)
</pre>

I found some php files <code class="language-plaintext highlighter-rouge">/home.php</code> and <code class="language-plaintext highlighter-rouge">/validate.php</code>

# Web Page

Let's open it <code class="language-plaintext highlighter-rouge">/home.php</code>, we will see

<img src="/assets/img/chocolatefactory_img/home_page.jpg">

If you will type some commands like **ls -la**, **cat /etc/passwd** it will work. It's time for shell. 

You can get reverse from <a href="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet">Pentest Monkey Reverse Shell</a>. Try every shell until it'll work. For me bash and python shells refused to work.


# Reverse Shell

Let's check what we have
<pre>
www-data@chocolate-factory:/var/www/html$ ls -la
ls -la
total 1152
drwxr-xr-x 2 root    root       4096 Oct  6  2020 .
drwxr-xr-x 3 root    root       4096 Sep 29  2020 ..
-rw------- 1 root    root      12288 Oct  1  2020 .swp
-rw-rw-r-- 1 charlie charley   65719 Sep 30  2020 home.jpg
-rw-rw-r-- 1 charlie charley     695 Sep 30  2020 home.php
-rw-rw-r-- 1 charlie charley 1060347 Sep 30  2020 image.png
-rw-rw-r-- 1 charlie charley    1466 Oct  1  2020 index.html
-rw-rw-r-- 1 charlie charley     273 Sep 29  2020 index.php.bak
-rw-r--r-- 1 charlie charley    8496 Sep 30  2020 key_rev_key
-rw-rw-r-- 1 charlie charley     303 Sep 30  2020 validate.php
</pre>

What we have inside <code class="language-plaintext highlighter-rouge">validate.php</code>.

<pre>
www-data@chocolate-factory:/var/www/html$ cat validate.php
...
... $uname=="charlie" && $password=="*******")
</pre>
There login and password for login page. But if we'll read the code, after login we will be on **/home.php**. So it just for answer the question.

You also can find the key as the scan from nmap said <code class="language-plaintext highlighter-rouge">http://localhost/key_rev_key <- You will find the key here!!!</code>.

<pre>
www-data@chocolate-factory:/var/www/html$ strings key__rev_key
strings key__rev_key
...
Enter your name: 
***********
 congratulations you have found the key:   
b'***********************************'
 Keep its safe
Bad name!
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
...
</pre>

After that you can go to <code class="language-plaintext highlighter-rouge">/home/charlie</code> and will find SSh key. Tell the truth I've known about it after **linpeash** enum.

<pre>
[+] Searching ssl/ssh files
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes
Possible private SSH keys were found!
/home/charlie/teleport
  --> Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem

 --> /etc/hosts.allow file found, read the rules:
/etc/hosts.allow
</pre>

# Connect to SSH
Copy the ssh key and connect.

Change permission 
<pre> chmod 600 id_rsa </pre>
Connect 
<pre>ssh -i id_rsa charlie@10.10.198.143</pre>

Now you can read User.txt

<pre>
cat user.txt

flag{cd*********************}
</pre>

# Privilage Escalation
Let's see waht user **charlie** can do
<pre>
sudo -l
Matching Defaults entries for charlie on chocolate-factory:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User charlie may run the following commands on chocolate-factory:
    (ALL : !root) NOPASSWD: /usr/bin/vi
</pre>

Go to <a href="https://gtfobins.github.io/gtfobins/vi/">GTFOBins</a> and become root.
On the **root** directory you will see the python file <code class="language-plaintext highlighter-rouge">root.py</code>.

<pre>
from cryptography.fernet import Fernet
import pyfiglet
key=input("Enter the key:  ")
f=Fernet(key)
encrypted_mess= 'gAAAAABfdb52eejIlEaE9ttPY8ckMMfHTIw5lamAWMy8yEdGPhnm9_H_yQikhR-bPy09-NVQn8lF_PDXyTo-T7CpmrFfoVRWzlm0OffAsUM7KIO_xbIQkQojwf_unpPAAKyJQDHNvQaJ'
dcrypt_mess=f.decrypt(encrypted_mess)
mess=dcrypt_mess.decode()
display1=pyfiglet.figlet_format("You Are Now The Owner Of ")
display2=pyfiglet.figlet_format("Chocolate Factory ")
print(display1)
print(display2)
print(mess)
</pre>

Use the key, which you found before and you will get the flag.

<pre>
python root.py
Enter the key:  b'*************************************'
b'*************************************'
__   __               _               _   _                 _____ _          
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                                                             
  ___                              ___   __  
 / _ \__      ___ __   ___ _ __   / _ \ / _| 
| | | \ \ /\ / / '_ \ / _ \ '__| | | | | |_  
| |_| |\ V  V /| | | |  __/ |    | |_| |  _| 
 \___/  \_/\_/ |_| |_|\___|_|     \___/|_|   
                                             

  ____ _                     _       _       
 / ___| |__   ___   ___ ___ | | __ _| |_ ___ 
| |   | '_ \ / _ \ / __/ _ \| |/ _` | __/ _ \
| |___| | | | (_) | (_| (_) | | (_| | ||  __/
 \____|_| |_|\___/ \___\___/|_|\__,_|\__\___|
                                             
 _____          _                    
|  ___|_ _  ___| |_ ___  _ __ _   _  
| |_ / _` |/ __| __/ _ \| '__| | | | 
|  _| (_| | (__| || (_) | |  | |_| | 
|_|  \__,_|\___|\__\___/|_|   \__, | 
                              |___/  

flag{ce****************************}
</pre>

# Extra
I could try to pay attention to **ftp** enumeration. On ftp we could connect by anonymous creds and find image.

<pre>
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
226 Directory send OK.
</pre>

# Steghide
The image has some secret
<pre>
steghide info gum_room.jpg 
"gum_room.jpg":
  format: jpeg
  capacity: 10.9 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "b64.txt":
    size: 2.5 KB
    encrypted: rijndael-128, cbc
    compressed: yes
</pre>

Let's extract this file
<pre>
steghide extract -sf gum_room.jpg 
Enter passphrase: 
wrote extracted data to "b64.txt".
</pre>

And decode it
<pre>
cat b64.txt | base64 -d
daemon:*:18380:0:99999:7:::
bin:*:18380:0:99999:7:::
sys:*:18380:0:99999:7:::
sync:*:18380:0:99999:7:::
games:*:18380:0:99999:7:::
man:*:18380:0:99999:7:::
lp:*:18380:0:99999:7:::
mail:*:18380:0:99999:7:::
news:*:18380:0:99999:7:::
uucp:*:18380:0:99999:7:::
proxy:*:18380:0:99999:7:::
www-data:*:18380:0:99999:7:::
backup:*:18380:0:99999:7:::
list:*:18380:0:99999:7:::
irc:*:18380:0:99999:7:::
gnats:*:18380:0:99999:7:::
nobody:*:18380:0:99999:7:::
systemd-timesync:*:18380:0:99999:7:::
systemd-network:*:18380:0:99999:7:::
systemd-resolve:*:18380:0:99999:7:::
_apt:*:18380:0:99999:7:::
mysql:!:18382:0:99999:7:::
tss:*:18382:0:99999:7:::
shellinabox:*:18382:0:99999:7:::
strongswan:*:18382:0:99999:7:::
ntp:*:18382:0:99999:7:::
messagebus:*:18382:0:99999:7:::
arpwatch:!:18382:0:99999:7:::
Debian-exim:!:18382:0:99999:7:::
uuidd:*:18382:0:99999:7:::
debian-tor:*:18382:0:99999:7:::
redsocks:!:18382:0:99999:7:::
freerad:*:18382:0:99999:7:::
iodine:*:18382:0:99999:7:::
tcpdump:*:18382:0:99999:7:::
miredo:*:18382:0:99999:7:::
dnsmasq:*:18382:0:99999:7:::
redis:*:18382:0:99999:7:::
usbmux:*:18382:0:99999:7:::
rtkit:*:18382:0:99999:7:::
sshd:*:18382:0:99999:7:::
postgres:*:18382:0:99999:7:::
avahi:*:18382:0:99999:7:::
stunnel4:!:18382:0:99999:7:::
sslh:!:18382:0:99999:7:::
nm-openvpn:*:18382:0:99999:7:::
nm-openconnect:*:18382:0:99999:7:::
pulse:*:18382:0:99999:7:::
saned:*:18382:0:99999:7:::
inetsim:*:18382:0:99999:7:::
colord:*:18382:0:99999:7:::
i2psvc:*:18382:0:99999:7:::
dradis:*:18382:0:99999:7:::
beef-xss:*:18382:0:99999:7:::
geoclue:*:18382:0:99999:7:::
lightdm:*:18382:0:99999:7:::
king-phisher:*:18382:0:99999:7:::
systemd-coredump:!!:18396::::::
_rpc:*:18451:0:99999:7:::
statd:*:18451:0:99999:7:::
_gvm:*:18496:0:99999:7:::
charlie:$6$******************************************************************jPYeeGyIJWE82X/:18535:0:99999:7:::
</pre>

You can brute the hash with **John** or **Hashcat** and after that connect to SSH as user Charlie.


# Userful for me references
<div><a href="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet">Reverse Shells</a></div>
<div><a href="https://gtfobins.github.io/gtfobins/vi/">GTFOBins vi</a></div>

