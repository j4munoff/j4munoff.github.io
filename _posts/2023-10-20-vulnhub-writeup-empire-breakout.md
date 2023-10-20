---
layout: single
title: Empire: BreakOut - VulnHub
excerpt: "En este writeup vamos a resolver la máquina **Empire: BreakOut** de la plataforma **VulnHub**. En una máquina Linux y su nivel de dificultad es fácil. En esta máquina encontraremos un usuario y una password en la enumeración que permitirá acceder a una aplicación Webmin. Posteriormente leeremos un fichero de password de root a traves de una vulnerabilidad del ejecutable **tar**."
date: 2023-07-18
classes: wide
header:
  teaser: /assets/images/vulnhub-empire-breakout/breakout.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.png
categories:
  - vulnhub
tags:
  - webmin
---

![](/assets/images/vulnhub.png)
![](/assets/images/vulnhub-empire-breakout/breakout.png)

## Introducción

En este writeup vamos a resolver la máquina **Empire: BreakOut** de la plataforma **VulnHub**. En una máquina Linux y su nivel de dificultad es fácil. En esta máquina encontraremos un usuario y una password en la enumeración que permitirá acceder a una aplicación Webmin. Posteriormente leeremos un fichero de password de root a traves de una vulnerabilidad del ejecutable **tar**.

## Enumeración

Realizamos un **ping** a la máquina para intuir el tipo de sistema operativo:

```console
┌──(kali㉿kali)-[~/VulnHub/01-EmpireBreakOut]
└─$ ping -c 1 192.168.168.158
PING 192.168.168.158 (192.168.168.158) 56(84) bytes of data.
64 bytes from 192.168.168.158: icmp_seq=1 ttl=64 time=1.18 ms

--- 192.168.168.158 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.182/1.182/1.182/0.000 ms
```

Nos devuelve un *ttl* de 64 por lo que podemos deducir que estamos ante un sistema **Linux**.

Realizamos un escaneo rápido para obtener puertos abiertos:

```console
┌──(kali㉿kali)-[~/VulnHub/01-EmpireBreakOut]
└─$ sudo nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 192.168.168.158 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-20 09:54 CEST
Initiating ARP Ping Scan at 09:54
Scanning 192.168.168.158 [1 port]
Completed ARP Ping Scan at 09:54, 0.08s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 09:54
Scanning 192.168.168.158 [65535 ports]
Discovered open port 139/tcp on 192.168.168.158
Discovered open port 80/tcp on 192.168.168.158
Discovered open port 445/tcp on 192.168.168.158
Discovered open port 10000/tcp on 192.168.168.158
Discovered open port 20000/tcp on 192.168.168.158
Completed SYN Stealth Scan at 09:54, 1.98s elapsed (65535 total ports)
Nmap scan report for 192.168.168.158
Host is up, received arp-response (0.00013s latency).
Scanned at 2023-10-20 09:54:30 CEST for 2s
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE          REASON
80/tcp    open  http             syn-ack ttl 64
139/tcp   open  netbios-ssn      syn-ack ttl 64
445/tcp   open  microsoft-ds     syn-ack ttl 64
10000/tcp open  snet-sensor-mgmt syn-ack ttl 64
20000/tcp open  dnp              syn-ack ttl 64
MAC Address: 00:0C:29:E4:DF:F1 (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.25 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)

```

Ahora realizamos un escaneo mas exhaustivo sobre los puertos abiertos.

```console
┌──(kali㉿kali)-[~/VulnHub/01-EmpireBreakOut]
└─$ nmap -sCV -p80,139,445,10000,20000 192.168.168.158 -oN targeted
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-20 09:55 CEST
Nmap scan report for 192.168.168.158
Host is up (0.00052s latency).

PORT      STATE SERVICE     VERSION
80/tcp    open  http        Apache httpd 2.4.51 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.51 (Debian)
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
10000/tcp open  http        MiniServ 1.981 (Webmin httpd)
|_http-server-header: MiniServ/1.981
|_http-title: 200 &mdash; Document follows
20000/tcp open  http        MiniServ 1.830 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
|_http-server-header: MiniServ/1.830

Host script results:
|_nbstat: NetBIOS name: BREAKOUT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-10-20T07:55:27
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.92 seconds

```

Al estar el puerto **SMB** abierto, (445), podemos enumerar con **enum4linux** para descubrir recursos compartidos y usuarios:

![](/assets/images/vulnhub-empire-breakout/image.png)

Nos encuentra el usuario **cyber**.

Revisamos a continuación la web del puerto 80.

![](/assets/images/vulnhub-empire-breakout/image-1.png)

A priori parece la página por defecto de Apache. Revisamos el código fuente y vemos que tiene una barra de desplazamiento muy larga. Nos desplazamos al final:

![](/assets/images/vulnhub-empire-breakout/image-2.png)

Vemos un texto cifrado en **Brainfuck**. Desciframos el código:

![](/assets/images/vulnhub-empire-breakout/image-3.png)

Encontramos una posible password.

## Explotación

Ahora exploramos las aplicaciones Web de los puertos 10000 y 20000. Ambas nos  muestran la pantalla de autenticación de un Webmin. 

![](/assets/images/vulnhub-empire-breakout/image-4.png)

Probamos a validarnos con el usuario cyber y la password encontrada. En la aplicación del puerto 20000 nos permite la entrada.

![](/assets/images/vulnhub-empire-breakout/image-5.png)

Webmin tiene una utilidad de linea de comandos. Podemos utilizarla para enviarnos una reverse shell:

![](/assets/images/vulnhub-empire-breakout/image-6.png)

Y obtenemos acceso:

![](/assets/images/vulnhub-empire-breakout/image-7.png)

Y podemos leer la flag de usuario:

![](/assets/images/vulnhub-empire-breakout/image-8.png)

## Escalada

Realizamos un tratamiento de la tty y buscamos vías potenciales de escalar privilegios.

```console
cyber@breakout:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
cyber@breakout:~$ ^Z
zsh: suspended  sudo TERMINFO="/opt/kitty/lib/kitty/terminfo" nc -nlvp 443
                                                                                                                                                                                         
┌──(kali㉿kali)-[~/VulnHub/01-EmpireBreakOut]
└─$ stty raw -echo; fg
[1]  + continued  sudo TERMINFO="/opt/kitty/lib/kitty/terminfo" nc -nlvp 443
                                                                            reset xterm
```

```console
cyber@breakout:~$ export TERM=xterm
cyber@breakout:~$ export SHELL=bash
cyber@breakout:~$ stty rows 49 columns 185
cyber@breakout:~$ 
```

Realizamos las típicas tareas de búsqueda de vectores de escalada. No vemos nada reseñable. Si que vemos un ejecutable "tar" en el directorio del usuario **cyber** con permisos de root que nos resulta estraño:

![](/assets/images/vulnhub-empire-breakout/image-9.png)

Buscamos ficheros sensibles con patrones como **pass**, **backup**, etc.

Con el comando **find / -name "*pass*" 2>/dev/null** encontramos un archivo interesante:

![](/assets/images/vulnhub-empire-breakout/image-10.png)

Recordemos que dentro del home del usuario hay una utilidad **tar**. Es posible utilizar esta utilidad para leer ficheros protegidos:

![](/assets/images/vulnhub-empire-breakout/image-11.png)

Podemos utilizar esta vulnerabilidad para leer el fichero encontrado:

![](/assets/images/vulnhub-empire-breakout/image-12.png)

Utilizamos esta contraseña para cambiar al usuario root:

![](/assets/images/vulnhub-empire-breakout/image-13.png)

Y podemos leer su flag:

![](/assets/images/vulnhub-empire-breakout/image-14.png)


