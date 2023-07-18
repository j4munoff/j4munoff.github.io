---
layout: single
title: Validation - Hack The Box
excerpt: "En este writeup vamos a resolver la máquina **Validation** de la plataforma **HackTheBox**. En una máquina Linux y su nivel de dificultad es fácil. En esta máquina escribiremos una WebShell que inyectaremos utilizando una vulnerabilidad SQL injection. Con esta Shell, accederemos a la máquina objetivo para encontrar la primera flag. Para acceder a root, utilizaremos una password encontrada en la enumeración de la maquina."
date: 2023-07-18
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


## Explotación

