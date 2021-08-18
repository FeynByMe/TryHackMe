## Understading SMB
---
### What is SMB?
**SMB - Sever Message Block Protocol -** was created by IBM in the 1980's, and it is a layer 7 (application layer) protcol, using a [client-server architecture](https://en.wikipedia.org/wiki/Client%E2%80%93server_model) used primarily for sharing access to files, printers, serial ports and other resources which might be made available through a network. Over the years it has been mutated, extended and adapted to meet evolving network requirements - these variants are also often called ***dialects***.

The SMB protocol enables an application, or the user of an application, to access files on a remote server, printers and mails slots to name a few. This allows the client application to read, write, read, move, create and update files on the remote server. 

It uses a request-response protocol to establish a connection. This means it exchanges request and response messages back and forth, before it can completely conneect the client with the server. This made the original implementations of SMB, like CIFS (Common Internet File System), particularly *chatty*, which led a lot of networks, particularly Wide Area ones, to be slowed down by a swarm of SMB messages flying back and forth between SMB client and server nodes. As such, by 2006, SMB 2.0 was released with Windows Vista and Windows Server 2008 - which reduced chattiness, improved perfomrmance, enhanced security and resiliency and added support for Wide Area Networks 

*As a curiosity: You might have heard about the WannaCry and Petya ransomware attacks that plagued hundreds of thousands of computers back in 2017, but did you know that it was precisely a vulnerability in SMB 1.0 that hackers exploited to load the malware on vulnerable clients, effectively giving it a self-replicating platform across network hosts. As a result Microsoft has advised all users and administrators to disable SMB 1.0/CIFS on all of their systems, despite the fact that they have since patched the vulnerability.* 

--- 
### Enumerating SMB

If you're not sure what enumeration is, in the context of cyber security, make sure you first read the following quick explanation:

The reason we chose to introduce and talk about SMB has to do with fact that SMB share drives are a typical weak point when we begin enumerating targets. In practice, we have seen they are used by servers to view, cater and transfer files and share certain folders among users in a network. This means often you'll find sensitive information lying around in these shared drives. 

Our target in this task has the following IP address:

    MACHINE_IP = 10.10.77.85;
    
Our goal is to enumerate it. To find interesting intelligence we could eventually use to initiate an attack. 

As is customary, we begin by doing a port scanning on the target, to try and figure what kinds of services, applications, structure and possibly operating systems are being used by our target machine. To do this we make use of [Nmap](https://nmap.org/). In particular, in the spirit of our learning path, we want to explore if any port is running an SMB application, as such we run the following command:

    diogo@kali ~ :$ nmap -sV 10.10.77.85
    
    # Nmap 7.91 scan initiated Tue Aug 17 19:34:59 2021 as: nmap -sV -oA /tmp/scan 10.10.77.85
    Nmap scan report for 10.10.77.85
    Host is up (0.059s latency).
    Not shown: 997 closed ports
    PORT    STATE SERVICE     VERSION
    22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    Service Info: Host: POLOSMB; OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Tue Aug 17 19:35:11 2021 -- 1 IP address (1 host up) scanned in 12.56 seconds
    

    
