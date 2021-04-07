# Hacking-With-CSharp

C#安全资源合集

## 内网渗透

- [SharpDump](https://github.com/GhostPack/SharpDump) - C#版本的Minidump
- [SharpKatz](https://github.com/b4rtik/SharpKatz) - C#版本的MiniKatz
- [sharpwmi](https://github.com/QAX-A-Team/sharpwmi) - RPC横向移动、命令执行、上传文件
- [SharpSQLTools](https://github.com/uknowsec/SharpSQLTools) - 内网Mssql利用工具，可上传下载文件，xp_cmdshell与sp_oacreate执行命令回显和clr加载程序集执行相应操作
- [RunDLL.Net](https://github.com/p3nt4/RunDLL.Net) - 使用RunDLL32.exe内存执行.net assemblies
- [Sharpmad](https://github.com/Kevin-Robertson/Sharpmad) - C# version of Powermad
- [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter) - payload生成和内存执行C#源码

## 内网信息收集

- [ADCollector](https://github.com/dev-2null/ADCollector) - 快速获取域内环境信息
- [SharpEventLog](https://github.com/uknowsec/SharpEventLog) - 读取登录过本机的登录失败或登录成功（4624，4625）的所有计算机信息，在内网渗透中快速定位运维管理人员
- [CSharp-Tools](https://github.com/RcoIl/CSharp-Tools) - 大黑阔写的CSharp工具合集,包括编码转换工具、获取 Navicat 的连接记录及保存的账号密码、Weblogic 的反序列化系列检测工具、获取机器基础信息（压缩包 AES 加密）其中包括高权限 dump lsass 内存、解密压缩包，解析 sqlite 数据库内容，以获取 Chrome 浏览器的浏览、下载记录、密码信息、IPC$ 连接获取远程主机账号列表	、批量解密 DES加密算法、用于判断当前机器类型（桌面计算机、笔记本等判断、枚举域内用户密码（指定单个密码-枚举（密码喷射），指定单个用户-爆破）、查看 Office 版本及宏状态、扫描 C段 的 Web 应用，获取 Title，可自定义多端口、NetSessionEnum 与 NetWkstaUserEnum的一个 demo，可自行扩展、获取 SPN	、SCShell 的 C# 版本、为域用户启用 可逆加密 的三种方法、使用 WMI远程执行命令，利用 SMB 读取结果、获取当前所有进程的 CommandLine、vssown.vbs 的 C# 版本（部分功能），当然，有瑕疵、解析 NTDS.dit 数据库	、OXID 解析器，用于探测多网口机器（依赖于 135 端口）、用于修改文件/文件夹的最后一次访问时间及修改时间、基于 mssql 数据库的文件上传、下载及命令执行
- [SharpAVKB](https://github.com/uknowsec/SharpAVKB) - Windows杀软对比和补丁号对比
- [SharpCheckInfo](https://github.com/uknowsec/SharpCheckInfo) - 收集目标主机信息，包括最近打开文件，系统环境变量和回收站文件等等
- [Net-GPPPassword](https://github.com/outflanknl/Net-GPPPassword) - .NET版本的GPPPassword信息提取工具
- [SharpSQLDump](https://github.com/uknowsec/SharpSQLDump) - 内网渗透中快速获取数据库所有库名，表名，列名。具体判断后再去翻数据，节省时间。适用于mysql，mssql。
- [SharpNetCheck](https://github.com/uknowsec/SharpNetCheck) - 内网中快速定位出网机器
- [SharpWeb](https://github.com/djhohnstein/SharpWeb) - 从谷歌,火狐,IE和Microsoft Edge提取登录过的网站信息，包括cookie和历史浏览记录
- [SharpClipboard](https://github.com/slyd0g/SharpClipboard) - 获取剪贴板内容的工具，也可用于cobalt strike中使用
- [ListRDPConnections](https://github.com/Heart-Sky/ListRDPConnections) - 读取本机对外RDP连接记录和其他主机对该主机的连接记录，从而在内网渗透中获取更多可通内网网段信息以及定位运维管理人员主机


## 密码解密

- [BrowserGhost](https://github.com/QAX-A-Team/BrowserGhost) - 抓取浏览器密码,解密chrome全版本密码, 支持IE
- [SharpDecryptPwd](https://github.com/uknowsec/SharpDecryptPwd) - 对密码已保存在 Windwos 系统上的部分程序进行解析,包括：Navicat,TeamViewer,FileZilla,WinSCP,Xmangager系列产品（Xshell,Xftp)

## 漏洞利用

- [Eternalblue](https://github.com/povlteksttv/Eternalblue) - 永恒之蓝利用

## 免杀&混淆&加壳

- [DefenderCheck](https://github.com/matterpreter/DefenderCheck) - 标记出Defender检测到的恶意特征，方便针对性免杀
- [MatryoshkaDollTool](https://github.com/TheKingOfDuck/MatryoshkaDollTool) - MatryoshkaDollTool-程序加壳/捆绑工具
- [NativePayload_CBT](https://github.com/DamonMohammadbagher/NativePayload_CBT) - 通过函数回调执行shellcode，避免使用CreateThread API

## 安全加固

- [pingcastle](https://github.com/vletoux/pingcastle) - 快速对AD活动目录进行安全配置

## 提权

- [SweetPotato](https://github.com/CCob/SweetPotato) - 土豆提权，支持从Windows 7 到 Windows 10/Server 2019
- [SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC) - bypass UAC

## 权限维持

- [Telemetry](https://github.com/Imanfeng/Telemetry) - 滥用Telemetry进行权限维持

## 进程相关

- [KsDumper](https://github.com/EquiFox/KsDumper) - 利用内核特性，dump进程内存
- [DInvoke_PoC](https://github.com/dtrizna/DInvoke_PoC) - 进程注入POC

## 远控&后门

- [AndroSpy](https://github.com/qH0sT/AndroSpy) - Android RAT工具

## 代码库

- [HttpCode.Core](https://github.com/stulzq/HttpCode.Core) - 简单、易用、高效 一个有态度的开源.Net Http请求框架!可以用制作爬虫，api请求等等
- [MinHook.NET](https://github.com/CCob/MinHook.NET) - C#版本的代码Hook库
- [dotnet_coreclr](https://github.com/steveharter/dotnet_coreclr) - C# CLR库


