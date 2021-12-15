![](https://ebpf.io/static/logo-big-9cf8920e80cdc57e6ea60825ebe287ca.png)

# eHIDS 介绍
eBPF内核技术实现的HIDS demo. 

功能实现：
1. TCP网络数据捕获
2. UDP网络数据捕获
3. uprobe方式的DNS信息捕获
4. 进程数据捕获
5. uprobe方式实现JAVA的RASP命令执行场景事件捕获
6. eBPF的go框架实现，针对kprobe\uprobe挂载方式，多类型event进行抽象实现。
7. 开发者只需要实现内核态C文件，用户态go文件，用户态event消息结构体三个文件即可，框架会自动加载执行。
8. 使用者可以按照logger的interface自行实现数据的上报处理，比如上报到ES\kafka等日志中心。


# 原理

参考[ebpf](https://ebpf.io)官网的介绍
![](https://ebpf.io/static/overview-bf463455a5666fc3fb841b9240d588ff.png)

1. 内核态用C写eBPF代码，llvm编译为eBPF字节码。
2. 用户态使用golang编写，cilium/ebpf纯go类库，做eBPF字节码的内核加载，kprobe/uprobe HOOK对应函数。
3. 用户态使用golang做事件读取、解码、处理。

# 规划
## 排期规划
笔者在从源码角度分析cilium、datadog、tracee、falco、kubeArmor等云原生相关eBPF技术实现的运行时安全防护产品，在分析完成后，会继续规划本产品的设计方案、思路、功能等。

当前进展完成

* 【DONE】2021-12-09 [Cilium eBPF实现机制源码分析](https://www.cnxct.com/how-does-cilium-use-ebpf-with-go-and-c/?f=g_ehids)
* 【DING】2021-12-19 datadog-agent eBPF实现机制源码分析
* 【TODO】tracee eBPF实现机制源码分析
* ...

## 产品规划
1. 功能完善（网络、进程、文件、事件）
2. 监控
3. 告警
4. 熔断
5. 统计
6. 对账
7. 统一管控

# 说明

1. 内核态部分为linux原生类库实现的ebpf编程代码，使用clang(llvm)进行字节码编译。
2. 用户态部分为golang的cilium/ebpf类库编写，实现加载eBPF字节码到内核，挂载到hook点，事件读取等功能。
3. 本项目分别用kprobe、uprobe实现了TCP、UDP的网络事件捕获。
  

# 开发环境

* UBUNTU 21.04 server
* go version go1.17.2 linux/amd64
* Ubuntu clang version 12.0.0-3ubuntu1~21.04.2
* openjdk version "1.8.0_292"

## 环境安装步骤

参见[CFC4N的eBPF开发环境](https://www.cnxct.com/lessons-using-ebpf-accelerating-cloud-native-zh/?f=github#i-3)

* sudo apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev git
  pkg-config libmnl-dev bison flex graphviz
* sudo apt-get install -y make gcc clang llvm git pkg-config dpkg-dev gcc-multilib
* cd ~/download/
* sudo apt update
* sudo apt-get source linux-image-$(uname -r)
* sudo apt-get source linux-image-unsigned-$(uname -r)
* sudo apt install libbfd-dev libcap-dev zlib1g-dev libelf-dev libssl-dev

# 编译运行

## 编译

```shell
git clone https://github.com/cfc4n/ehids.git
cd ehids
make
./bin/ehids
```

## 运行

再开一个shell，执行网络命令，触发网络行为
```shell
wget www.cnxct.com
```

或者编译运行java的命令执行例子，来测试java RASP的功能。
uprobe挂载了libjava.so的 JDK_execvpe函数，对应偏移地址offset为0x19C30，其他版本请自行定位偏移地址。
```shell
cd examples
javac Main.java
java Main
```
JAVA JDK版本信息如下
> ~$java -version
> 
> openjdk version "1.8.0_292" 
>
> OpenJDK Runtime Environment (build 1.8.0_292-8u292-b10-0ubuntu1-b10)
> 
> OpenJDK 64-Bit Server VM (build 25.292-b10, mixed mode)
## 结果

```shell
root@vmubuntu:/home/cfc4n/project/ehids# ./bin/ehids
2021/12/01 19:27:08 start to run EBPFProbeUJavaRASP probe
2021/12/01 19:27:08 start to run EBPFProbeKTCP probe
2021/12/01 19:27:08 start to run EBPFProbeKTCPSec probe
2021/12/01 19:27:08 start to run EBPFProbeKUDP probe
2021/12/01 19:27:08 start to run EBPFProbeUDNS probe
2021/12/01 19:27:08 probeName:EBPFProbeKTCPSec, probeTpye:kprobe, start time:07:23:49, PID:864, UID:101, AF:2, TASK:5systemd-resolv
2021/12/01 19:27:08 probeName:EBPFProbeKUDP, probeTpye:kprobe, PID:0, comm:systemd-resolve, qname:57.22.91.101.in-addr.arpa, qclass:1, qtype:12.
2021/12/01 19:27:09 probeName:EBPFProbeKTCP, probeTpye:kprobe, start time:19:31:19, family:AF_INET, PID:409744, command:curl, UID:0, rx:67408, tx:79, dest:118.31.44.218:20480, source:172.16.71.4, type:OUT, result:True
2021/12/01 19:27:10 probeName:EBPFProbeUJavaRASP, probeTpye:uprobe, JAVA RASP exec and fork. PID:409049, command:ifconfig, mode:MODE_VFORK
```

# 参考

* https://ebpf.io
* https://github.com/trichimtrich/dns-tcp-ebpf
* https://github.com/p-/socket-connect-bpf
  
# 团队招聘
该仓库非美团在用HIDS版本，为精简后demo，若需要查看详细全部源码，请点击：[https://www.cnxct.com/jobs/](https://www.cnxct.com/jobs/?f=ehids-github)