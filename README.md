# eHIDS 介绍
以eBPF实现的HIDS demo.

1. TCP网络数据捕获
2. UDP网络数据捕获
3. uprobe方式的DNS信息捕获
4. 进程数据捕获
5. uprobe方式实现JAVA的RASP命令执行场景事件捕获

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

参考了几个ebpf的项目，很多都是[bcc](https://github.com/iovisor/bcc)写的，我这里去掉[bcc](https://github.com/iovisor/bcc)写法，改为纯ebpf的内核态编码实现。用户态的加载、挂载、读取用go实现。

* https://github.com/trichimtrich/dns-tcp-ebpf
* https://github.com/p-/socket-connect-bpf
  
# 团队招聘

美团安全团队持续招人，尤其是HIDS项目，欢迎你的加入，详情见：[https://www.cnxct.com/jobs/](https://www.cnxct.com/jobs/)