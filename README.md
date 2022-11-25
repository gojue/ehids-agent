![](./images/ehids-logo-1.png)

English | [中文介绍](./README_CN.md)

# Introduction to eHIDS

HIDS `demo` implemented by eBPF kernel technology.

> **Warning**
> Just a eBPF-based DEMO, please use [Tetragon](https://github.com/cilium/tetragon)
> /  [Tracee](https://github.com/aquasecurity/tracee) / [falco](https://github.com/falcosecurity/falco) instead.

Implementations & Functionalities：

1. TCP network data capture
2. UDP network data capture
3. DNS information capture in uprobe mode
4. Process data capture
5. Uprobe way to achieve JAVA RASP command execution scene event capture
6. Go framework implementation of eBPF, abstract implementation of multi-type events for the kprobe\uprobe mounting
   method.
7. Developers only need to implement three files:
    * The kernel-mode C file.
    * The user-mode go file.
    * The user-mode event message structure, and the framework will automatically load and execute.
8. Users can implement data reporting and processing according to the logger interface, such as reporting to ES\kafka and other log centers.


# Principle

Reference : [eBPF Official Website](https://ebpf.io)

![](https://ebpf.io/static/overview-bf463455a5666fc3fb841b9240d588ff.png)

1. In the kernel mode, eBPF code is written in C, and llvm is compiled into eBPF bytecode.
2. User mode is written in golang, cilium/ebpf pure go class library, kernel loading of eBPF bytecode, kprobe/uprobe HOOK corresponding function.
3. User mode uses golang for event reading, decoding, and processing.

# Planning
## Scheduling
The author is analyzing the runtime security protection products implemented by cloud-native eBPF technologies such as cilium, datadog, tracee, falco, and kubeArmor from the perspective of source code. 
After the analysis is completed, I will continue to share the design, ideas, and functions of this product.

Current progress & Changes

* 【DONE】2021-12-09 [Source code analysis of Cilium eBPF implementation mechanism](https://www.cnxct.com/how-does-cilium-use-ebpf-with-go-and-c/?f=g_ehids)
* 【DONE】2021-12-19 [Analysis of datadog's eBPF security detection mechanism](https://www.cnxct.com/how-does-datadog-use-ebpf-in-runtime-security/?f=g_ehids)
* 【DONE】2021-12-30 [Kernel state eBPF program to implement container escape and hide account rootkit](https://mp.weixin.qq.com/s?__biz=MzUyMDM0OTY5NA==&mid=2247483773&idx=1&sn=d9a6233f2ec94b63304209246b1b6a3b&chksm=f9eaf3ecce9d7afa8c539e47ddd0250874859bc4e81e6206a0d1b3fdaffd712bf81389ced579&token=1909106120&lang=zh_CN#rd)
* 【DING】2022-1-31 tracee Source code analysis of eBPF implementation mechanism
* ...

## Prodcut Features
1. Complete functions (network, process, file, event)
2. Monitoring
3. Alert
4. Fusing
5. Statistics
6. Reconciliation
7. Unified management and control

# Instructions

1. The kernel mode part is the ebpf programming code implemented by the linux native class library, and uses clang (llvm) for bytecode compilation.
2. The user mode part is written for golang's cilium/ebpf class library, which implements functions such as loading eBPF bytecodes to the kernel, mounting to hook points, and event reading.
3. This project uses kprobe and uprobe respectively to realize the network event capture of TCP and UDP.
  

# Development Environment

* UBUNTU 21.04 server
* go version go1.17.2 linux/amd64
* Ubuntu clang version 12.0.0-3ubuntu1~21.04.2
* openjdk version "1.8.0_292"

## Environment installation steps

See also : [CFC4N's eBPF development environment](https://www.cnxct.com/lessons-using-ebpf-accelerating-cloud-native-zh/?f=github#i-3)

* sudo apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev git
  pkg-config libmnl-dev bison flex graphviz
* sudo apt-get install -y make gcc clang llvm git pkg-config dpkg-dev gcc-multilib
* cd ~/download/
* sudo apt update
* sudo apt-get source linux-image-$(uname -r)
* sudo apt-get source linux-image-unsigned-$(uname -r)
* sudo apt install libbfd-dev libcap-dev zlib1g-dev libelf-dev libssl-dev

# Compiling and running

## Compilation

```shell
git clone https://github.com/ehids/ehids-agent.git
cd ehids
make
./bin/ehids-agent
```

## Runnig

Open another shell, execute network commands, and trigger network behavior
```shell
wget www.cnxct.com
```

Or compile and run the java command execution example to test the function of java RASP.
Uprobe mounts the JDK_execvpe function of libjava.so, and the corresponding offset address offset is 0x19C30. 
For other versions, please locate the offset address by yourself.
```shell
cd examples
javac Main.java
java Main
```
JAVA JDK version information
> ~$java -version
> 
> openjdk version "1.8.0_292" 
>
> OpenJDK Runtime Environment (build 1.8.0_292-8u292-b10-0ubuntu1-b10)
> 
> OpenJDK 64-Bit Server VM (build 25.292-b10, mixed mode)
## Results

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

# References

* https://ebpf.io
* https://github.com/trichimtrich/dns-tcp-ebpf
* https://github.com/p-/socket-connect-bpf

# Malicious exploitation and detection mechanism of eBPF

The article on malicious exploitation and detection mechanism based on eBPF has been shared on the WeChat public account of `Meituan Security Emergency Response Center`，[Malicious utilization and detection mechanism of eBPF](https://mp.weixin.qq.com/s/-1GiCncNTqtfO_grQT7cGw)

![](./images/ebpf-evil-use-detect-kernel-space.png)

# Wechat Group 

![](./images/wechat-group.jpg)

# Notes

It is not the official warehouse of Meituan, and is only contributed by engineers.

The repository does not contain the full HIDS version in use by **Meituan**, for the streamlined demo, if you need to see the full source code in detail, please click：[https://www.cnxct.com/jobs/](https://www.cnxct.com/jobs/?f=ehids-github)
