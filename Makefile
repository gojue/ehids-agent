TARGETS := kern/sec_socket_connect
TARGETS += kern/tcp_set_state
TARGETS += kern/dns_lookup
TARGETS += kern/udp_lookup
TARGETS += kern/java_exec
TARGETS += kern/proc
TARGETS += kern/bpf_call

# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS:=_kern.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}

#
# environment
#

UNAME_M := $(shell uname -m)
UNAME_R := $(shell uname -r)

#
# Target Arch
#

ifeq ($(UNAME_M),x86_64)
   ARCH = x86_64
   LINUX_ARCH = x86
   GO_ARCH = amd64
endif


LLC ?= llc
CLANG ?= clang
EXTRA_CFLAGS ?= -O2 -mcpu=v1 -nostdinc -Wno-pointer-sign

BPFHEADER = -I./kern

all: $(KERN_OBJECTS) assets build
	@echo $(shell date)

.PHONY: clean assets

clean:
	rm -f user/bytecode/*.d
	rm -f user/bytecode/*.o
	rm -f assets/ebpf_probe.go
	rm -f bin/ehids

$(KERN_OBJECTS): %.o: %.c
	$(CLANG) $(EXTRA_CFLAGS) \
		$(BPFHEADER) \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-target bpfel -c $< -o $(subst kern/,user/bytecode/,$@) \
		-fno-ident -fdebug-compilation-dir . -g -D__BPF_TARGET_MISSING="GCC error \"The eBPF is using target specific macros, please provide -target\"" \
		-MD -MP

assets:
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" $(wildcard ./user/bytecode/*.o)

build:
	go build -o bin/ehids .