CLANG ?= clang
CXX   ?= g++
LIBBPF_DIR ?= /usr/lib/bpf
CFLAGS = -O2 -g -Wall -m64 -I$(LIBBPF_DIR)/include -I./src

BPF_OBJS = src/net_trace.bpf.o
USER_OBJS = src/net_trace

all: $(USER_OBJS)

# Generar vmlinux.h automáticamente
src/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compilación BPF
src/net_trace.bpf.o: src/net_trace.bpf.c src/net_event.h src/vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c $< -o $@

# Skeleton
src/net_trace.skel.h: src/net_trace.bpf.o
	bpftool gen skeleton $< > $@

# User space
src/net_trace: src/net_trace.cpp src/net_trace.skel.h
	$(CXX) $(CFLAGS) -o $@ $< -lbpf

clean:
	rm -f src/*.o src/*.skel.h src/net_trace src/vmlinux.h
