CLANG ?= clang
CXX   ?= g++
LIBBPF_DIR ?= /usr/lib/bpf
CFLAGS = -O2 -g -Wall -m64 -I$(LIBBPF_DIR)/include -I./src

BUILD_DIR := build
SRC_DIR := src
BPF_OBJS   = $(BUILD_DIR)/net_trace.bpf.o
USER_OBJS  = $(BUILD_DIR)/net_trace
VMLINUX_H  = $(SRC_DIR)/vmlinux.h
SKEL_HDR   = $(SRC_DIR)/net_trace.skel.h

all: $(USER_OBJS)

# Asegurar que build/ exista
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generar vmlinux.h automáticamente
$(VMLINUX_H): | $(BUILD_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compilación BPF
$(BUILD_DIR)/net_trace.bpf.o: src/net_trace.bpf.c src/net_event.h $(VMLINUX_H) | $(SRC_DIR)
	$(CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c $< -o $@

# Skeleton
$(SKEL_HDR): $(BUILD_DIR)/net_trace.bpf.o | $(SRC_DIR)
	bpftool gen skeleton $< > $@

# User space
$(USER_OBJS): src/net_trace.cpp $(SKEL_HDR) | $(BUILD_DIR)
	$(CXX) $(CFLAGS) -o $@ $< -lbpf

clean:
	rm -rf $(BUILD_DIR)
	rm -f  src/*.skel.h src/vmlinux.h

run :
	sudo ./build/net_trace mode=events

runBW :
	sudo ./build/net_trace mode=bandwidth