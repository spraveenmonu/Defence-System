/*
 * KLCDS — eBPF Probe Makefile
 *
 * Build the eBPF probes (Phase 2):
 *   make            — Compile probes
 *   make skeleton   — Generate libbpf skeleton header
 *   make clean      — Remove build artifacts
 *
 * Requirements:
 *   - clang >= 14
 *   - llvm
 *   - libbpf-dev
 *   - linux-headers-$(uname -r)
 *   - bpftool (for skeleton generation)
 */

CLANG      ?= clang
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/')
KERN_SRC   := /usr/src/linux-headers-$(shell uname -r)
LIBBPF_INC := /usr/include/bpf

CFLAGS := -O2 -g -Wall \
          -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -I$(LIBBPF_INC) \
          -I$(KERN_SRC)/include

SRC  := klcds_probes.c
OBJ  := klcds_probes.o
SKEL := klcds_probes.skel.h

.PHONY: all skeleton clean

all: $(OBJ)

$(OBJ): $(SRC) klcds_probes.h
	$(CLANG) $(CFLAGS) -c $< -o $@

skeleton: $(OBJ)
	$(BPFTOOL) gen skeleton $< > $(SKEL)
	@echo "Generated $(SKEL)"

clean:
	rm -f $(OBJ) $(SKEL)
