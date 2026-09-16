# ── Makefile ──────────────────────────────────────────────────────────────
# PQC Benchmark Suite
#
# Targets:
#   make            - build both binaries
#   make bench_pqc  - build only the PQC benchmark
#   make bench_classical - build only the classical baseline
#   make run        - build and run both benchmarks sequentially
#   make clean      - remove binaries and CSV output
#
# Output filenames carry PLATFORM (default x86); set it on the ARM host:
#   make run PLATFORM=arm    - writes results_{pqc,classical}_arm.csv
#
# Prerequisites (Ubuntu 22.04):
#   sudo apt install build-essential cmake ninja-build libssl-dev
#   # Then build and install liboqs. The paper's numbers come from liboqs
#   # 0.16.0 at commit 5a1a854; a --depth 1 clone cannot check that commit
#   # out, so clone fully and pin it. The install prefix must match
#   # OQS_PREFIX below, which defaults to $(HOME)/liboqs-install:
#   git clone https://github.com/open-quantum-safe/liboqs.git
#   git -C liboqs checkout 5a1a854
#   cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX=$$HOME/liboqs-install \
#         -DOQS_DIST_BUILD=ON -GNinja
#   cmake --build liboqs/build --parallel
#   cmake --install liboqs/build
#   # To install system-wide instead, use -DCMAKE_INSTALL_PREFIX=/usr/local
#   # with `sudo cmake --install`, then build with: make OQS_PREFIX=/usr/local
# ──────────────────────────────────────────────────────────────────────────

CC      = gcc
OQS_PREFIX ?= $(HOME)/liboqs-install

# Platform tag used in output filenames. analyze.py expects the ARM results
# to be named results_{pqc,classical}_arm.csv, so run `make PLATFORM=arm`
# there rather than renaming afterwards.
PLATFORM ?= x86

PQC_CSV           = results_pqc_$(PLATFORM).csv
PQC_CSV_RAW       = results_pqc_$(PLATFORM)_raw.csv
CLASSICAL_CSV     = results_classical_$(PLATFORM).csv
CLASSICAL_CSV_RAW = results_classical_$(PLATFORM)_raw.csv
CFLAGS  = -O2 -Wall -Wextra -I$(OQS_PREFIX)/include
LDFLAGS = -L$(OQS_PREFIX)/lib

OQS_LIBS     = -l:liboqs.a $(shell pkg-config --libs openssl) -lm -lpthread
OPENSSL_LIBS = $(shell pkg-config --libs openssl) -lm

TARGETS = bench_pqc bench_classical
FAST_TARGETS = bench_pqc_fast bench_classical_fast

.PHONY: all run run_pqc run_classical clean install_deps fast

all: $(TARGETS)

# fast: N_ITERATIONS/WARMUP_ITERS overridden for perf-stat / concurrency sweeps
fast: $(FAST_TARGETS)

bench_pqc: bench_pqc.c benchmark.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(OQS_LIBS)
	@echo "Built: $@"

bench_classical: bench_classical.c benchmark.h
	$(CC) $(CFLAGS) -o $@ $< \
	    $(shell pkg-config --cflags openssl) $(LDFLAGS) $(OPENSSL_LIBS)
	@echo "Built: $@"

bench_pqc_fast: bench_pqc.c benchmark.h
	$(CC) $(CFLAGS) -DN_ITERATIONS=100 -DWARMUP_ITERS=5 -o $@ $< $(LDFLAGS) $(OQS_LIBS)
	@echo "Built: $@ (N_ITERATIONS=100)"

bench_classical_fast: bench_classical.c benchmark.h
	$(CC) $(CFLAGS) -DN_ITERATIONS=100 -DWARMUP_ITERS=5 -o $@ $< \
	    $(shell pkg-config --cflags openssl) $(LDFLAGS) $(OPENSSL_LIBS)
	@echo "Built: $@ (N_ITERATIONS=100)"

# ── run targets ──────────────────────────────────────────────────────────
run: all run_pqc run_classical
	@echo ""
	@echo "All benchmarks complete."
	@echo "Results: $(PQC_CSV)  $(CLASSICAL_CSV)"

run_pqc: bench_pqc
	@echo ""
	@echo "--- Running PQC benchmark ---"
	./bench_pqc $(PQC_CSV) $(PQC_CSV_RAW)

run_classical: bench_classical
	@echo ""
	@echo "--- Running classical baseline benchmark ---"
	./bench_classical $(CLASSICAL_CSV) $(CLASSICAL_CSV_RAW)

# ── cleanup ───────────────────────────────────────────────────────────────
clean:
	rm -f $(TARGETS) $(PQC_CSV) $(CLASSICAL_CSV)

# ── dependency installation hint ─────────────────────────────────────────
install_deps:
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y build-essential cmake ninja-build \
	    libssl-dev pkg-config git
	@echo ""
	@echo "Now build and install liboqs (full clone: --depth 1 cannot check"
	@echo "out the pinned commit 5a1a854 the paper's numbers come from):"
	@echo "  git clone https://github.com/open-quantum-safe/liboqs.git"
	@echo "  git -C liboqs checkout 5a1a854"
	@echo "  cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX=$$HOME/liboqs-install \\"
	@echo "        -DOQS_DIST_BUILD=ON -GNinja"
	@echo "  cmake --build liboqs/build --parallel"
	@echo "  cmake --install liboqs/build"
	@echo ""
	@echo "That prefix matches OQS_PREFIX's default. For a system-wide"
	@echo "install use -DCMAKE_INSTALL_PREFIX=/usr/local with sudo, then"
	@echo "build the harnesses with: make OQS_PREFIX=/usr/local"
