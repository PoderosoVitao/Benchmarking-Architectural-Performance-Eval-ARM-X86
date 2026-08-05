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
# Prerequisites (Ubuntu 22.04):
#   sudo apt install build-essential cmake ninja-build libssl-dev
#   # Then build and install liboqs:
#   git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
#   cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX=/usr/local \
#         -DOQS_DIST_BUILD=ON -GNinja
#   cmake --build liboqs/build --parallel
#   sudo cmake --install liboqs/build
# ──────────────────────────────────────────────────────────────────────────

CC      = gcc
OQS_PREFIX ?= $(HOME)/liboqs-install
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
	@echo "Results: results_pqc_x86.csv  results_classical_x86.csv"

run_pqc: bench_pqc
	@echo ""
	@echo "--- Running PQC benchmark ---"
	./bench_pqc results_pqc_x86.csv

run_classical: bench_classical
	@echo ""
	@echo "--- Running classical baseline benchmark ---"
	./bench_classical results_classical_x86.csv

# ── cleanup ───────────────────────────────────────────────────────────────
clean:
	rm -f $(TARGETS) results_pqc_x86.csv results_classical_x86.csv

# ── dependency installation hint ─────────────────────────────────────────
install_deps:
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y build-essential cmake ninja-build \
	    libssl-dev pkg-config git
	@echo ""
	@echo "Now build and install liboqs:"
	@echo "  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git"
	@echo "  cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX=/usr/local \\"
	@echo "        -DOQS_DIST_BUILD=ON -GNinja"
	@echo "  cmake --build liboqs/build --parallel"
	@echo "  sudo cmake --install liboqs/build"
