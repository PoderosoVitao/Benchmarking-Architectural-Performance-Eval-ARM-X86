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
# Prerequisites (Debian/Ubuntu; adjust package manager elsewhere):
#   sudo apt install build-essential cmake libssl-dev pkg-config git
#   # Then build and install liboqs (0.15.0 used for this project's results):
#   git clone --depth 1 --branch 0.15.0 \
#       https://github.com/open-quantum-safe/liboqs.git
#   cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX=/usr/local \
#         -DOQS_DIST_BUILD=ON -G "Unix Makefiles"
#   # (swap in -GNinja if ninja-build is installed; not required)
#   cmake --build liboqs/build --parallel
#   sudo cmake --install liboqs/build
# ──────────────────────────────────────────────────────────────────────────

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -I/usr/local/include
LDFLAGS = -L/usr/local/lib

OQS_LIBS     = -loqs $(shell pkg-config --libs openssl) -lm
OPENSSL_LIBS = $(shell pkg-config --libs openssl) -lm

TARGETS = bench_pqc bench_classical

.PHONY: all run run_pqc run_classical clean install_deps

all: $(TARGETS)

bench_pqc: bench_pqc.c benchmark.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(OQS_LIBS)
	@echo "Built: $@"

bench_classical: bench_classical.c benchmark.h
	$(CC) $(CFLAGS) -o $@ $< \
	    $(shell pkg-config --cflags openssl) $(LDFLAGS) $(OPENSSL_LIBS)
	@echo "Built: $@"

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
