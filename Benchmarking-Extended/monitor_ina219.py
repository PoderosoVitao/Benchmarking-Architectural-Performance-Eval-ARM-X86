#!/usr/bin/env python3
"""
monitor_ina219.py

Per-operation energy resolution for the Raspberry Pi via an INA219 current/
power sensor on the I2C bus, wired inline with the Pi's power supply.

*** UNVERIFIED — no physical INA219 was available to test this against. ***
The register map and calibration formula below are the standard TI INA219
datasheet procedure (stable across the many INA219 breakout boards on the
market), not guessed — but "correct per the datasheet" and "correct on your
specific board wired your specific way" are different claims, and only the
second one matters. Before trusting any number this prints: check bus_v_v
against a known-good voltage reading with a multimeter, and confirm
current_ma looks sane at idle (a Pi 4 idles around 400-600 mA typically).

Why this exists: x86 gets energy-per-operation for free from RAPL (see
open_energy_counter() in benchmark.h). The Pi's SoC has no equivalent
on-chip energy accumulator the OS can read, so ARM energy needs an
external sensor in the power path instead — this script is the software
half of that; the hardware half (an INA219 breakout board wired in series
with the Pi's 5V input, plus enabling I2C via raspi-config) is something
only you can do.

Wiring (standard INA219 breakout, e.g. Adafruit/generic clones):
  - VIN+ / VIN- go in SERIES with the Pi's 5V power input (the sensor
    measures current flowing THROUGH it, so the Pi's power feed must be
    interrupted and routed through the shunt).
  - VCC -> Pi 3.3V, GND -> Pi GND, SDA -> Pi SDA (pin 3), SCL -> Pi SCL (pin 5).
  - Enable I2C: `sudo raspi-config` -> Interface Options -> I2C -> enable.
  - Confirm the device is visible: `i2cdetect -y 1` should show 0x40
    (the INA219's default address) on the bus.

Dependency: smbus2 (`pip install smbus2` or `sudo apt install python3-smbus`).

Usage:
    ./monitor_ina219.py <output_csv> [sample_hz]
    Runs until killed (SIGTERM/SIGINT), same convention as monitor_system.sh:
        ./monitor_ina219.py energy.csv 50 &
        PID=$!
        ./bench_pqc results.csv results_raw.csv
        kill $PID

    Cross-reference against a benchmark run's raw CSV via the shared
    wall-clock epoch column (epoch_start in the raw CSV, epoch here):
    for a given algorithm/operation block, sum (power_mw * dt) over every
    sample whose epoch falls within [epoch_start, epoch_start + total
    block duration] to get that block's total energy, then divide by
    N_ITERATIONS for mean energy per operation — the same "energy before
    vs. after the whole block, divided by N" idea RAPL uses on x86,
    just computed post-hoc from a continuous power trace instead of a
    single accumulating hardware counter.
"""
import sys
import time
import signal

try:
    from smbus2 import SMBus
except ImportError:
    print("ERROR: smbus2 not installed. Try: pip install smbus2  "
          "(or: sudo apt install python3-smbus)", file=sys.stderr)
    sys.exit(1)

# ── INA219 register map (TI datasheet SBOS448) ─────────────────────────────
REG_CONFIG      = 0x00
REG_SHUNT_V     = 0x01
REG_BUS_V       = 0x02
REG_POWER       = 0x03
REG_CURRENT     = 0x04
REG_CALIBRATION = 0x05

DEFAULT_I2C_ADDR = 0x40   # INA219 default address (A0/A1 both tied low)
DEFAULT_I2C_BUS  = 1      # /dev/i2c-1, the standard Pi user-accessible bus

# Calibration assumes the common breakout-board default: 0.1 ohm shunt,
# 32V bus range, up to ~3.2A. If your board uses a different shunt
# resistor (check its silkscreen/datasheet), SHUNT_OHMS below MUST match
# it or every current/power/energy reading will be wrong by a constant
# factor — this is the single most common INA219 mistake.
SHUNT_OHMS = 0.1
MAX_EXPECTED_AMPS = 3.2

# Standard calibration-register derivation (datasheet section 8.5):
#   current_lsb = max_expected_amps / 32768
#   cal = trunc(0.04096 / (current_lsb * shunt_ohms))
#   power_lsb = 20 * current_lsb
CURRENT_LSB = MAX_EXPECTED_AMPS / 32768.0
CAL_VALUE = int(0.04096 / (CURRENT_LSB * SHUNT_OHMS))
POWER_LSB = 20.0 * CURRENT_LSB

# Config register: 32V bus range, 320mV shunt range (gain /8, the
# datasheet's widest/safest gain setting), 12-bit ADC, continuous
# shunt+bus conversion. 0x399F is the datasheet's own example value for
# this exact combination — used as-is rather than hand-derived, since a
# single wrong bit here silently produces plausible-looking garbage.
CONFIG_VALUE = 0x399F

_running = True


def _stop(_signum, _frame):
    global _running
    _running = False


def read_word_be(bus, addr, reg):
    """INA219 registers are big-endian 16-bit; smbus2's word read is
    little-endian, so swap bytes."""
    raw = bus.read_word_data(addr, reg)
    return ((raw << 8) & 0xFF00) | (raw >> 8)


def to_signed16(val):
    return val - 65536 if val > 32767 else val


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "ina219_energy.csv"
    sample_hz = float(sys.argv[2]) if len(sys.argv) > 2 else 50.0
    period = 1.0 / sample_hz

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    try:
        bus = SMBus(DEFAULT_I2C_BUS)
    except FileNotFoundError:
        print(f"ERROR: /dev/i2c-{DEFAULT_I2C_BUS} not found. Enable I2C via "
              f"raspi-config first.", file=sys.stderr)
        sys.exit(1)

    try:
        bus.write_word_data(DEFAULT_I2C_ADDR, REG_CALIBRATION,
                             ((CAL_VALUE << 8) & 0xFF00) | (CAL_VALUE >> 8))
        bus.write_word_data(DEFAULT_I2C_ADDR, REG_CONFIG,
                             ((CONFIG_VALUE << 8) & 0xFF00) | (CONFIG_VALUE >> 8))
    except OSError as e:
        print(f"ERROR: could not write INA219 registers at address "
              f"0x{DEFAULT_I2C_ADDR:02x} on bus {DEFAULT_I2C_BUS}: {e}\n"
              f"  Check wiring and `i2cdetect -y {DEFAULT_I2C_BUS}` shows "
              f"the device.", file=sys.stderr)
        sys.exit(1)

    print(f"monitor_ina219.py: sampling at {sample_hz} Hz, "
          f"shunt={SHUNT_OHMS} ohm, cal=0x{CAL_VALUE:04x} -> {out_path}",
          file=sys.stderr)

    with open(out_path, "w") as f:
        f.write("epoch,bus_v_v,current_ma,power_mw\n")
        cumulative_mj = 0.0
        last_t = time.time()

        while _running:
            t0 = time.time()

            raw_bus = read_word_be(bus, DEFAULT_I2C_ADDR, REG_BUS_V)
            # bus voltage register: bits [15:3] are the 13-bit value in
            # 4mV steps; bits [2:0] are status/overflow flags, discard them.
            bus_v = ((raw_bus >> 3) * 4) / 1000.0  # volts

            raw_current = to_signed16(read_word_be(bus, DEFAULT_I2C_ADDR, REG_CURRENT))
            current_ma = raw_current * CURRENT_LSB * 1000.0

            raw_power = read_word_be(bus, DEFAULT_I2C_ADDR, REG_POWER)
            power_mw = raw_power * POWER_LSB * 1000.0

            dt = t0 - last_t
            cumulative_mj += power_mw * dt  # mW * s = mJ
            last_t = t0

            f.write(f"{t0:.3f},{bus_v:.4f},{current_ma:.2f},{power_mw:.2f}\n")
            f.flush()

            elapsed = time.time() - t0
            sleep_for = period - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)

    print(f"monitor_ina219.py: stopped, cumulative energy = "
          f"{cumulative_mj:.1f} mJ over the run", file=sys.stderr)


if __name__ == "__main__":
    main()
