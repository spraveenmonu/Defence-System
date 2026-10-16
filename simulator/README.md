# KLCDS Simulator Scripts
#
# This directory contains SAFE simulation scripts that mimic attack patterns
# using only dummy files in a sandboxed directory.  NO real malware, NO real
# encryption.
#
# Scripts (Phase 5):
#   simulate_ransomware.py  — Renames/modifies dummy files to trigger ransomware rules
#   simulate_trojan.py      — Download-execute-connect chain against localhost
#   simulate_portscan.py    — Opens connections to local ports to trigger scan detection
