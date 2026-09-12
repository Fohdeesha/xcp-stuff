#!/usr/bin/env bash
# J-Sands / D-Pollak - Vates
#
# Retired. This was the bash health check (last live at v2.9, commit a7d5c8b); health.py
# in this same repo replaced it, and this file now does nothing but say so. The full
# implementation is in the git history if it is ever wanted again.

cat <<'EOF'

This bash based script has been retired, please use the new python based script:

# from XOA as root (no args = interactive menu to choose pool):
python3 <(curl -fsSL https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/health.py)

# With args:
python3 <(curl -fsSL https://raw.githubusercontent.com/Fohdeesha/xcp-stuff/main/health.py) -n mainpool

That same command also runs directly on an XCP-ng host (8.3 or newer) as root. XCP-ng
8.2.1 has no python3 in dom0, so check those pools from XOA instead.

https://github.com/Fohdeesha/xcp-stuff

EOF

# non-zero on purpose: a cron job or wrapper still calling this must not read "retired" as
# "checked, and all clean"
exit 1
