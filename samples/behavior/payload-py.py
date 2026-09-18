"""DEMO - inert sample for the behavioural analyser (never executed).

Demonstrates the indicators the Python AST layer looks for.  The "payload"
is a harmless base64 string; nothing here is real malware.
"""
import base64
import os
import socket
import subprocess

PAYLOAD_B64 = "aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSByZWFsIHBheWxvYWQgaXQganVzdCBsb29zZXMgbGlrZSBvbmUgZm9yIHRoZSBEZW1vIG9mIHRoZSBiZWhhdmlvdXJhbCBhbmFseXplciBpbiB0aGUgQW50aVZpcmVzIHByb2plY3QgdG8gc2hvdyBvZmYgd2hhdCBhIG9idXNjdXJlIHB5cXVlIGxvb2tzIGxpa2Ugbm90aGluZw=="

# Indicator: shell command execution (os.system)
os.system("uname -a")

# Indicator: subprocess with shell=True
subprocess.check_output("id && whoami", shell=True)

# Indicator: network connect to a hardcoded address
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.9", 4444))

# Indicators: dynamic code execution on decoded data
exec(base64.b64decode(PAYLOAD_B64))
