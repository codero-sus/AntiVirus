Behavioural-analysis demo samples
=================================

Every file in this directory is INERT.  They are plain text scripts and a
hand-assembled, code-less PE image used to demonstrate the behavioural
detection layer.  None of them is ever executed by AntiVirus (analysis is
purely static), and none of them contains real malware.

  harmless-py.py       clean Python script          -> no findings
  harmless.sh          clean shell script           -> no findings
  payload-py.py        dynamic code exec, shell-outs, hardcoded C2,
                       base64 payload blob          -> Python AST findings
  pipe-shell.sh        curl | sh, /dev/tcp, crontab persistence,
                       mining endpoint              -> shell findings
  reverse-ps1.ps1      IEX + DownloadString, execution-policy bypass
                       -> PowerShell findings
  dropper.bat          certutil/mshta LOLBins       -> batch findings
  suspicious.exe       minimal code-less PE whose import table advertises
                       process-injection / download / persistence APIs
                       -> PE findings

Try it:

  python3 -m antivirus scan samples/behavior
  python3 -m antivirus behavior analyze samples/behavior/pipe-shell.sh
