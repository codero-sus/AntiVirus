Behavioural-analysis demo samples
=================================

Every file in this directory is INERT.  They are plain text scripts and
hand-assembled, code-less PE images used to demonstrate the behavioural
detection layer and the PE "debug report" dissection.  None of them is ever
executed by AntiVirus (analysis is purely static), and none of them contains
real malware.

  harmless-py.py       clean Python script          -> no findings
  harmless.sh          clean shell script           -> no findings
  payload-py.py        dynamic code exec, shell-outs, hardcoded C2,
                       base64 payload blob          -> Python AST findings
  pipe-shell.sh        curl | sh, /dev/tcp, crontab persistence,
                       mining endpoint              -> shell findings
  reverse-ps1.ps1      IEX + DownloadString, execution-policy bypass
                       -> PowerShell findings
  dropper.bat          certutil/mshta LOLBins       -> batch findings
  suspicious.exe       code-less PE: dangerous imports, ASLR/DEP off,
                       no entry point, no relocations, no debug info,
                       VBScript hidden in the resources -> many PE findings
  packed-upx.exe       code-less PE: RELOCS_STRIPPED, no import table,
                       high-entropy UPX0 section    -> packer PE findings
  clean.exe            well-formed code-less PE: benign imports, ASLR +
                       DEP on, entry point, relocations, debug info
                       -> no findings

Try it:

  python3 -m antivirus scan samples/behavior
  python3 -m antivirus behavior analyze samples/behavior/pipe-shell.sh
  python3 -m antivirus pe analyze samples/behavior/suspicious.exe
  python3 -m antivirus pe analyze samples/behavior/packed-upx.exe
  python3 -m antivirus pe analyze samples/behavior/clean.exe
