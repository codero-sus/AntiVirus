Behavioural-analysis demo samples
=================================

Every file in this directory is INERT.  They are plain text scripts and
hand-assembled, code-less PE / ELF images used to demonstrate the
behavioural detection layer, the PE "debug report" dissection, the ELF
import-table analysis and the archive layer.  None of them is ever executed
by AntiVirus (analysis is purely static), and none of them contains real
malware.

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
  suspicious.elf       code-less ELF32: imports system/execve/popen,
                       dlopen/dlsym, socket/connect/send -> ELF import findings
  clean.elf            code-less ELF32: benign imports (printf, write, ...)
                       -> no findings
  sneaky.zip           archive: harmless EICAR test string hidden inside
                       (sneaky.zip!eicar-test.txt) + a zip-slip entry name
                       (../outside.txt)             -> archive findings
  sneaky.tar.gz        gzip-compressed TAR: EICAR string hidden inside
                       (sneaky.tar.gz!eicar-test.txt) + a tar-slip entry name
                       (../outside.txt)             -> archive findings

Try it:

  python3 -m antivirus scan samples/behavior
  python3 -m antivirus scan samples/behavior --fast
  python3 -m antivirus behavior analyze samples/behavior/pipe-shell.sh
  python3 -m antivirus pe analyze samples/behavior/suspicious.exe
  python3 -m antivirus pe analyze samples/behavior/packed-upx.exe
  python3 -m antivirus pe analyze samples/behavior/clean.exe
  python3 -m antivirus behavior analyze samples/behavior/suspicious.elf
  python3 -m antivirus scan samples/behavior/sneaky.tar.gz
