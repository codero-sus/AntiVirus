"""Indicator checks (v2.8) — *technique* markers, not family names.

The signature database answers *"is this a known threat?"* (hashes and
family markers).  This module answers a different question:

    *"does this file (a script, document, config or binary) contain the
    commands, API calls and artefacts of an attack technique?"*

That is what catches the long tail: a freshly-written loader has no known
signature, but it still runs ``certutil -urlcache``, writes a Run key and
deletes shadow copies.  Each check below is a small, reviewable rule with an
id, a category and a severity, grouped as:

* ``execution``    – script interpretation, LOLBins, download cradles
* ``persistence``  – autostart/scheduled-task/service/cron mechanisms
* ``evasion``      – AV/firewall/log tampering, sandbox & debugger checks
* ``credential``   – credential, browser and wallet theft primitives
* ``lateral``      – shares, remote exec tools, recon, RDP enablement
* ``exfil``        – C2 channels and upload/staging behaviour
* ``impact``       – ransomware note text, encryption sweeps, wipers
* ``office``       – macro/DDE/LNK delivery behaviour

Matching is case-insensitive and runs over the file bytes plus the decoded
UTF-16 view (so PowerShell ``-EncodedCommand`` payloads and Windows config
dumps are visible).  Checks only look for *markers*; every finding says
which marker matched, so a human can verify it in seconds.

Design notes
------------
* Checks with only ``patterns`` are merged into **one compiled alternation
  per severity** – a file is scanned once per severity, not once per check.
* ``require`` checks (all-of, e.g. "shell **and** CreateObject") run
  individually; there are only a handful.
* ``filenames`` conditions are matched against the file *name* (ransomware
  extensions, note names, ``.lnk`` files).
* Nothing is executed; this layer is pure static analysis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Sequence, Tuple

from .models import Finding
from .prefilter import Prefilter
from .utils import marker_text_ok, utf16_view

#: How much of a file is inspected (technique markers live near the front,
#: and this keeps the merged regexes cheap on big installers).
MAX_BYTES = 2 * 1024 * 1024
#: At most this many findings per file (avoid a "wall of noise" on some
#: packer stub that trips half the table).
MAX_FINDINGS = 20
#: Highest number of distinct snippets recorded per check.
MAX_SNIPPETS = 2

_PRE = 24      # characters of context shown *before* a match
_POST = 24     # characters of context shown *after* a match


@dataclass(frozen=True)
class Indicator:
    """One technique check."""

    id: str
    name: str
    category: str
    severity: str
    description: str
    patterns: Tuple[str, ...] = ()       # any-of (merged into the fast path)
    require: Tuple[str, ...] = ()        # all-of (run individually)
    filenames: Tuple[str, ...] = ()      # file-name regexes (any-of)
    tags: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "tags": list(self.tags),
        }


def _i(id: str, name: str, category: str, severity: str, description: str,
       *patterns: str, require: Sequence[str] = (), filenames: Sequence[str] = (),
       tags: Sequence[str] = ()) -> Indicator:
    return Indicator(id=id, name=name, category=category, severity=severity,
                     description=description, patterns=tuple(patterns),
                     require=tuple(require), filenames=tuple(filenames),
                     tags=tuple(tags))


#: Human titles for the categories (used by the CLI and the web API).
CATEGORY_TITLES = {
    "execution": "Execution & scripting",
    "persistence": "Persistence",
    "evasion": "Defense evasion",
    "credential": "Credential access",
    "lateral": "Lateral movement & discovery",
    "exfil": "Command & control / exfiltration",
    "impact": "Impact (ransomware / wiper)",
    "office": "Office / document delivery",
}

# --------------------------------------------------------------------------
# The table.  Keep patterns strictly single-line (no DOTALL): every marker
# is a command line, a registry path or a file name.
# --------------------------------------------------------------------------
CHECKS: Tuple[Indicator, ...] = (

    # ----------------------------------------------------------- execution
    _i("IND-EXEC-PS-ENCODED", "PowerShell encoded command",
       "execution", "high",
       "Base64-encoded PowerShell command line (the classic -enc wrapper).",
       r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{24,}",
       r"-EncodedCommand\s",
       tags=("powershell", "obfuscation")),
    _i("IND-EXEC-PS-HIDDEN", "Hidden PowerShell window",
       "execution", "medium",
       "PowerShell launched without a visible window (user never sees it).",
       r"-(?:w|windowstyle)\s+hidden",
       r"WindowStyle\s+Hidden"),
    _i("IND-EXEC-PS-BYPASS", "PowerShell execution-policy bypass",
       "execution", "medium",
       "Execution policy is being bypassed so downloaded scripts can run.",
       r"-(?:executionpolicy|ep)\s+bypass",
       r"ExecutionPolicy\s+(?:Bypass|Unrestricted)"),
    _i("IND-EXEC-PS-DOWNLOAD", "PowerShell download cradle",
       "execution", "high",
       "Script downloads content from the network before executing it.",
       r"DownloadString", r"DownloadFile", r"DownloadData",
       r"Net\.WebClient", r"Invoke-WebRequest", r"Start-BitsTransfer",
       tags=("powershell", "download")),
    _i("IND-EXEC-PS-IEX", "Dynamic PowerShell evaluation",
       "execution", "medium",
       "Invoke-Expression / IEX executes a string as code (obfuscation "
       "and staged payloads).",
       r"\bIEX\s*\(", r"\|\s*IEX\b", r"\bInvoke-Expression\b"),
    _i("IND-EXEC-PS-FROMBASE64", "Base64 decode in PowerShell",
       "execution", "medium",
       "PowerShell decodes a base64 blob at runtime.",
       r"FromBase64String", r"FromBase64CharArray"),
    _i("IND-EXEC-PS-REFLECTLOAD", "In-memory .NET assembly load",
       "execution", "high",
       "Loads a .NET assembly straight from bytes/memory (fileless "
       "execution, no DLL on disk).",
       r"\[Reflection\.Assembly\]::Load", r"Assembly\]::LoadFrom",
       r"Assembly\]::LoadFile",
       tags=("fileless",)),
    _i("IND-EXEC-PS-ADDTYPE", "PowerShell compiles code at runtime",
       "execution", "medium",
       "Add-Type compiles attacker-supplied source in memory.",
       r"Add-Type\s+-TypeDefinition", r"Add-Type\s+-AssemblyName"),
    _i("IND-EXEC-CERTUTIL", "certutil used as a downloader/decoder",
       "execution", "high",
       "certutil fetching or decoding a payload (a built-in Windows "
       "binary abused as a downloader).",
       r"certutil[^\n]{0,40}-urlcache",
       r"certutil[^\n]{0,40}\s-(?:decode|encode)\b",
       tags=("lolbin",)),
    _i("IND-EXEC-BITSADMIN", "bitsadmin transfer",
       "execution", "medium",
       "Background Intelligent Transfer Service used to fetch a file.",
       r"bitsadmin\s+/transfer", r"bitsadmin[^\n]{0,24}/addfile",
       tags=("lolbin",)),
    _i("IND-EXEC-MSHTA", "mshta remote/script execution",
       "execution", "high",
       "mshta executing a remote page or inline script (HTML application "
       "abuse).",
       r"mshta(?:\.exe)?\s+https?://", r"mshta\s+(?:javascript|vbscript):",
       tags=("lolbin",)),
    _i("IND-EXEC-RUNDLL32-JS", "rundll32 script execution",
       "execution", "high",
       "rundll32 loading javascript:/vbscript: or a remote .sct scriptlet.",
       r"rundll32[^\n]{0,40}javascript:", r"rundll32[^\n]{0,40}\.sct",
       tags=("lolbin",)),
    _i("IND-EXEC-REGSVR32", "regsvr32 remote scriptlet",
       "execution", "high",
       "regsvr32 with a URL/scriptlet (the 'Squiblydoo' AppLocker bypass).",
       r"regsvr32[^\n]{0,40}/i:https?://", r"regsvr32[^\n]{0,40}scrobj",
       tags=("lolbin", "bypass")),
    _i("IND-EXEC-WMIC", "wmic process creation / remote node",
       "execution", "medium",
       "wmic spawning a process or targeting a remote node.",
       r"wmic[^\n]{0,60}process\s+call\s+create", r"wmic[^\n]{0,40}/node:",
       tags=("lolbin",)),
    _i("IND-EXEC-MSBUILD", "MSBuild inline task",
       "execution", "high",
       "MSBuild compiling an attacker-supplied inline task (AppLocker "
       "bypass).",
       require=(r"msbuild", r"UsingTask"),
       tags=("lolbin", "bypass")),
    _i("IND-EXEC-INSTALLUTIL", "InstallUtil bypass",
       "execution", "high",
       "InstallUtil executing a .NET assembly (classic AppLocker bypass).",
       r"installutil[^\n]{0,40}/logfile=", r"installutil[^\n]{0,40}\s/u\b",
       tags=("lolbin", "bypass")),
    _i("IND-EXEC-CMSTP", "CMSTP UAC bypass",
       "execution", "high",
       "cmstp being used with a .inf/CMLUA.dll (UAC bypass technique).",
       r"cmstp[^\n]{0,40}/s", r"cmstp[^\n]{0,40}/ni", r"CMLUA\.dll",
       tags=("lolbin", "bypass")),
    _i("IND-EXEC-ODBCCONF", "odbcconf bypass",
       "execution", "medium",
       "odbcconf registering an arbitrary DLL (AppLocker bypass).",
       r"odbcconf[^\n]{0,40}RegisterDlls", r"odbcconf\s+/a\s+\{",
       tags=("lolbin", "bypass")),
    _i("IND-EXEC-XPCMDSHELL", "MSSQL command execution",
       "execution", "high",
       "xp_cmdshell / sp_configure used to run OS commands via SQL "
       "Server.",
       r"xp_cmdshell", r"sp_configure[^\n]{0,40}show\s+advanced",
       tags=("database",)),
    _i("IND-EXEC-PIPE-TO-SHELL", "Download piped into a shell",
       "execution", "critical",
       "curl/wget/PowerShell output piped straight to a shell – the "
       "canonical one-line installer *and* malware dropper.",
       r"(?:curl|wget)[^\n]{0,80}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b",
       r"powershell[^\n]{0,60}\|\s*(?:IEX|iex|Invoke-Expression)",
       tags=("download",)),
    _i("IND-EXEC-B64-PIPE", "Base64 decoded into a shell",
       "execution", "high",
       "A base64 blob is decoded and piped to a shell (encoded "
       "payload execution).",
       r"base64\s+(?:-d|--decode|-[dD])[^\n]{0,24}\|\s*(?:ba|z|k)?sh",
       tags=("obfuscation", "download")),
    _i("IND-EXEC-SCRIPT-ONELINER", "Interpreter one-liner with network/exec",
       "execution", "medium",
       "python/perl one-liner combining networking with command "
       "execution (reverse shell or downloader oneliner).",
       r"python[0-9.]*\s+-c[^\n]{0,90}(?:socket|urllib|subprocess|os\.system)",
       r"perl\s+-e[^\n]{0,60}socket",
       tags=("oneliner",)),
    _i("IND-EXEC-EVAL-OBFUSCATED", "Obfuscated script evaluation",
       "execution", "medium",
       "eval/unescape or fromCharCode chain – script hiding its payload.",
       r"eval\(\s*unescape\(", r"eval\(String\.fromCharCode\(",
       r"fromCharCode[^\n]{0,300}eval\(",
       tags=("obfuscation",)),
    _i("IND-EXEC-WSCRIPT-SHELL", "WScript.Shell object",
       "execution", "medium",
       "Script creates a WScript.Shell object (run commands / registry "
       "writes from VBS/JS).",
       r"WScript\.Shell", r"Shell\.Run\s*\(",
       tags=("vbs",)),
    _i("IND-EXEC-SCHTASK-SPAWN", "Command interpreter spawned from script",
       "execution", "low",
       "Script spawns cmd.exe/PowerShell to run further commands.",
       r"cmd(?:\.exe)?\s+/c\s", r"powershell(?:\.exe)?\s+-(?:nop|noni|w\s+hidden|c)\b",
       tags=("script",)),

    # --------------------------------------------------------- persistence
    _i("IND-PERSIST-RUNKEY", "Registry Run key autostart",
       "persistence", "high",
       "Writes to a Windows Run key (starts with the user session).",
       r"CurrentVersion\\Run", r"CurrentVersion\\RunOnce",
       tags=("registry", "windows")),
    _i("IND-PERSIST-SCHTASKS", "Scheduled task creation",
       "persistence", "high",
       "Creates a scheduled task (periodic persistence, often SYSTEM).",
       r"schtasks[^\n]{0,60}/create",
       r"Register-ScheduledTask", r"Register-ScheduledJob",
       tags=("scheduler",)),
    _i("IND-PERSIST-SERVICE", "Service installation",
       "persistence", "high",
       "Installs a Windows service (starts at boot, often SYSTEM).",
       r"\bsc(?:\.exe)?\s+create\b", r"New-Service\b",
       r"CreateService\s*\(", r"CreateServiceW\s*\(",
       tags=("service", "windows")),
    _i("IND-PERSIST-WMI-EVENT", "WMI event subscription",
       "persistence", "high",
       "Permanent WMI event consumer – fileless persistence.",
       r"__EventFilter", r"CommandLineEventConsumer",
       r"ActiveScriptEventConsumer", r"__EventConsumer",
       tags=("wmi", "fileless")),
    _i("IND-PERSIST-STARTUP-FOLDER", "Startup folder drop",
       "persistence", "medium",
       "Writes into the user's Startup folder.",
       r"Start Menu\\Programs\\Startup", r"\\Startup\\[^\s\"']+\.(?:exe|lnk|bat|vbs|js)",
       tags=("windows",)),
    _i("IND-PERSIST-WINLOGON", "Winlogon hijack",
       "persistence", "high",
       "Modifies Winlogon Shell/Userinit (runs before the desktop).",
       r"Winlogon\\Shell", r"Winlogon\\Userinit", r"UserinitMprLogonScript",
       tags=("registry", "windows")),
    _i("IND-PERSIST-APPINIT", "AppInit_DLLs injection",
       "persistence", "high",
       "AppInit_DLLs makes Windows load the DLL into every process.",
       r"AppInit_DLLs", r"AppInit_Dlls",
       tags=("registry", "dll")),
    _i("IND-PERSIST-IFEO", "Image File Execution Options hijack",
       "persistence", "high",
       "IFEO 'Debugger' value – hijacks a program (often a security "
       "tool) when it starts.",
       r"Image File Execution Options", r"IFEO\\[^\n]{0,40}Debugger",
       tags=("registry", "windows")),
    _i("IND-PERSIST-CRON", "Cron persistence",
       "persistence", "medium",
       "Adds cron entries / @reboot commands.",
       r"crontab\s+-(?:e|u|\s)", r"@reboot[^\n]{0,60}",
       r"/etc/cron\.d/", r"cron\.d[^\n]{0,40}>>",
       tags=("linux",)),
    _i("IND-PERSIST-SYSTEMD", "systemd unit persistence",
       "persistence", "medium",
       "Writes or enables a systemd unit (Linux service persistence).",
       r"/etc/systemd/system/[^\s\"']+\.service",
       r"systemctl\s+(?:enable|--user\s+enable)\s",
       tags=("linux",)),
    _i("IND-PERSIST-RCLOCAL", "rc.local / init.d modification",
       "persistence", "medium",
       "Appends to rc.local or an init.d script (legacy Linux autostart).",
       r"/etc/rc\.local", r"/etc/init\.d/[^\s\"']+",
       tags=("linux",)),
    _i("IND-PERSIST-SSH-KEYS", "SSH authorized_keys write",
       "persistence", "high",
       "Adds a public key to authorized_keys (SSH backdoor).",
       r"authorized_keys", r"\.ssh/id_(?:rsa|ed25519)\.pub",
       tags=("ssh", "linux")),
    _i("IND-PERSIST-SHELL-PROFILE", "Shell profile modification",
       "persistence", "medium",
       "Appends to .bashrc/.profile/.zshrc so the payload runs on login.",
       r">>?\s*(?:~|\$HOME)/\.(?:bashrc|bash_profile|profile|zshrc)",
       r"(?:bashrc|bash_profile|zshrc)[^\n]{0,40}(?:curl|wget|python|nc\s)",
       tags=("linux", "shell")),
    _i("IND-PERSIST-LOGON-SCRIPT", "Logon script registration",
       "persistence", "medium",
       "Registers a logon script / Group Policy script path.",
       r"UserInitMprLogonScript", r"Scripts\\Logon",
       tags=("windows",)),

    # ------------------------------------------------------------- evasion
    _i("IND-EVADE-DEFENDER", "Windows Defender tampering",
       "evasion", "critical",
       "Disables Defender real-time protection or adds exclusions.",
       r"Set-MpPreference[^\n]{0,60}-Disable(?:RealtimeMonitoring|IOAVProtection)",
       r"DisableAntiSpyware", r"Add-MpPreference[^\n]{0,60}-ExclusionPath",
       r"DisableRealtimeMonitoring",
       tags=("antivirus", "windows")),
    _i("IND-EVADE-AV-PROCESS", "Security product process killed",
       "evasion", "critical",
       "Kills or stops an antivirus/EDR process or service.",
       r"taskkill[^\n]{0,60}(?:MsMpEng|NisSrv|avp|avpui|ekrn|sophos|mbam|mcshield|windefend)",
       r"net\s+stop[^\n]{0,40}(?:WinDefend|SharedAccess|Sense|wscsvc)",
       r"(?:Stop-Service|sc(?:\.exe)?\s+stop)[^\n]{0,40}(?:WinDefend|Sense|MpsSvc)",
       tags=("antivirus",)),
    _i("IND-EVADE-FIREWALL-OFF", "Firewall disabled",
       "evasion", "high",
       "Turns the host firewall off (opens the door for C2).",
       r"netsh[^\n]{0,60}advfirewall[^\n]{0,60}\b(?:off|state\s+off)",
       r"Set-NetFirewallProfile[^\n]{0,40}-Enabled\s+(?:False|\$false)",
       r"netsh[^\n]{0,60}firewall[^\n]{0,30}disable",
       tags=("firewall",)),
    _i("IND-EVADE-LOG-CLEAR", "Event log clearing",
       "evasion", "high",
       "Clears Windows event logs or deletes Linux logs (anti-forensics).",
       r"wevtutil\s+cl\s", r"Clear-EventLog", r"EventLog\.Delete\s*\(",
       r"rm\s+-[a-z]*f[a-z]*\s+/var/log",
       tags=("antiforensics",)),
    _i("IND-EVADE-SHADOWCOPY", "Shadow copy deletion",
       "evasion", "critical",
       "Deletes volume shadow copies – ransomware's step before "
       "encryption (removes restore points).",
       r"vssadmin[^\n]{0,60}delete\s+shadows",
       r"wmic[^\n]{0,40}shadowcopy[^\n]{0,20}delete",
       r"Win32_ShadowCopy[^\n]{0,80}Delete",
       r"Get-WmiObject[^\n]{0,40}Win32_ShadowCopy[^\n]{0,60}\.Delete",
       tags=("ransomware", "backup")),
    _i("IND-EVADE-BACKUP-DELETE", "Backup deletion",
       "evasion", "critical",
       "Deletes Windows backups / catalogs (prevents recovery).",
       r"wbadmin[^\n]{0,40}delete\s+(?:catalog|backup)",
       r"vssadmin[^\n]{0,40}delete\s+catalog",
       r"diskshadow[^\n]{0,40}delete\s+shadows",
       tags=("ransomware", "backup")),
    _i("IND-EVADE-RECOVERY-DISABLE", "Recovery options disabled",
       "evasion", "critical",
       "Disables boot recovery / startup repair so a reboot stays broken.",
       r"bcdedit[^\n]{0,60}recoveryenabled\s+no",
       r"bcdedit[^\n]{0,60}bootstatuspolicy\s+ignoreallfailures",
       r"Disable-ComputerRestore", r"REAGENTC\.EXE[^\n]{0,40}/disable",
       tags=("ransomware", "boot")),
    _i("IND-EVADE-HISTFILE", "Shell history tampering",
       "evasion", "medium",
       "Disables or wipes shell history (hides the operator's commands).",
       r"HISTFILE=/?dev/null", r"unset\s+HISTFILE", r"history\s+-c"),
    _i("IND-EVADE-SHRED", "Secure deletion tool",
       "evasion", "medium",
       "shred/srm/sdelete – securely wiping files (anti-forensics).",
       r"\bshred\s+-", r"\bsrm\s+-", r"\bsdelete[^\n]{0,40}-p\b"),
    _i("IND-EVADE-AMSI", "AMSI bypass",
       "evasion", "critical",
       "Patches or disables the Antimalware Scan Interface used by "
       "PowerShell.",
       r"amsiInitFailed", r"AmsiUtils", r"amsi\.dll", r"AMSI_RESULT",
       tags=("fileless", "bypass")),
    _i("IND-EVADE-ETW", "ETW telemetry patching",
       "evasion", "high",
       "Blinds Event Tracing for Windows (hides process behaviour from "
       "EDR).",
       r"EtwEventWrite", r"EtwpEventWriteFull", r"Microsoft-Windows-Threat-Intelligence",
       tags=("fileless", "bypass")),
    _i("IND-EVADE-UAC-OFF", "UAC disabled in registry",
       "evasion", "high",
       "Sets EnableLUA=0 – turns user account control off.",
       r"EnableLUA[^\n]{0,30}0", r"ConsentPromptBehaviorAdmin",
       tags=("registry", "windows")),
    _i("IND-EVADE-TIMESTOMP", "Timestamp manipulation",
       "evasion", "medium",
       "Changes file timestamps to hide when a file was dropped.",
       r"SetFileTime", r"timestomp", r"SetLastWriteTime",
       r"SetCreationTime", r"touch\s+-[a-z]*t\s"),
    _i("IND-EVADE-VM-ARTIFACTS", "Virtualisation artefact checks",
       "evasion", "medium",
       "Queries VMware/VirtualBox/QEMU artefacts to detect an analysis "
       "VM and hide.",
       r"SOFTWARE\\VMware, Inc\.\\VMware Tools",
       r"VBOX\\GuestProperties", r"VBoxService", r"vboxhook\.dll",
       r"qemu-ga", r"vmtoolsd",
       tags=("sandbox",)),
    _i("IND-EVADE-SANDBOX-DLLS", "Sandbox DLL detection",
       "evasion", "high",
       "Checks for sandbox instrumentation DLLs (SbieDll, cuckoomon, "
       "pafish) – the file expects to be analysed.",
       r"SbieDll\.dll", r"cuckoomon", r"\bpafish\.(?:exe|dll)\b",
       r"api_log\.dll", r"\bsbiedll\b\s*:",
       tags=("sandbox",)),
    _i("IND-EVADE-DEBUGGER", "Debugger presence check",
       "evasion", "medium",
       "Checks whether a debugger is attached (stops under analysis).",
       r"IsDebuggerPresent", r"CheckRemoteDebuggerPresent",
       r"PTRACE_TRACEME", r"NtQueryInformationProcess[^\n]{0,40}DebugPort"),
    _i("IND-EVADE-SLEEP", "Long sleep / delay evasion",
       "evasion", "low",
       "Long hard-coded delay – a classic sandbox timeout beater.",
       r"Start-Sleep[^\n]{0,20}(?:-Seconds\s+)?[1-9][0-9]{2,}",
       r"\bsleep\s+[1-9][0-9]{2,}\b", r"timeout\s+/t\s+[1-9][0-9]{2,}"),

    # --------------------------------------------------------- credential
    _i("IND-CRED-LSASS-DUMP", "LSASS memory dump",
       "credential", "critical",
       "Dumps LSASS process memory (where Windows keeps credential "
       "material).",
       r"MiniDumpWriteDump", r"procdump[^\n]{0,60}lsass",
       r"lsass\.dmp", r"comsvcs[^\n]{0,60}MiniDump",
       tags=("credentials",)),
    _i("IND-CRED-SAM-SAVE", "SAM/SYSTEM hive extraction",
       "credential", "critical",
       "Registers a copy of the SAM/SYSTEM hives or uses secretsdump "
       "/esentutl to extract password hashes.",
       r"reg\s+save[^\n]{0,40}HKLM\\SAM", r"reg\s+save[^\n]{0,40}HKLM\\SYSTEM",
       r"esentutl[^\n]{0,40}/vss", r"secretsdump",
       tags=("credentials",)),
    _i("IND-CRED-BROWSER-DATA", "Browser credential store access",
       "credential", "high",
       "Reads browser password/cookie databases (stealer behaviour).",
       r"Login Data", r"cookies\.sqlite", r"Local State",
       r"['\"]webData", r"Login Data For Account",
       tags=("credentials", "stealer")),
    _i("IND-CRED-WALLET", "Crypto wallet access",
       "credential", "high",
       "Reads or targets cryptocurrency wallet files/extensions.",
       r"wallet\.dat", r"Electrum\\wallets", r"MetaMask",
       r"nkbihfbeogaeaoehlefnkodbefgpgknn",
       tags=("cryptowallet", "stealer")),
    _i("IND-CRED-KEYLOG", "Keystroke capture primitives",
       "credential", "high",
       "Keyboard state/hook APIs — keylogger building blocks.",
       r"GetAsyncKeyState", r"SetWindowsHookEx", r"WH_KEYBOARD_LL",
       tags=("keylogger",)),
    _i("IND-CRED-CLIPBOARD", "Clipboard access",
       "credential", "medium",
       "Reads the clipboard (crypto-address swapping / credential "
       "capture).",
       r"GetClipboardData", r"OpenClipboard", r"Get-Clipboard"),
    _i("IND-CRED-SCREEN-CAPTURE", "Screen capture primitives",
       "credential", "low",
       "Takes screenshots or captures the screen (spyware behaviour).",
       r"BitBlt\b", r"PrintWindow\b", r"CopyFromScreen"),

    # ------------------------------------------------------ lateral/scan
    _i("IND-LATERAL-ADMIN-SHARE", "Admin share access",
       "lateral", "high",
       "Accesses C$/ADMIN$/IPC$ (remote copy or execution).",
       r"\\\\[^\s\"'<>|]{1,80}\\?(?:c|admin|ipc)\$"),
    _i("IND-LATERAL-PSEXEC", "PsExec-style remote execution",
       "lateral", "medium",
       "PsExec or its service (PSEXESVC) – remote command execution.",
       r"\bpsexec(?:\.exe)?\s+(?:-|\\\\|/accepteula)", r"PSEXESVC"),
    _i("IND-LATERAL-RECON", "Domain/host reconnaissance",
       "lateral", "medium",
       "Enumerates domain structure, admins or network shares.",
       r"nltest[^\n]{0,24}/dclist", r"net\s+group\s+\"Domain Admins\"",
       r"net\s+view\s+/domain", r"Get-ADDomain", r"net\s+accounts\s+/domain"),
    _i("IND-LATERAL-NETSCAN", "Network scanner usage",
       "lateral", "low",
       "Port/host scanner names — discovery stage of an intrusion.",
       r"\bnmap\s+-{1,2}[A-Za-z]", r"\bmasscan\s+-{1,2}[A-Za-z]"),
    _i("IND-LATERAL-RDP-ENABLE", "Remote desktop enabled",
       "lateral", "medium",
       "Enables RDP access (remote hands on the host).",
       r"fDenyTSConnections[^\n]{0,20}0",
       r"Set-ItemProperty[^\n]{0,80}fDenyTSConnections",
       r"Enable-NetFirewallRule[^\n]{0,60}RemoteDesktop"),

    # ------------------------------------------------------------- exfil
    _i("IND-EXFIL-DISCORD-WEBHOOK", "Discord webhook C2",
       "exfil", "high",
       "Posts to a Discord webhook (popular free exfiltration channel).",
       r"discord(?:app)?\.com/api/webhooks"),
    _i("IND-EXFIL-TELEGRAM-BOT", "Telegram bot C2",
       "exfil", "high",
       "Talks to the Telegram bot API (stealer C2 / exfiltration).",
       r"api\.telegram\.org/bot"),
    _i("IND-EXFIL-PASTEBIN", "Paste service staging",
       "exfil", "medium",
       "Fetches or posts to paste services (payload/text staging).",
       r"pastebin\.com/raw", r"paste\.ee/[a-zA-Z0-9]+"),
    _i("IND-EXFIL-UPLOAD", "File upload / data staging",
       "exfil", "medium",
       "Uploads local data (curl --data-binary, -F file=@, scp, "
       "Invoke-RestMethod -InFile).",
       r"curl[^\n]{0,80}--data-binary", r"curl[^\n]{0,80}-F\s+file=@",
       r"Invoke-RestMethod[^\n]{0,80}-InFile",
       r"scp\s+[^\n]{0,60}@[^\s]+:"),
    _i("IND-EXFIL-RAW-IP-DOWNLOAD", "Download from a bare IP",
       "exfil", "high",
       "Fetches a payload from a raw IP URL (no domain name – typical "
       "staging server).",
       r"(?:curl|wget|Invoke-WebRequest|iwr|DownloadFile)\b[^\n]{0,60}https?://\d{1,3}(?:\.\d{1,3}){3}"),

    # ------------------------------------------------------------ impact
    _i("IND-IMPACT-RANSOM-NOTE", "Ransom note text",
       "impact", "critical",
       "Text typical of a ransom note (files encrypted, pay to recover).",
       r"all your files (?:have been|are) encrypted",
       r"your files (?:have been|are) encrypted",
       r"to decrypt your files",
       r"files are encrypted.{0,60}(?:pay|bitcoin|btc)",
       r"your files will be (?:leaked|published)"),
    _i("IND-IMPACT-BTC-ADDRESS", "Bitcoin address present",
       "impact", "medium",
       "A Bitcoin address inside a document/note (ransom payment "
       "demand – verify the context).",
       r"\bbc1[ac-hj-np-z02-9]{25,62}\b",
       r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    _i("IND-IMPACT-ONION-ADDRESS", "Tor onion address present",
       "impact", "medium",
       "A .onion address (dark-web contact/payment site).",
       r"\b[a-z2-7]{16,56}\.onion\b"),
    _i("IND-IMPACT-ENCRYPT-SWEEP", "Scripted mass-encryption sweep",
       "impact", "critical",
       "A script that walks the filesystem and encrypts files with "
       "openssl/gpg — a hand-rolled ransomware pattern.",
       require=(r"openssl\s+enc", r"find\s+/"),
       tags=("ransomware",)),
    _i("IND-IMPACT-WIPE", "Disk/file wiping command",
       "impact", "critical",
       "Overwrites data with zeros/random (wiper or destructive "
       "cleanup).",
       r"dd\s+if=/dev/(?:zero|urandom)[^\n]{0,40}of=",
       r"cipher\s+/w[^\n]{0,40}",
       r"Format-Volume[^\n]{0,60}-Force"),
    _i("IND-IMPACT-SHUTDOWN-ABORT", "Abort shutdown / safe-mode tricks",
       "impact", "medium",
       "Suppresses shutdown prompts or forces safe-mode boot (keeps the "
       "payload running).",
       r"shutdown\s+/a\b", r"bcdedit[^\n]{0,40}/set[^\n]{0,20}safeboot"),

    # ------------------------------------------------------------ office
    _i("IND-OFFICE-MACRO-AUTORUN", "Office macro auto-exec",
       "office", "high",
       "Macro entry points that run when the document opens/closes.",
       r"Auto(?:Open|Close|Exec)", r"Document_Open", r"Workbook_Open",
       r"DocumentBeforeClose", r"Workbook_Activate", r"Auto_Open",
       tags=("macro",)),
    _i("IND-OFFICE-MACRO-DOWNLOAD", "Macro download primitive",
       "office", "high",
       "Macro uses XMLHTTP/URLDownloadToFile to fetch a payload.",
       r"URLDownloadToFile", r"MSXML2\.(?:XMLHTTP|ServerXMLHTTP)",
       r"WinHttp\.WinHttpRequest", r"Microsoft\.XMLHTTP",
       tags=("macro", "download")),
    _i("IND-OFFICE-MACRO-SHELL", "Macro executes a command",
       "office", "high",
       "Macro creates a shell object and runs a command (the standard "
       "macro payload step).",
       require=(r"CreateObject", r"(?:Shell|WScript\.Shell)"),
       tags=("macro",)),
    _i("IND-OFFICE-EXCEL4", "Excel 4.0 macro formula",
       "office", "high",
       "Excel 4.0 macro-sheet formulas (EXEC/CALL/REGISTER) – a popular "
       "macro bypass.",
       r"=EXEC\(", r"=CALL\(", r"=REGISTER\(", r"=HALT\(",
       tags=("macro",)),
    _i("IND-OFFICE-DDE", "DDE formula execution",
       "office", "high",
       "DDE/DDEAUTO fields spawn commands without macros.",
       r"DDEAUTO", r"=\s*cmd\s*\|", r"\{\s*DDE\s",
       tags=("dde",)),
    _i("IND-OFFICE-LNK-LAUNCHER", "LNK launcher with script content",
       "office", "high",
       "A .lnk shortcut whose target/arguments reference a script "
       "interpreter (phishing launcher).",
       r"powershell", r"cmd\.exe", r"mshta", r"rundll32",
       r"wscript", r"cscript",
       filenames=(r"\.lnk$",),
       tags=("lnk", "phishing")),

    # ------------------------------------------------ filename indicators
    _i("IND-RANSOM-NOTE-FILENAME", "Ransom note filename",
       "impact", "critical",
       "File named like a ransom note (readme/decrypt/restore).",
       filenames=(r"(?:readme[_-]?restore|how[_-]?to[_-]?decrypt|decrypt[_-]?instructions|"
                  r"recover[_-]?files|restore[_-]?my[_-]?files|read_me_medusa|"
                  r"readme_colp|akira_readme|\+readme-warning\+|decrypt-files)",
                  ),
       tags=("ransomware", "filename")),
    _i("IND-RANSOM-EXT-CLASSIC", "Classic ransomware extension",
       "impact", "medium",
       "File extension from a classic ransomware family (2016–2019 "
       "wave).",
       filenames=(r"\.(?:locky|zepto|cerber|locky|dharma|phobos|makop|djvu|"
                  r"sodinokibi|revil|conti|nefilim|clop|maze|trigona)\Z",),
       tags=("ransomware", "filename")),
    _i("IND-RANSOM-EXT-MODERN", "Modern ransomware extension",
       "impact", "medium",
       "File extension from a recent ransomware family (verify the file "
       "really was renamed).",
       filenames=(r"\.(?:lockbit|blackcat|alphv|hive|akira|basta|royal|"
                  r"medusa|yanluowang|cuba|noescape|rhysida|blackmatter|"
                  r"blacksuit|darkside|babuk|avoslocker|mountlocker)\Z",),
       tags=("ransomware", "filename")),
    _i("IND-RANSOM-EXT-GENERIC", "Generic crypto/encrypted extension",
       "impact", "low",
       "Generic .locked/.encrypted/.crypto style extension used by many "
       "families (many false alarms – verify).",
       filenames=(r"\.(?:locked|encrypted|crypted|crypto|enc|lock)\Z",),
       tags=("ransomware", "filename")),
)


# --------------------------------------------------------------------------
# Fast path: per-check compiled regexes + a literal-token gate.
#
# Matching 89 checks as one alternation costs O(checks) per byte (CPython's
# ``re`` has no multi-branch optimisation – measured ~10 s/MiB).  Each check
# therefore gets a memchr-backed literal gate first (prefilter.py) and only
# the survivors run their regexes.
# --------------------------------------------------------------------------
_COMPILED: List[Tuple[Indicator, List[Pattern[bytes]]]] = []
_COMBO: List[Indicator] = []


def _build() -> None:
    """Compile every check once and split off the combo/filename checks."""
    _COMBO.clear()
    _COMPILED.clear()
    for ind in CHECKS:
        # Checks with a file-name condition must not run here: their match
        # is only valid for matching names, so they go through the combo
        # path below (`_COMBO`) where the name is checked first.
        if ind.patterns and not ind.filenames:
            _COMPILED.append((ind, [
                re.compile(pat.encode("utf-8"), re.IGNORECASE)
                for pat in ind.patterns]))
        if ind.filenames or ind.require or not ind.patterns:
            _COMBO.append(ind)


def _rebuild_prefilter() -> Prefilter:
    """One literal gate per check: any-of patterns → any token present;
    ``require`` checks → every pattern's token present."""
    pf = Prefilter()
    for ind in CHECKS:
        if ind.require:
            pf.add_patterns(ind.id, list(ind.require), any_of=False)
        elif ind.patterns:
            pf.add_patterns(ind.id, list(ind.patterns), any_of=True)
    return pf


def _filename_regexes() -> List[Tuple[Indicator, Pattern[str]]]:
    out = []
    for ind in CHECKS:
        if ind.filenames:
            out.append((ind, re.compile("|".join(
                "(?:%s)" % p for p in ind.filenames), re.IGNORECASE)))
    return out


_build()
_PREFILTER = _rebuild_prefilter()


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------
def _sanitize(raw: bytes) -> str:
    text = raw.decode("latin-1", "replace")
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)


def _snippet(view: bytes, start: int, end: int) -> str:
    lo, hi = max(0, start - _PRE), min(len(view), end + _POST)
    return _sanitize(view[lo:hi]).strip()


def _check_allowed(ind: Indicator, name: str) -> bool:
    """Whether the file-name condition of *ind* (if any) is satisfied."""
    if not ind.filenames:
        return True
    return any(re.search("(?:%s)" % p, name, re.IGNORECASE)
               for p in ind.filenames)


def analyze(path, data: bytes, filename: Optional[str] = None,
            max_findings: int = MAX_FINDINGS) -> List[Finding]:
    """Run every indicator against *data* and return findings.

    *path* is used for the finding's path and (when *filename* is not
    given) for the file-name checks.  Nothing is executed.
    """
    name = filename if filename is not None else Path(str(path)).name
    if not data:
        return []
    views = [data[:MAX_BYTES]]
    wide = utf16_view(data[:MAX_BYTES])
    if wide and wide != views[0]:
        views.append(wide)

    findings: List[Finding] = []
    seen: Dict[str, int] = {}
    candidates = set(_PREFILTER.candidates(data[:MAX_BYTES]))
    if wide:
        candidates |= set(_PREFILTER.candidates(wide))

    def _emit(ind: Indicator, snippet: str, *, text_ok: bool = True) -> None:
        if not text_ok:
            return
        if seen.get(ind.id, 0) >= MAX_SNIPPETS:
            return
        seen[ind.id] = seen.get(ind.id, 0) + 1
        findings.append(Finding(
            path=str(path), kind="indicator", name=ind.name,
            severity=ind.severity,
            message=(f"{ind.description} Matched: \"{snippet[:96]}\" "
                     f"[{ind.id}]")))

    # 1. any-of content checks (literal prefilter, then text-context check)
    for ind, regexes in _COMPILED:
        if ind.id not in candidates:
            continue
        for view in views:
            for rx in regexes:
                m = rx.search(view)
                if m is not None:
                    _emit(ind, _snippet(view, m.start(), m.end()),
                          text_ok=marker_text_ok(view, m.start(), m.end()))
                    break
            if len(findings) >= max_findings:
                return findings

    # 2. filename-conditioned and require (all-of) checks
    for ind in _COMBO:
        if len(findings) >= max_findings:
            break
        if not _check_allowed(ind, name):
            continue
        if ind.require:
            if ind.id not in candidates:
                continue
            view = None
            for candidate in views:
                if all(re.search(p.encode("utf-8"), candidate, re.IGNORECASE)
                       for p in ind.require):
                    view = candidate
                    break
            if view is None:
                continue
            first = re.search(ind.require[0].encode("utf-8"), view,
                              re.IGNORECASE)
            snippet = _snippet(view, first.start(), first.end()) if first else ""
            _emit(ind, snippet or ind.require[0],
                  text_ok=bool(first) and marker_text_ok(
                      view, first.start(), first.end()))
        elif ind.patterns:
            # file-name condition plus a content marker (e.g. .lnk + powershell)
            for view in views:
                hit = None
                for pat in ind.patterns:
                    m = re.search(pat.encode("utf-8"), view, re.IGNORECASE)
                    if m is not None:
                        hit = m
                        break
                if hit is not None:
                    _emit(ind, _snippet(view, hit.start(), hit.end()),
                          text_ok=marker_text_ok(view, hit.start(), hit.end()))
                    break
        else:
            # file-name-only check (ransomware extensions, note names)
            _emit(ind, name)
    return findings


def list_checks(category: Optional[str] = None) -> List[Indicator]:
    """All checks, optionally filtered by *category*."""
    return [ind for ind in CHECKS if category is None or ind.category == category]


def get_check(check_id: str) -> Optional[Indicator]:
    """Look up one check by id (case-insensitive)."""
    wanted = check_id.strip().lower()
    for ind in CHECKS:
        if ind.id.lower() == wanted:
            return ind
    return None


def stats() -> Dict[str, Dict[str, int]]:
    """``{category: {severity: count}}`` plus a ``total`` key."""
    out: Dict[str, Dict[str, int]] = {}
    for ind in CHECKS:
        bucket = out.setdefault(ind.category, {})
        bucket[ind.severity] = bucket.get(ind.severity, 0) + 1
    out["total"] = {"checks": len(CHECKS)}
    return out
