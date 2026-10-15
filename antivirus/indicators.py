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
       # Loopback and the unspecified address are how ordinary scripts
       # talk to a service on the same machine (health checks, sidecars);
       # flagging `curl http://127.0.0.1:8080/healthz` is a false positive.
       r"(?:curl|wget|Invoke-WebRequest|iwr|DownloadFile)\b[^\n]{0,60}https?://"
       r"(?!(?:127|0|10|192\.168|169\.254|172\.(?:1[6-9]|2[0-9]|3[01]))\b)"
       r"\d{1,3}(?:\.\d{1,3}){3}"),

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
       "File named like a ransom note (readme/decrypt/restore).  The list is "
       "deliberately made of *compound* names: a plain README.txt is not a "
       "ransom note.",
       filenames=(r"(?:readme[_-]?restore|how[_-]?to[_-]?decrypt|decrypt[_-]?instructions|"
                  r"recover[_-]?files|restore[_-]?my[_-]?files|read_me_medusa|"
                  r"readme_colp|akira_readme|\+readme-warning\+|decrypt-files|"
                  r"unlock[_-]?instructions|help[_-]?decrypt|decryption[_-]?instructions|"
                  r"how[_-]?to[_-]?restore|encrypted[_-]?files[_-]?readme|"
                  r"(?:readme|note)[_-]?(?:lockbit|blackcat|alphv|conti|revil|hive|"
                  r"royal|play|akira|medusa))",
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
# v3.0 additions – batch 1: execution & scripting hosts, document delivery.
#
# Every marker below is a *command line*, a *registry path* or a *tool
# artefact*; none is a bare English word, so the text-context gate and the
# literal prefilter keep them usable on binary input.  Where a LOLBin name
# alone would be ambiguous the pattern requires the argument that makes it
# malicious (e.g. ``msiexec`` + a remote URL).
# --------------------------------------------------------------------------
_BATCH_1: Tuple[Indicator, ...] = (

    # ------------------------------------------------------------ execution
    _i("IND-EXEC-CONHOST-HEADLESS", "conhost headless execution",
       "execution", "medium",
       "conhost.exe run with --headless, a known way to spawn a console "
       "process without a visible window.",
       r"conhost(?:\.exe)?[^\n]{0,40}--headless",
       tags=("lolbin", "execution")),
    _i("IND-EXEC-DESKTOPIMG-DOWNLOAD", "desktopimgdownldr download",
       "execution", "high",
       "desktopimgdownldr.exe (a signed Windows binary) told to fetch a "
       "remote file.",
       r"desktopimgdownldr[^\n]{0,60}(?:/lockscreenurl|/url)",
       tags=("lolbin", "download")),
    _i("IND-EXEC-ESENTUTL-COPY", "esentutl file copy abuse",
       "execution", "medium",
       "esentutl.exe used to copy a locked file — a common way to steal "
       "databases and registry hives.",
       r"esentutl(?:\.exe)?[^\n]{0,50}(?:/y|/vss|/m\s)",
       tags=("lolbin", "credential")),
    _i("IND-EXEC-EXTRAC32-CAB", "extrac32 cabinet extraction",
       "execution", "medium",
       "extrac32.exe unpacking a .cab archive (often used to drop a payload "
       "that other tools would flag).",
       r"extrac32(?:\.exe)?[^\n]{0,80}\.cab",
       tags=("lolbin", "staging")),
    _i("IND-EXEC-FTP-SCRIPT", "ftp scripted transfer",
       "execution", "medium",
       "ftp.exe driven by a script file (-s:) — a quiet way to move files "
       "without PowerShell.",
       r"ftp(?:\.exe)?[^\n]{0,30}-s:[^\n]{0,40}",
       tags=("lolbin", "transfer")),
    _i("IND-EXEC-FORFILES", "forfiles command execution",
       "execution", "medium",
       "forfiles.exe /c spawning another process — documented LOLBin for "
       "running commands from a signed binary.",
       r"forfiles[^\n]{0,50}/c\s",
       tags=("lolbin", "execution")),
    _i("IND-EXEC-MSIEXEC-REMOTE", "msiexec remote package",
       "execution", "high",
       "msiexec installing a package from a URL or UNC path.",
       r"msiexec(?:\.exe)?[^\n]{0,90}(?:https?://|//[a-z0-9.-]+/|\\\\[a-z0-9.-]+\\)",
       tags=("lolbin", "execution")),
    _i("IND-EXEC-NTDSUtil", "ntdsutil directory extraction",
       "execution", "critical",
       "ntdsutil used to create or mount an Active Directory database copy "
       "(credential dumping at domain scale).",
       r"ntdsutil[^\n]{0,70}(?:ifm|activate instance|ac i ntds)",
       tags=("credential", "lolbin")),
    _i("IND-EXEC-PNPUTIL-DRIVER", "pnputil driver installation",
       "execution", "high",
       "pnputil.exe installing a driver package — a way to load a malicious "
       "kernel driver.",
       r"pnputil[^\n]{0,50}/add-driver",
       tags=("lolbin", "driver")),
    _i("IND-EXEC-PRESENTATIONHOST", "presentationhost.exe proxy execution",
       "execution", "medium",
       "presentationhost.exe launched with a command or URL (AppPath "
       "proxy-execution LOLBin).",
       r"presentationhost(?:\.exe)?[^\n]{0,70}(?:\.exe|https?://)",
       tags=("lolbin", "proxy-execution")),
    _i("IND-EXEC-SYNCAPPVPUBLISHING", "SyncAppvPublishingServer script host",
       "execution", "medium",
       "SyncAppvPublishingServer.vbs used to run a PowerShell payload from a "
       "signed VBScript host.",
       r"syncappvpublishingserver[^\n]{0,60}",
       tags=("lolbin", "execution")),
    _i("IND-EXEC-VERCLSID-COMPONENT", "verclsid COM object execution",
       "execution", "medium",
       "verclsid.exe /S /C used to instantiate a COM object — a "
       "denied-execution bypass technique.",
       r"verclsid(?:\.exe)?[^\n]{0,50}/s\s*/c\s",
       tags=("lolbin", "bypass")),
    _i("IND-EXEC-WBEMTEST", "WMI test harness execution",
       "execution", "medium",
       "wbemtest.exe — a GUI WMI client abused to run WMI queries from a "
       "signed binary.",
       r"wbemtest(?:\.exe)?[^\n]{0,60}",
       tags=("lolbin", "wmi")),
    _i("IND-EXEC-LOLBIN-PIPE", "signed-binary output piped to a shell",
       "execution", "high",
       "Output of a LOLBin is piped straight into cmd.exe or PowerShell.",
       r"(?:certutil|bitsadmin|forfiles|esentutl|pnputil|msiexec)[^\n]{0,80}\|\s*(?:cmd|powershell|pwsh)",
       tags=("lolbin", "pipe")),
    _i("IND-EXEC-INF-INSTALL", "INF file installation",
       "execution", "high",
       "DefaultInstall section executed through setupapi (right-click "
       "'Install' INF execution) — a scriptless code-execution route.",
       r"\[DefaultInstall(?:\.NT|\.NTAMD64|\.NTx86)?\]",
       tags=("execution", "inf")),
    _i("IND-EXEC-SETUPAPI-HINFSECTION", "setupapi INF execution",
       "execution", "high",
       "rundll32 setupapi InstallHinfSection invoking an INF file.",
       r"setupapi[^\n]{0,40}InstallHinfSection",
       tags=("lolbin", "execution")),
    _i("IND-EXEC-PS-REVERSE-SHELL", "PowerShell reverse shell",
       "execution", "critical",
       "PowerShell opening a TCP socket and attaching a stream to a "
       "process — the classic reverse-shell cradle.",
       r"(?:powershell|pwsh)[^\n]{0,140}(?:TcpClient|Net\.Sockets\.Sockets|System\.Net\.Sockets)",
       r"(?:TcpClient|Net\.Sockets\.Sockets)[^\n]{0,120}(?:GetStream|Start-Process)",
       tags=("powershell", "reverse-shell")),
    _i("IND-EXEC-PS-OFFENSIVE-MODULE", "offensive PowerShell module",
       "execution", "critical",
       "Names of widely used offensive PowerShell tooling "
       "(PowerSploit / Mimikatz module / Shellcode runners).",
       r"(?:Invoke-Shellcode|Invoke-ReflectivePEInjection|Invoke-DllInjection|"
       r"Invoke-Mimikatz|Out-EncryptedScript|Get-Keystrokes|Invoke-Kerberoast)",
       tags=("powershell", "tooling")),
    _i("IND-EXEC-PS-AMA", "PowerShell AMSI/AV enumeration",
       "execution", "medium",
       "PowerShell probing the antivirus/AMSI configuration before running.",
       r"(?:Get-MpPreference|Get-MpComputerStatus)[^\n]{0,60}",
       tags=("powershell", "discovery")),
    _i("IND-EXEC-PS-WMI-EXEC", "PowerShell remote WMI execution",
       "execution", "high",
       "PowerShell driving Win32_Process.Create over WMI to run code "
       "remotely or laterally.",
       r"Win32_Process[^\n]{0,60}(?:Create\(|Invoke-WmiMethod|Invoke-CimMethod)",
       tags=("powershell", "wmi", "lateral")),
    _i("IND-EXEC-WINRM-REMOTE", "WinRM remote invocation",
       "execution", "medium",
       "PowerShell remoting (Invoke-Command / New-PSSession) pointed at "
       "another host — routine for administrators, notable inside a payload "
       "or macro.",
       r"(?:Invoke-Command|New-PSSession|Enter-PSSession)[^\n]{0,80}(?:-ComputerName|-ConnectionUri|-Session)",
       tags=("powershell", "lateral")),
    _i("IND-EXEC-CSCRIPT-REMOTE", "cscript remote script",
       "execution", "high",
       "cscript.exe running a script from a URL or network share.",
       r"cscript(?:\.exe)?[^\n]{0,70}(?:https?://|\\\\[a-z0-9.-]+\\)",
       tags=("script", "download")),
    _i("IND-EXEC-WSCRIPT-REMOTE", "wscript remote script",
       "execution", "high",
       "wscript.exe running a script from a URL or network share.",
       r"wscript(?:\.exe)?[^\n]{0,70}(?:https?://|\\\\[a-z0-9.-]+\\)",
       tags=("script", "download")),
    _i("IND-EXEC-PERL-INLINE", "Perl inline payload",
       "execution", "medium",
       "Perl one-liner using sockets or executing code.",
       r"perl\s+-e[^\n]{0,90}(?:IO::Socket|Socket|system|exec|`[^`]{1,60}`)",
       tags=("script", "inline")),
    _i("IND-EXEC-RUBY-INLINE", "Ruby inline payload",
       "execution", "medium",
       "Ruby one-liner using sockets or executing code.",
       r"ruby\s+-e[^\n]{0,90}(?:TCPSocket|Socket|eval|system|%x\{)",
       tags=("script", "inline")),
    _i("IND-EXEC-PHP-INLINE", "PHP inline payload",
       "execution", "high",
       "PHP one-liner or template calling a shell/exec function with a "
       "variable.",
       r"php\s+-r[^\n]{0,80}(?:system|shell_exec|passthru|fsockopen|base64_decode)",
       tags=("php", "webshell")),
    _i("IND-EXEC-PHP-WEBSHELL-MARKER", "PHP web shell marker",
       "execution", "critical",
       "Classic web-shell request-handler idiom (eval of a request variable).",
       r"@?eval\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)",
       r"\$_(?:POST|GET|REQUEST)\s*\[[^\]]{1,30}\][^\n]{0,40}(?:system|shell_exec|passthru|exec)\s*\(",
       tags=("webshell", "php")),
    _i("IND-EXEC-NCAT-EXEC", "netcat exec / bind shell",
       "execution", "critical",
       "netcat told to execute a shell (-e) or act as a listener with a "
       "command.",
       r"\bnc(?:at)?(?:\.exe)?[^\n]{0,60}(?:-e\s+/?bin/|-e\s+cmd|--exec)",
       r"\bnc(?:at)?(?:\.exe)?[^\n]{0,40}-[lv]{1,2}[^\n]{0,20}-[lv]{1,2}[^\n]{0,20}-e\s",
       tags=("netcat", "reverse-shell")),
    _i("IND-EXEC-SOCAT-EXEC", "socat exec redirection",
       "execution", "high",
       "socat bridging a socket to a process (EXEC:).",
       r"socat[^\n]{0,80}\bexec:",
       tags=("socat", "reverse-shell")),
    _i("IND-EXEC-DEVTCP", "Bash /dev/tcp redirection",
       "execution", "high",
       "Bash opening a raw TCP connection through /dev/tcp (file-descriptor "
       "reverse shell).",
       r"/dev/(?:tcp|udp)/[0-9a-z.\-]{3,80}/[0-9]{1,5}",
       tags=("bash", "reverse-shell")),
    _i("IND-EXEC-MSFVENOM", "Metasploit payload generation",
       "execution", "high",
       "msfvenom payload generation command line.",
       r"msfvenom[^\n]{0,90}-p\s",
       tags=("tooling", "metasploit")),
    _i("IND-EXEC-MSFCONSOLE", "Metasploit console automation",
       "execution", "high",
       "msfconsole driven by a resource script or -x command.",
       r"msfconsole[^\n]{0,60}(?:-x\s|resource|/bin/msfconsole)",
       tags=("tooling", "metasploit")),
    _i("IND-EXEC-C2-ARTEFACT", "Known C2 framework artefact",
       "execution", "critical",
       "File or build artefact names belonging to widely used command-and-"
       "control frameworks.",
       r"(?:beacon\.dll|beacon\.x64\.dll|teamserver\.jar|cobaltstrike\.jar|"
       r"smb_beacon|payload\.x64\.shellcode)",
       tags=("c2", "tooling")),
    _i("IND-EXEC-SLIVER-ARTEFACT", "Sliver / Mythic implant artefact",
       "execution", "critical",
       "Artefact or operator string belonging to modern C2 frameworks "
       "(Sliver, Mythic).",
       r"(?:sliver-server|sliver-client|\.sliver/|apollo\.exe|poseidon\.bin)",
       tags=("c2", "tooling")),
    _i("IND-EXEC-BITS-JOB", "BITS transfer job",
       "execution", "medium",
       "Background Intelligent Transfer Service used to fetch a payload "
       "(survives reboots, less monitored than PowerShell).",
       r"Start-BitsTransfer[^\n]{0,70}",
       r"bitsadmin[^\n]{0,60}/transfer[^\n]{0,40}https?://",
       tags=("bits", "download")),
    _i("IND-EXEC-CMD-DELAYED-EXPANSION", "cmd delayed expansion obfuscation",
       "execution", "medium",
       "Delayed variable expansion used to build a command string at "
       "runtime (defeats naive string logging).",
       r"(?:^|\s)/v:(?:on|off)[^\n]{0,120}![\w~@#$%^&*()\-]{1,40}!",
       tags=("cmd", "obfuscation")),
    _i("IND-EXEC-SET-PATH-HIJACK", "current-directory PATH hijack",
       "execution", "high",
       "Script prepends . or the working directory to PATH, so a dropped "
       "binary shadows system tools.",
       r"(?:PATH|Path)\s*=\s*[\"']?\.\s*[:;]",
       r"(?:set|export)\s+PATH\s*=\s*%?CD%?[;:]",
       tags=("path", "hijack")),
    _i("IND-EXEC-RUNDLL32-MSI", "rundll32 MSI/advpack abuse",
       "execution", "high",
       "rundll32 invoking advpack/ieadvpack/MSI entry points to install a "
       "dropped package.",
       r"rundll32[^\n]{0,80}(?:advpack|ieadvpack|msi\.dll|pcwutl)",
       tags=("lolbin", "rundll32")),
    _i("IND-EXEC-ODBC-DRIVER-EXEC", "ODBC/EXCEL driver execution",
       "execution", "medium",
       "Excel/ODBC driver functions invoked outside Excel (process "
       "injection through a signed library).",
       r"(?:Excel\.exe|excel\.exe)[^\n]{0,60}--headless",
       tags=("excel", "execution")),
    _i("IND-EXEC-DOTNET-LOAD-REMOTE", "Remote .NET assembly load",
       "execution", "high",
       ".NET assembly loaded from a URL or byte array (in-memory execution "
       "of a downloaded payload).",
       r"(?:Assembly\.Load|LoadFrom|Reflection\.Assembly)[^\n]{0,80}(?:http|DownloadData|DownloadString|FromBase64String)",
       tags=("dotnet", "in-memory")),
    _i("IND-EXEC-CERTUTIL-ENCODE-EXEC", "certutil output executed",
       "execution", "high",
       "certutil decode output piped into a shell or executable.",
       r"certutil[^\n]{0,90}-decode[^\n]{0,60}(?:\||&&|;)[^\n]{0,40}(?:cmd|powershell|/bin/sh|bash)",
       tags=("lolbin", "execution")),
    _i("IND-EXEC-JS-RUNTIME-EXEC", "Node/Deno one-liner execution",
       "execution", "medium",
       "Node or Deno invoked with an inline script that shells out or opens "
       "a socket.",
       r"(?:node|deno)[^\n]{0,20}(?:-e|eval)[^\n]{0,90}(?:child_process|require\('net'\)|Deno\.run|exec\()",
       tags=("node", "inline")),
    _i("IND-EXEC-JAVA-INLINE", "Java inline execution",
       "execution", "medium",
       "Java source/class execution from a one-liner or an in-memory "
       "payload (common in exploit chains).",
       r"java[^\n]{0,40}(?:-jar\s+\S+\.jar|\s+sun\.tools\.script\.Main)",
       tags=("java", "execution")),

    # --------------------------------------------------------------- office
    _i("IND-OFFICE-HTA-LAUNCHER", "HTA launcher content",
       "office", "high",
       "HTML Application header plus script that runs a command — delivered "
       "as .hta or through mshta.",
       r"<hta:application",
       r"<script[^>]{0,40}language\s*=\s*[\"']?VBScript[\"']?[^\n]{0,200}(?:CreateObject|WScript\.Shell)",
       tags=("hta", "delivery")),
    _i("IND-OFFICE-REMOTE-TEMPLATE", "Remote document template",
       "office", "critical",
       "Document pulls its template from a remote URL (template-injection "
       "delivery of macros over HTTP).",
       r"attachedTemplate[^\n]{0,80}https?://",
       r"(?:TargetFrame|Template)[^\n]{0,40}https?://[^\s\"'<>]{6,120}\.(?:dotm|dotx|docm|docx)",
       tags=("office", "template")),
    _i("IND-OFFICE-ONENOTE-EMBED", "OneNote embedded payload",
       "office", "high",
       "OneNote document embedding a script/executable payload (a current "
       "delivery favourite).",
       r"\.one[^\n]{0,40}(?:WScript\.Shell|cmd\.exe|powershell)",
       r"(?:onenote|OneNote)[^\n]{0,60}(?:\.bat|\.cmd|\.lnk|\.hta)",
       tags=("onenote", "delivery")),
    _i("IND-OFFICE-EQUATION-EXPLOIT", "Equation Editor exploit marker",
       "office", "critical",
       "Object header for the legacy Microsoft Equation Editor "
       "(CVE-2017-11882 and friends).",
       r"Equation\.3",
       r"Equation Native",
       tags=("office", "exploit")),
    _i("IND-OFFICE-OLE-EMBEDDED", "Embedded OLE package object",
       "office", "high",
       "Document embedding a package object that runs a command when "
       "double-clicked.",
       r"OLE2Link[^\n]{0,80}(?:\.exe|\.bat|\.cmd)",
       r"(?:ObjectPool|Packager)[^\n]{0,60}cmd\.exe",
       tags=("office", "embed")),
    _i("IND-OFFICE-RTF-EXPLOIT", "RTF exploit structure",
       "office", "high",
       "RTF containing an OLE object control word used by exploit chains.",
       r"\\obj(?:update|class|emb)",
       r"\\objdata[^\n]{0,80}",
       tags=("rtf", "exploit")),
)

CHECKS = CHECKS + _BATCH_1


_BATCH_2: Tuple[Indicator, ...] = (

    # -------------------------------------------------------------- evasion
    _i("IND-EVADE-AMSI-PATCH", "AMSI scan function patched",
       "evasion", "critical",
       "amsi.dll / AmsiScanBuffer patched or hooked to make script scanning "
       "always return 'clean'.",
       r"AmsiScanBuffer[^\n]{0,70}(?:patch|ret|hook|nop|WriteProcessMemory|VirtualProtect)",
       tags=("amsi", "evasion")),
    _i("IND-EVADE-ETW-PATCH", "ETW provider patched",
       "evasion", "high",
       "EtwEventWrite / NtTraceEvent neutralised so telemetry stops flowing.",
       r"(?:EtwEventWrite|NtTraceEvent)[^\n]{0,70}(?:patch|ret\b|nop|hook|WriteProcessMemory)",
       tags=("etw", "evasion")),
    _i("IND-EVADE-NTDLL-UNHOOK", "ntdll unhooking",
       "evasion", "high",
       "A fresh copy of ntdll is mapped or written over the loaded one to "
       "remove EDR userland hooks.",
       r"(?:NtProtectVirtualMemory|NtWriteVirtualMemory|NtMapViewOfSection)[^\n]{0,90}ntdll",
       r"(?:ntdll\.dll)[^\n]{0,60}(?:PAGE_EXECUTE_READWRITE|0x40)[^\n]{0,40}(?:write|memcpy)",
       tags=("edr", "evasion")),
    _i("IND-EVADE-DEFENDER-EXCLUSION", "Defender exclusion added",
       "evasion", "critical",
       "A path/process/extension is added to the Windows Defender exclusion "
       "list so the payload is never scanned.",
       r"Add-MpPreference[^\n]{0,80}-Exclusion(?:Path|Process|Extension|IpAddress)",
       r"(?:Set|Add)-MpPreference[^\n]{0,60}ExclusionPath",
       tags=("defender", "evasion")),
    _i("IND-EVADE-DEFENDER-DISABLE-PS", "Defender features disabled",
       "evasion", "critical",
       "Defender real-time / behaviour / script / network protection turned "
       "off through PowerShell.",
       r"Set-MpPreference[^\n]{0,80}-Disable(?:RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|BlockAtFirstSeen|NetworkProtection)",
       tags=("defender", "evasion")),
    _i("IND-EVADE-DEFENDER-SERVICE-STOP", "Security service stopped",
       "evasion", "high",
       "Defender-related Windows services stopped or reconfigured.",
       r"(?:net|sc)(?:\.exe)?[^\n]{0,30}stop[^\n]{0,40}(?:WinDefend|WdNisSvc|Sense|MsMpSvc|SecurityHealthService)",
       r"Stop-Service[^\n]{0,40}(?:WinDefend|WdNisSvc|Sense|MsMpSvc)",
       tags=("defender", "evasion")),
    _i("IND-EVADE-FIREWALL-RULE-ALLOW", "Firewall rule opened",
       "evasion", "high",
       "An inbound/outbound allow rule is added (often for a backdoor port).",
       r"netsh[^\n]{0,40}advfirewall[^\n]{0,60}add[^\n]{0,40}rule[^\n]{0,60}action\s*=\s*allow",
       tags=("firewall", "evasion")),
    _i("IND-EVADE-FIREWALL-PS", "Firewall rule added via PowerShell",
       "evasion", "high",
       "New-NetFirewallRule / Set-NetFirewallProfile used to open access.",
       r"New-NetFirewallRule[^\n]{0,80}-Action\s+Allow",
       r"Set-NetFirewallProfile[^\n]{0,60}-Enabled\s+(?:False|0)",
       tags=("firewall", "evasion")),
    _i("IND-EVADE-EVENTLOG-DISABLE", "Event log service disabled",
       "evasion", "high",
       "The Windows event log service is reconfigured to not start, so "
       "activity is never recorded.",
       r"sc(?:\.exe)?[^\n]{0,30}config[^\n]{0,40}(?:EventLog|EventSystem)[^\n]{0,30}start\s*=\s*disabled",
       tags=("logging", "evasion")),
    _i("IND-EVADE-BCDEDIT-SAFEBOOT", "Safe-mode boot configured",
       "evasion", "high",
       "BCD store set to boot into safe mode — used to run ransomware or an "
       "AV-killer with security software unloaded.",
       r"bcdedit[^\n]{0,70}/set[^\n]{0,40}\{?current\}?[^\n]{0,30}safeboot",
       tags=("bcd", "evasion")),
    _i("IND-EVADE-BCDEDIT-RECOVERY", "Boot recovery disabled",
       "evasion", "high",
       "Boot recovery / failure reporting switched off so the system boots "
       "into the encrypted state.",
       r"bcdedit[^\n]{0,80}(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures|ignoreallfailures)",
       tags=("bcd", "evasion")),
    _i("IND-EVADE-WBADMIN-DELETE", "Backup catalog deleted",
       "evasion", "critical",
       "Windows Backup catalog / system-state backups deleted (removes the "
       "victim's ability to restore).",
       r"wbadmin[^\n]{0,80}delete[^\n]{0,50}(?:catalog|systemstatebackup|backup)",
       tags=("backup", "evasion")),
    _i("IND-EVADE-CIPHER-WIPE", "Free-space wiping",
       "evasion", "medium",
       "cipher /w overwrites deleted data — used to make forensic recovery "
       "harder.",
       r"cipher(?:\.exe)?[^\n]{0,60}/w(?::|\s)",
       tags=("anti-forensics", "evasion")),
    _i("IND-EVADE-SDELETE", "SDelete secure deletion",
       "evasion", "medium",
       "Sysinternals SDelete used with its overwrite flags.",
       r"sdelete(?:64)?(?:\.exe)?[^\n]{0,70}(?:-[pq]\b|\s-p\s|\s-q\s)",
       tags=("anti-forensics", "evasion")),
    _i("IND-EVADE-USNJRNL-DELETE", "USN journal deleted",
       "evasion", "high",
       "The NTFS change journal is deleted to destroy file-operation history.",
       r"fsutil[^\n]{0,60}usn[^\n]{0,30}deletejournal",
       tags=("anti-forensics", "evasion")),
    _i("IND-EVADE-PREFETCH-DELETE", "Prefetch evidence deleted",
       "evasion", "high",
       "Prefetch files removed to hide which programs ran.",
       r"(?:del|erase|Remove-Item)[^\n]{0,80}(?:\\\\Prefetch\\\\|/Prefetch/|C:\\Windows\\Prefetch)",
       tags=("anti-forensics", "evasion")),
    _i("IND-EVADE-ANALYSIS-TOOL-ENUM", "Analysis-tool process scan",
       "evasion", "high",
       "The process list is enumerated looking for analysis tools (Wireshark,"
       " Procmon, debuggers) before continuing.",
       r"(?:CreateToolhelp32Snapshot|Process32(?:First|Next)|EnumProcesses)[^\n]{0,160}(?:wireshark|procmon|procexp|ollydbg|x64dbg|idaq|fiddler|dnSpy)",
       tags=("anti-analysis", "evasion")),
    _i("IND-EVADE-SANDBOX-USERNAME", "Sandbox user-name check",
       "evasion", "high",
       "The current user name is compared against common sandbox accounts.",
       r"(?:GetUserName|USERNAME|UserName)[^\n]{0,90}(?:sandbox|malware|virus|cuckoo|wdag|analyst|maltest)",
       tags=("anti-analysis", "evasion")),
    _i("IND-EVADE-LONG-SLEEP-API", "Very long sleep before execution",
       "evasion", "medium",
       "A multi-minute sleep/delay — the classic way to outlive an "
       "automated sandbox run.",
       r"(?:NtDelayExecution|Sleep|sleep)\s*\(?[^\n]{0,20}(?:3[0-9]{5}|[4-9][0-9]{5}|[0-9]{7,})\b",
       tags=("anti-analysis", "evasion")),
    _i("IND-EVADE-CPU-CORE-CHECK", "CPU core count check",
       "evasion", "medium",
       "The number of processors is compared to a small constant (1-2 "
       "cores = likely virtual machine).",
       r"(?:GetSystemInfo|NumberOfProcessors|dwNumberOfProcessors|os\.cpu_count)[^\n]{0,70}(?:[<>=]=?\s*[12]\b|cpu_count\(\)\s*[<>=]=?\s*[12])",
       tags=("anti-analysis", "evasion")),
    _i("IND-EVADE-RAM-SIZE-CHECK", "Physical memory size check",
       "evasion", "medium",
       "Total RAM compared against a small threshold (sandboxes are usually "
       "given 1-2 GB).",
       r"(?:GlobalMemoryStatusEx|TotalPhysicalMemory|ullTotalPhys|MemTotal)[^\n]{0,90}(?:[<>=]=?\s*\d{6,}|[<>=]=?\s*\d+\s*\*\s*1024)",
       tags=("anti-analysis", "evasion")),
    _i("IND-EVADE-VM-MAC-OUI", "Virtualisation MAC address",
       "evasion", "medium",
       "MAC-address prefixes belonging to VMware / VirtualBox / Xen / "
       "Hyper-V adapters are hard-coded.",
       r"(?:08:00:27|00:05:69|00:0C:29|00:1C:14|00:50:56|00:15:5D|52:54:00|00:16:3E)",
       tags=("anti-analysis", "evasion")),
    _i("IND-EVADE-ANTI-DISASM", "Anti-disassembly API probe",
       "evasion", "medium",
       "Debug flags queried through the native API (heavier than "
       "IsDebuggerPresent, used to defeat automated unpacking).",
       r"(?:ProcessDebugFlags|ProcessDebugPort|ProcessDebugObjectHandle)[^\n]{0,40}",
       tags=("anti-analysis", "evasion")),
    _i("IND-EVADE-DLL-SIDELOAD-PATH", "DLL loaded from a user-writable path",
       "evasion", "medium",
       "A module is loaded from AppData/Temp/ProgramData — the usual "
       "side-loading drop location.",
       r"(?:LoadLibrary|dlopen)[^\n]{0,80}(?:AppData|Temp\\\\|ProgramData|/tmp/)",
       tags=("dll", "evasion")),
    _i("IND-EVADE-SETDLLDIRECTORY", "DLL search path hijacked",
       "evasion", "medium",
       "SetDllDirectory / AddDllDirectory pointed at a writable directory so "
       "a planted DLL wins the search.",
       r"(?:SetDllDirectory|AddDllDirectory)[^\n]{0,60}(?:AppData|Temp|ProgramData|current)",
       tags=("dll", "evasion")),
    _i("IND-EVADE-LD-PRELOAD", "Dynamic linker preload",
       "evasion", "high",
       "LD_PRELOAD / LD_LIBRARY_PATH used to inject a shared object into "
       "another program.",
       r"(?:LD_PRELOAD|LD_LIBRARY_PATH)\s*=\s*[^\s;]{3,120}",
       tags=("linux", "injection")),
    _i("IND-EVADE-KERNEL-MODULE-LOAD", "Kernel module load",
       "evasion", "critical",
       "insmod/modprobe loading a kernel object — rootkit installation.",
       r"(?:insmod|modprobe)[^\n]{0,60}\S+\.ko\b",
       tags=("linux", "rootkit")),
    _i("IND-EVADE-AUDIT-DISABLE", "Linux audit disabled",
       "evasion", "high",
       "The kernel audit subsystem is switched off (auditctl -e 0) or the "
       "auditd service stopped.",
       r"auditctl\s+-e\s*0",
       r"(?:systemctl|service)\s+stop\s+auditd",
       tags=("linux", "evasion")),
    _i("IND-EVADE-SELINUX-PERMISSIVE", "SELinux set to permissive",
       "evasion", "medium",
       "setenforce 0 disables SELinux enforcement.",
       r"setenforce\s+0",
       tags=("linux", "evasion")),
    _i("IND-EVADE-HISTORY-CLEAR", "Shell history destroyed",
       "evasion", "medium",
       "HISTFILE redirected to /dev/null or the history file deleted.",
       r"HISTFILE\s*=\s*/dev/null",
       r"(?:rm|shred|truncate)[^\n]{0,40}\.bash_history",
       r"unset\s+HISTFILE",
       tags=("linux", "anti-forensics")),
    _i("IND-EVADE-LOG-WIPE-LINUX", "Linux log wipe",
       "evasion", "high",
       "System logs truncated or deleted (dmesg -c, /var/log removal, "
       "journal vacuum).",
       r"dmesg\s+-c\b",
       r"(?:rm\s+-rf?|shred|truncate\s+-s\s*0)\s+/var/log",
       r":\s*>\s*/var/log/[^\s]+",
       tags=("linux", "anti-forensics")),
    _i("IND-EVADE-MEMFD-EXEC", "Fileless execution on Linux",
       "evasion", "high",
       "memfd_create + fexecve (or executing through /proc/self/fd) runs a "
       "payload without ever writing it to disk.",
       r"memfd_create[^\n]{0,80}(?:fexecve|execve|/proc/self/fd)",
       r"(?:fexecve|execve)\([^\n]{0,40}/proc/self/fd/[0-9]+",
       tags=("linux", "fileless")),
    _i("IND-EVADE-MACOS-GATEKEEPER", "macOS Gatekeeper bypass",
       "evasion", "high",
       "Gatekeeper/quarantine controls disabled so an unsigned binary runs "
       "without a prompt.",
       r"spctl\s+--master-disable",
       r"xattr\s+-[dr]{1,2}\s+com\.apple\.quarantine",
       r"defaults\s+write\s+com\.apple\.quarantine[^\n]{0,60}(?:false|0)",
       tags=("macos", "evasion")),
    _i("IND-EVADE-MACOS-TCC", "macOS TCC database manipulation",
       "evasion", "critical",
       "Privacy (TCC) permissions reset or edited directly — granting access "
       "to camera, microphone, disk or automation without a prompt.",
       r"tccutil\s+reset",
       r"sqlite3[^\n]{0,80}TCC\.db",
       tags=("macos", "evasion")),
    _i("IND-EVADE-PACKER-MARKER", "Executable packer section",
       "evasion", "medium",
       "Section names left by common packers/protectors (UPX, MPRESS, "
       "ASPack, PECompact, Themida).",
       r"(?:UPX0|UPX1|UPX2|\.MPRESS1|\.MPRESS2|\.aspack|\.adata|PEC2|\.themida|\.vmp0|\.vmp1)",
       tags=("packer", "evasion")),
    _i("IND-EVADE-PAGE-EXECUTE-RW", "Writable+executable memory",
       "evasion", "high",
       "Memory protection flipped to PAGE_EXECUTE_READWRITE — the standard "
       "step before running in-memory shellcode.",
       r"(?:VirtualProtect|VirtualProtectEx|NtProtectVirtualMemory)[^\n]{0,90}(?:PAGE_EXECUTE_READWRITE|0x40)",
       tags=("injection", "evasion")),
    _i("IND-EVADE-PROCESS-HOLLOWING", "Process hollowing API sequence",
       "evasion", "critical",
       "A suspended process image is unmapped and replaced — process "
       "hollowing.",
       r"(?:NtUnmapViewOfSection|ZwUnmapViewOfSection)[^\n]{0,60}",
       r"(?:CreateProcess|CreateProcessInternal)[^\n]{0,80}CREATE_SUSPENDED[^\n]{0,120}(?:UnmapView|WriteProcessMemory)",
       tags=("injection", "evasion")),
    _i("IND-EVADE-EARLYBIRD-APC", "APC injection (early bird)",
       "evasion", "high",
       "QueueUserAPC combined with a suspended process — APC injection.",
       r"(?:QueueUserAPC|NtQueueApcThread)[^\n]{0,90}(?:CREATE_SUSPENDED|ResumeThread|CreateProcess)",
       tags=("injection", "evasion")),
    _i("IND-EVADE-CREATE-REMOTE-THREAD", "Remote thread creation",
       "evasion", "high",
       "CreateRemoteThread/NtCreateThreadEx against another process.",
       r"(?:CreateRemoteThread|NtCreateThreadEx)[^\n]{0,90}(?:LoadLibrary|WriteProcessMemory|VirtualAllocEx|target)",
       tags=("injection", "evasion")),
    _i("IND-EVADE-WRITE-PROCESS-MEMORY", "Cross-process memory write",
       "evasion", "high",
       "WriteProcessMemory paired with an allocation in another process.",
       r"WriteProcessMemory[^\n]{0,90}(?:VirtualAllocEx|CreateRemoteThread|shellcode)",
       tags=("injection", "evasion")),
    _i("IND-EVADE-SHELLCODE-LOADER", "In-memory shellcode loader",
       "evasion", "critical",
       "Allocate, write, then execute a byte buffer — the shellcode-loading "
       "pattern used by almost every loader.",
       r"(?:VirtualAlloc|VirtualAllocEx|mmap)[^\n]{0,60}(?:PAGE_EXECUTE_READWRITE|PROT_EXEC)[^\n]{0,80}(?:memcpy|RtlMoveMemory|memmove)",
       r"(?:unsigned\s+char|BYTE)\s+\w{1,24}\[\]\s*=\s*\{[^\}]{200,}\}",
       tags=("shellcode", "injection")),
    _i("IND-EVADE-RECENT-DOCS-CLEAR", "User activity trails cleared",
       "evasion", "medium",
       "Jump lists / Recent / RunMRU history deleted to hide what was opened.",
       r"(?:del|erase|Remove-Item)[^\n]{0,90}(?:AutomaticDestinations|CustomDestinations|\\\\Recent\\\\|RunMRU|TypedPaths)",
       tags=("anti-forensics", "evasion")),
    _i("IND-EVADE-DRIVER-ABUSE-NAME", "Abusable signed driver name",
       "evasion", "high",
       "Driver names routinely dropped to bypass kernel-mode protections or "
       "kill security software.",
       r"(?:PROCEXP152|PROCMON2[0-9]|SysmonDrv|WinRing0|dbk64|kdu\.sys|iqvw64e)",
       tags=("driver", "edr-killer")),
    _i("IND-EVADE-FIREWALL-POLICY-OFF", "Firewall profile turned off",
       "evasion", "high",
       "All firewall profiles set to off (netsh or PowerShell).",
       r"netsh[^\n]{0,50}advfirewall[^\n]{0,50}set[^\n]{0,40}(?:firewallpolicy|allprofiles)[^\n]{0,30}off",
       tags=("firewall", "evasion")),
    _i("IND-EVADE-UAC-AUTO-ELEVATE", "Auto-elevating binary abuse",
       "evasion", "high",
       "Known auto-elevate binaries (fodhelper, computerdefaults, sdclt, "
       "slui, wusa) invoked to get admin without a UAC prompt; the registry "
       "key below is the classic ms-settings hijack.",
       # Requires the .exe, an invoked payload path, or the hijacked class
       # key — a bare five-letter word inside binary data must not match.
       r"(?:fodhelper|computerdefaults|sdclt|slui|wusa)\.exe\b",
       r"(?:fodhelper|computerdefaults|sdclt|slui|wusa)\b[^\n]{0,60}(?:\\\\|/)"
       r"[A-Za-z0-9._-]{2,40}\.(?:exe|dll|bat|cmd|ps1|vbs)",
       r"(?:ms-settings|Folder)\\\\shell\\\\open\\\\command",
       tags=("uac", "elevation")),
    _i("IND-EVADE-TOKEN-PRIVILEGE", "Token privilege manipulation",
       "evasion", "high",
       "AdjustTokenPrivileges enabling SeDebugPrivilege or similar — "
       "privilege escalation footwork.",
       r"AdjustTokenPrivileges[^\n]{0,90}(?:SeDebugPrivilege|SeImpersonatePrivilege|SeTcbPrivilege|SeBackupPrivilege)",
       tags=("privilege", "escalation")),
    _i("IND-EVADE-SUDOERS-NOPASSWD", "Passwordless sudo granted",
       "evasion", "critical",
       "A sudoers entry with NOPASSWD (or a broad ALL rule) added for a "
       "user.",
       r"NOPASSWD\s*:",
       r"/etc/sudoers[^\n]{0,40}(?:>|>>|\|\s*tee)",
       tags=("linux", "escalation")),
    _i("IND-EVADE-SUID-BIT", "SUID/SGID bit applied",
       "evasion", "medium",
       "chmod granting the SUID or SGID bit — a very common Linux privilege "
       "escalation.",
       r"chmod\s+(?:[ugo]*\+?s|4[0-7]{3}|2[0-7]{3})\b[^\n]{0,60}",
       tags=("linux", "escalation")),
    _i("IND-EVADE-CAPABILITY-SET", "Linux capability manipulation",
       "evasion", "medium",
       "setcap used to grant a file elevated capabilities (e.g. "
       "cap_sys_admin, cap_net_raw).",
       r"setcap\s+[a-z_,]*(?:cap_sys_admin|cap_net_raw|cap_dac_read_search|cap_setuid|ep)\b",
       tags=("linux", "escalation")),
)

CHECKS = CHECKS + _BATCH_2


_BATCH_3: Tuple[Indicator, ...] = (

    # ---------------------------------------------------------- persistence
    _i("IND-PERSIST-RUNONCE", "RunOnce autostart",
       "persistence", "high",
       "RunOnce keys execute a command exactly once at logon — the usual "
       "'first stage' autostart.",
       r"CurrentVersion\\\\RunOnce(?:Ex)?\b",
       tags=("registry", "autostart")),
    _i("IND-PERSIST-SHELL-OPEN-COMMAND", "File-association hijack",
       "persistence", "high",
       "shell\\open\\command for a file class rewritten (e.g. .txt or .exe "
       "now runs a script).",
       r"shell\\\\open\\\\command",
       tags=("registry", "hijack")),
    _i("IND-PERSIST-COM-HIJACK", "COM object hijack",
       "persistence", "high",
       "A CLSID's InprocServer32 handler redirected to a dropped DLL, often "
       "inside HKCU\\Software\\Classes.",
       r"Software\\\\Classes\\\\CLSID\\\\\{[0-9A-Fa-f-]{36}\}\\\\InprocServer32",
       r"CLSID\\\\\{[0-9A-Fa-f-]{36}\}\\\\InprocServer32",
       tags=("com", "hijack")),
    _i("IND-PERSIST-USERINIT", "Userinit replaced",
       "persistence", "critical",
       "The Userinit logon value points at something other than userinit.exe.",
       r"Winlogon[^\n]{0,80}Userinit[^\n]{0,60}\\\\",
       tags=("registry", "logon")),
    _i("IND-PERSIST-BOOT-EXECUTE", "BootExecute native app",
       "persistence", "critical",
       "Session Manager BootExecute entries run a native program before "
       "Windows starts — used by bootkits and wipers.",
       r"BootExecute(?:[^\n]{0,80}\\\\)?",
       tags=("registry", "bootkit")),
    _i("IND-PERSIST-PENDING-RENAME", "Pending file rename",
       "persistence", "high",
       "PendingFileRenameOperations schedules a file move at next boot (a "
       "way to drop a payload into a protected path).",
       r"PendingFileRenameOperations",
       tags=("registry", "staging")),
    _i("IND-PERSIST-LSA-PACKAGE", "LSA security package",
       "persistence", "critical",
       "An extra authentication package or security package registered with "
       "LSA — runs in lsass and survives reboots.",
       r"(?:Security Packages|Authentication Packages)[^\n]{0,120}",
       r"Control\\\\Lsa[^\n]{0,60}(?:Security|Authentication)\s*Packages",
       tags=("registry", "lsa")),
    _i("IND-PERSIST-PRINT-MONITOR", "Print monitor DLL",
       "persistence", "high",
       "A print monitor DLL registered under the print spooler — loads "
       "inside spoolsv.exe.",
       r"Print\\\\Monitors\\\\",
       tags=("registry", "print")),
    _i("IND-PERSIST-PRINT-PROCESSOR", "Print processor DLL",
       "persistence", "high",
       "A print processor registered to run attacker code inside the "
       "spooler service.",
       r"Print\\\\Processors\\\\",
       tags=("registry", "print")),
    _i("IND-PERSIST-TIME-PROVIDER", "Time provider DLL",
       "persistence", "high",
       "A W32Time service provider DLL (documented, spooler-independent "
       "persistence).",
       r"(?:TimeProviders|W32Time)[^\n]{0,80}\.dll",
       tags=("registry", "service")),
    _i("IND-PERSIST-DNS-PLUGIN", "DNS client plugin DLL",
       "persistence", "high",
       "A plugin DLL for the DNS client service — loaded into every "
       "process that resolves names.",
       r"DNS Client[^\n]{0,80}(?:ServerLevelPluginDll|\.dll)",
       r"ServerLevelPluginDll",
       tags=("registry", "dns")),
    _i("IND-PERSIST-NETSH-HELPER", "netsh helper DLL",
       "persistence", "high",
       "A netsh helper DLL registered (netsh add helper) so the library "
       "loads whenever netsh runs.",
       r"netsh[^\n]{0,40}add[^\n]{0,20}helper",
       r"NetSh\\\\HelperDLLs",
       tags=("netsh", "registry")),
    _i("IND-PERSIST-WINSOCK-LSP", "Winsock layered provider",
       "persistence", "high",
       "A Winsock LSP/dummy provider inserted into the TCP/IP stack chain.",
       r"(?:NSProvider|Protocol_Catalog9)[^\n]{0,80}\\\\",
       tags=("registry", "network")),
    _i("IND-PERSIST-CREDENTIAL-PROVIDER", "Credential provider registered",
       "persistence", "critical",
       "A custom credential provider DLL added to the logon UI — harvests "
       "passwords at every logon.",
       r"Credential Provider(?:s)?[^\n]{0,80}\\\\",
       r"\\{?:?[0-9A-Fa-f-]{36}\}?[^\n]{0,40}CredentialProviders",
       tags=("registry", "credential")),
    _i("IND-PERSIST-PASSWORD-FILTER", "Password filter DLL",
       "persistence", "critical",
       "A Notification Packages entry means the DLL sees every password "
       "change in clear text.",
       r"Notification Packages",
       tags=("registry", "credential")),
    _i("IND-PERSIST-SCREENSAVER", "Screensaver hijack",
       "persistence", "medium",
       "SCRNSAVE.EXE repointed at a payload (runs on idle).",
       r"Control Panel\\\\Desktop[^\n]{0,80}SCRNSAVE\.EXE",
       r"SCRNSAVE\.EXE[^\n]{0,60}\.exe",
       tags=("registry", "autostart")),
    _i("IND-PERSIST-ACTIVE-SETUP", "Active Setup entry",
       "persistence", "high",
       "Active Setup\\Installed Components runs a StubPath for every user "
       "profile at logon.",
       r"Active Setup\\\\Installed Components",
       tags=("registry", "logon")),
    _i("IND-PERSIST-BITS-NOTIFY", "BITS notification command",
       "persistence", "high",
       "A BITS job's notification command line executes when the transfer "
       "completes — reboot-surviving persistence.",
       r"NotifyCmdLine",
       tags=("bits", "persistence")),
    _i("IND-PERSIST-SERVICE-DLL", "svchost service DLL",
       "persistence", "critical",
       "A service registers a ServiceDll to be loaded by svchost.exe.",
       r"Parameters[^\n]{0,40}ServiceDll",
       r"ServiceDll[^\n]{0,80}\.dll",
       tags=("service", "dll")),
    _i("IND-PERSIST-KERNEL-DRIVER", "Kernel driver service",
       "persistence", "critical",
       "A service whose ImagePath is a .sys driver (kernel-mode "
       "persistence / rootkit).",
       r"Services\\\\[^\\\n]{1,60}\\\\ImagePath[^\n]{0,80}\.sys",
       r"ImagePath[^\n]{0,80}System32\\\\drivers\\\\[^\n]{0,60}\.sys",
       tags=("driver", "registry")),
    _i("IND-PERSIST-OFFICE-ADDIN", "Office add-in registration",
       "persistence", "high",
       "An Office add-in registered with LoadBehavior=3/9 so it runs with "
       "Word or Excel.",
       r"(?:Word|Excel|Outlook|PowerPoint)\\\\Addins[^\n]{0,120}",
       r"LoadBehavior[^\n]{0,40}(?:3|9|0x3|0x9)",
       tags=("office", "registry")),
    _i("IND-PERSIST-OUTLOOK-FORM", "Outlook VBA / form hijack",
       "persistence", "high",
       "Outlook VbaProject or form registry keys rewritten to run macro "
       "code at startup.",
       r"Outlook[^\n]{0,60}VbaProject",
       r"\\{?:?[0-9A-Fa-f-]{36}\}?\\\\VbaProject",
       tags=("office", "macro")),
    _i("IND-PERSIST-BROWSER-EXTENSION", "Browser extension persistence",
       "persistence", "medium",
       "A Chromium extension folder registered as a startup/forced-loaded "
       "extension.",
       r"Secure Preferences",
       r"Extensions[^\n]{0,80}(?:update_url|external)",
       tags=("browser", "extension")),
    _i("IND-PERSIST-GIT-HOOK", "Git hook persistence",
       "persistence", "medium",
       "A git hook script written into a repository — runs on commit, "
       "checkout or push (developer-machine persistence).",
       r"\.git/hooks/(?:pre-commit|post-commit|post-checkout|pre-push|update)",
       tags=("developer", "hook")),
    _i("IND-PERSIST-PROFILE-D", "Profile script drop",
       "persistence", "high",
       "A new script is written into /etc/profile.d, so it runs for every "
       "interactive login.",
       r"/etc/profile\.d/[^\s]{1,40}",
       tags=("linux", "logon")),
    _i("IND-PERSIST-BASHRC-EXEC", "Shell rc file payload",
       "persistence", "high",
       "A command appended to .bashrc/.zshrc that survives every new shell.",
       r"(?:>>?\s*[^\n]{0,20}~?/\.(?:bashrc|zshrc|bash_profile|profile))[^\n]{0,120}",
       r"(?:curl|wget|nc|/dev/tcp)[^\n]{0,60}>>\s*[^\n]{0,20}\.(?:bashrc|zshrc|profile)",
       tags=("linux", "shell")),
    _i("IND-PERSIST-LAUNCHD", "macOS launch agent/daemon",
       "persistence", "high",
       "A LaunchAgent/LaunchDaemon plist is installed (runs at login or "
       "boot).",
       r"/(?:Library/LaunchAgents|Library/LaunchDaemons)/[^\s]{1,60}\.plist",
       r"launchctl\s+(?:load|bootstrap)[^\n]{0,80}",
       tags=("macos", "autostart")),
    _i("IND-PERSIST-AT-JOB", "Scheduled 'at' job",
       "persistence", "medium",
       "An at(1) job queues a command to run later — the minimal Linux "
       "scheduling primitive.",
       r"\bat\s+(?:now|midnight|\d{1,2}:\d{2}|\d{1,2}\s*(?:am|pm))[^\n]{0,60}",
       tags=("linux", "schedule")),
    _i("IND-PERSIST-SYSTEMD-TIMER", "systemd timer unit",
       "persistence", "high",
       "A systemd .timer unit plus its service schedules a payload "
       "(equivalent to cron, harder to spot).",
       r"\.timer\b[^\n]{0,80}",
       r"\[Timer\][^\n]{0,120}(?:OnCalendar|OnBootSec|OnUnitActiveSec)",
       tags=("linux", "systemd")),
    _i("IND-PERSIST-UDEV-RULE", "udev rule execution",
       "persistence", "high",
       "A udev rule with RUN+= executes a command whenever a device event "
       "fires.",
       r"RUN\+=?\"?[^\n]{0,80}",
       r"/etc/udev/rules\.d/[^\s]{1,40}",
       tags=("linux", "udev")),
    _i("IND-PERSIST-WSL-BOOT", "WSL boot command",
       "persistence", "medium",
       "A [boot] command in /etc/wsl.conf runs inside the WSL instance at "
       "startup.",
       r"\[boot\][^\n]{0,120}",
       r"wsl\.conf",
       tags=("wsl", "autostart")),
    _i("IND-PERSIST-REG-ADD-ENCODED", "Encoded payload in a Run key",
       "persistence", "critical",
       "reg add writes a Run/RunOnce value whose data is an encoded or "
       "inline command.",
       r"reg(?:\.exe)?\s+add[^\n]{0,90}(?:Run|RunOnce)[^\n]{0,140}(?:-enc|-EncodedCommand|powershell|mshta|rundll32|/c\s)",
       tags=("registry", "encoded")),

    # ----------------------------------------------------------- credential
    _i("IND-CRED-MIMIKATZ-MODULE", "Mimikatz module invocation",
       "credential", "critical",
       "Mimikatz module syntax (sekurlsa / lsadump / kerberos / vault) "
       "appears in a script or memory image.",
       r"\b(?:sekurlsa::|lsadump::|kerberos::|vault::|crypto::|dpapi::)[a-z_]{3,20}",
       tags=("mimikatz", "credential")),
    _i("IND-CRED-COMSVCS-MINIDUMP", "comsvcs MiniDump",
       "credential", "critical",
       "The comsvcs.dll MiniDump export used through rundll32 to dump "
       "lsass without any tooling on disk.",
       r"comsvcs(?:\.dll)?[^\n]{0,60}(?:MiniDump|#24)",
       tags=("lsass", "lolbin")),
    _i("IND-CRED-PROCDUMP-LSASS", "ProcDump against lsass",
       "credential", "critical",
       "procdump writing a full memory dump of lsass.",
       r"procdump(?:64)?(?:\.exe)?[^\n]{0,80}(?:-ma\s+)?(?:lsass|\\\\lsass)",
       tags=("lsass", "tooling")),
    _i("IND-CRED-DUMPER-TOOL", "LSASS dumper tooling",
       "credential", "critical",
       "Names of dedicated LSASS dumpers that evade Defender's own "
       "detections.",
       r"(?:nanodump|dumpert|PPLDump|PPLdump|SharpMiniDump|SafetyKatz|"
       r"pypykatz|Kekeo|SharpKatz|Karnak)",
       tags=("lsass", "tooling")),
    _i("IND-CRED-RUBEUS-OPERATION", "Kerberos attack tooling",
       "credential", "critical",
       "Rubeus / Impacket Kerberos operations (kerberoast, asreproast, "
       "ticket delegation, pass-the-ticket).",
       r"(?:Rubeus|rubeus)[^\n]{0,60}(?:kerberoast|asreproast|tgtdeleg|ptt|s4u|dump)",
       r"(?:kerberoast|asreproast|GetNPUsers|GetUserSPNs|ticketer)\b",
       tags=("kerberos", "tooling")),
    _i("IND-CRED-DCSYNC", "DCSync replication request",
       "credential", "critical",
       "Directory replication rights abused to pull password hashes "
       "(lsadump::dcsync / DCSync / DRSUAPI).",
       r"lsadump::dcsync",
       r"(?:DCSync|DS-Replication-Get-Changes)[^\n]{0,60}",
       r"(?:impacket-)?secretsdump(?:\.py)?[^\n]{0,80}",
       tags=("kerberos", "dcsync")),
    _i("IND-CRED-IMPACKET-TOOL", "Impacket attack script",
       "credential", "high",
       "Impacket's lateral/credential scripts referenced by name.",
       r"(?:impacket-|/)(?:psexec|wmiexec|smbexec|atexec|secretsdump|"
       r"GetNPUsers|GetUserSPNs|ticketer|ntlmrelayx)(?:\.py)?",
       tags=("impacket", "tooling")),
    _i("IND-CRED-REG-SAVE-HIVES", "Registry hive copy",
       "credential", "critical",
       "reg save copying SAM / SYSTEM / SECURITY hives for offline password "
       "cracking.",
       r"reg(?:\.exe)?\s+save[^\n]{0,90}(?:hklm\\\\sam|hklm\\\\system|hklm\\\\security|\\\\sam\b|\\\\system\b|\\\\security\b)",
       tags=("sam", "hives")),
    _i("IND-CRED-NTDS-COPY", "ntds.dit copy",
       "credential", "critical",
       "The Active Directory database copied (often via VSS) for offline "
       "hash extraction.",
       r"ntds\.dit[^\n]{0,80}",
       r"Copy-Item[^\n]{0,80}ntds\.dit",
       tags=("ad", "credential")),
    _i("IND-CRED-DPAPI-ACCESS", "DPAPI master key access",
       "credential", "high",
       "DPAPI master keys / credential blobs decrypted (browser and "
       "Windows secrets).",
       r"(?:dpapi::masterkey|DPAPI[^\n]{0,40}MasterKey|CryptUnprotectData)[^\n]{0,60}",
       r"Protect\\\\S-1-5-21[^\n]{0,80}",
       tags=("dpapi", "credential")),
    _i("IND-CRED-BROWSER-LOGIN-DATA", "Browser login database",
       "credential", "high",
       "A browser's saved-password store referenced by file name.",
       r"(?:Login Data|logins\.json|key3\.db|key4\.db|signons\.sqlite)\b",
       tags=("browser", "credential")),
    _i("IND-CRED-BROWSER-DECRYPT-KEY", "Browser key decryption",
       "credential", "high",
       "Chromium's Local State key read and used to decrypt saved "
       "passwords.",
       r"Local State[^\n]{0,80}(?:encrypted_key|decrypt|base64)",
       r"(?:os_crypt|encrypted_key)[^\n]{0,60}(?:decrypt|AES)",
       tags=("browser", "credential")),
    _i("IND-CRED-MACOS-KEYCHAIN", "macOS keychain dump",
       "credential", "high",
       "Keychain export/dump commands (security dump-keychain, "
       "chainbreaker).",
       r"dump-keychain",
       r"security\s+find-(?:generic|internet)-password[^\n]{0,60}-w",
       r"login\.keychain(?:-db)?[^\n]{0,60}(?:copy|dump|cat)",
       tags=("macos", "credential")),
    _i("IND-CRED-SSH-KEY-EXFIL", "SSH private key access",
       "credential", "high",
       "A private SSH key is read, copied or uploaded.",
       r"id_(?:rsa|ed25519|ecdsa)\b[^\n]{0,60}",
       r"(?:cat|copy|scp|curl|upload)[^\n]{0,60}(?:\.ssh/|id_rsa|id_ed25519)",
       tags=("ssh", "credential")),
    _i("IND-CRED-MANAGER-CLI", "Windows credential manager access",
       "credential", "high",
       "cmdkey / vaultcmd / Credential Manager enumeration.",
       r"cmdkey\s+/list",
       r"vaultcmd[^\n]{0,60}",
       tags=("windows", "credential")),
    _i("IND-CRED-GPP-PASSWORD", "Group Policy Preferences password",
       "credential", "critical",
       "cpassword value from a GPP Groups.xml (the AES key is public, so "
       "this is plain-text recovery).",
       r"cpassword\s*=\s*\"?[A-Za-z0-9+/=]{20,}",
       r"Groups\.xml[^\n]{0,60}",
       tags=("gpp", "credential")),
    _i("IND-CRED-UNATTEND", "Unattend/sysprep credential read",
       "credential", "high",
       "Unattend.xml or sysprep answer files read for embedded admin "
       "passwords.",
       r"unattend\.xml",
       r"(?:sysprep|Unattend)[^\n]{0,60}<(?:Password|UserAccounts)",
       tags=("credential", "deployment")),
    _i("IND-CRED-WIFI-KEY-CLEAR", "Wi-Fi key extraction",
       "credential", "high",
       "netsh wlan show profile ... key=clear reveals saved Wi-Fi "
       "passwords.",
       r"wlan\s+show\s+profile[^\n]{0,60}key\s*=\s*clear",
       r"(?:Wifi|Wireless) Profiles[^\n]{0,40}key[^\n]{0,10}clear",
       tags=("wifi", "credential")),
    _i("IND-CRED-TOKEN-DUPLICATE", "Access token duplication",
       "credential", "high",
       "An access token is duplicated/impersonated to take over another "
       "user's security context.",
       r"(?:DuplicateToken(?:Ex)?|ImpersonateLoggedOnUser|OpenProcessToken)[^\n]{0,80}(?:TOKEN_DUPLICATE|TOKEN_ALL_ACCESS|Impersonate)",
       tags=("token", "credential")),
    _i("IND-CRED-SHARPTOOLS", "Windows offensive toolkit",
       "credential", "high",
       "Names of widely used .NET offensive tools (enumeration, privilege "
       "escalation, credential access).",
       r"(?:SharpHound|Seatbelt|SharpUp|Rubeus|Watson|PowerUp[^\n]{0,10}|"
       r"SweetPotato|JuicyPotato|RoguePotato|GodPotato|PrintSpoofer)",
       tags=("tooling", "enumeration")),
    _i("IND-CRED-PEAS", "PEAS enumeration script",
       "credential", "high",
       "WinPEAS / LinPEAS / linux-exploit-suggester style enumeration "
       "scripts running (very common post-exploitation step).",
       r"(?:winpeas|linpeas|unix-privesc-check|linux-exploit-suggester|pspy|"
       r"linuxprivchecker)",
       tags=("enumeration", "tooling")),
    _i("IND-CRED-LAZAGNE", "LaZagne credential harvester",
       "credential", "critical",
       "LaZagne, a credential-recovery tool that dumps dozens of "
       "applications at once.",
       r"lazagne(?:\.exe)?[^\n]{0,60}",
       tags=("tooling", "credential")),
    _i("IND-CRED-SHADOW-READ", "/etc/shadow access",
       "credential", "high",
       "Password hashes read or cracked from /etc/shadow (unshadow, "
       "john/hashcat workflows).",
       r"/etc/shadow[^\n]{0,60}",
       r"(?:unshadow|john)[^\n]{0,80}(?:shadow|passwd)",
       tags=("linux", "credential")),
    _i("IND-CRED-KERBEROS-TICKET", "Kerberos ticket file",
       "credential", "high",
       "A .kirbi ticket file or exported ticket cache handled by the "
       "process.",
       r"\.kirbi\b",
       r"KRB5CCNAME\s*=|klist[^\n]{0,40}(?:export|purge)",
       tags=("kerberos", "credential")),
    _i("IND-CRED-COOKIE-DB", "Browser cookie database copy",
       "credential", "high",
       "A browser cookie database is read or copied (session theft).",
       r"(?:cookies\.sqlite|Cookies\.binarycookies)[^\n]{0,60}",
       tags=("browser", "session")),
)

CHECKS = CHECKS + _BATCH_3


_BATCH_4: Tuple[Indicator, ...] = (

    # ----------------------------------------------------- lateral movement
    _i("IND-LATERAL-ADMIN-SHARE-PATH", "Administrative share path",
       "lateral", "high",
       "UNC path into an administrative share (C$, ADMIN$, IPC$) — copying "
       "to or executing from another host.",
       r"\\\\[A-Za-z0-9._-]{2,60}\\(?:[A-Za-z]\$|ADMIN\$|IPC\$)",
       tags=("smb", "lateral")),
    _i("IND-LATERAL-WINRS", "WinRS remote shell",
       "lateral", "high",
       "winrs against a remote host (WinRM shell without PowerShell).",
       r"winrs[^\n]{0,60}-r:",
       tags=("winrm", "lateral")),
    _i("IND-LATERAL-NET-USE", "SMB mount to a remote host",
       "lateral", "medium",
       "net use mounting a remote share, often with credentials on the "
       "command line.",
       r"net(?:\.exe)?\s+use[^\n]{0,90}\\\\[A-Za-z0-9._-]{2,60}\\\\",
       tags=("smb", "lateral")),
    _i("IND-LATERAL-PASS-THE-HASH", "Pass-the-hash tooling",
       "lateral", "critical",
       "Hash-based authentication tools/commands (sekurlsa::pth, "
       "Invoke-TheHash, SMBExec-style wrappers).",
       r"sekurlsa::pth",
       r"(?:Invoke-TheHash|Invoke-SMBExec|Invoke-WMIExec|psexec_winexe|pth-winexe)[^\n]{0,60}",
       tags=("pth", "lateral")),
    _i("IND-LATERAL-HOST-KEY-CHECK-OFF", "SSH host-key checking disabled",
       "lateral", "medium",
       "ssh with StrictHostKeyChecking=no / -o UserKnownHostsFile=/dev/null "
       "— scripted access to many hosts.",
       r"StrictHostKeyChecking\s*=\s*(?:no|false)",
       r"UserKnownHostsFile\s*=\s*/dev/null",
       tags=("ssh", "lateral")),
    _i("IND-LATERAL-SCP", "scp file transfer",
       "lateral", "medium",
       "scp moving files to or from a remote host (often post-exploitation "
       "movement).",
       # A dotted host followed by ':' plus a path, so the bare three-letter
       # command name inside random bytes cannot trigger it.
       r"\bscp\b[^\n]{0,60}\s(?:[A-Za-z0-9._%+-]{1,32}@)?"
       r"[A-Za-z0-9][A-Za-z0-9.-]{2,}\.[A-Za-z]{2,12}:(?:\S{1,60})",
       tags=("ssh", "transfer")),
    _i("IND-LATERAL-USER-ADD", "Local user account created",
       "lateral", "critical",
       "net user /add — a new local account for persistence and lateral "
       "access.",
       r"net(?:\.exe)?\s+user[^\n]{0,80}/add\b",
       tags=("account", "persistence")),
    _i("IND-LATERAL-LOCALGROUP-ADD", "Privileged group membership added",
       "lateral", "critical",
       "An account added to administrators/Remote Desktop Users.",
       r"localgroup[^\n]{0,60}(?:administrators|administradores|administratoren|"
       r"Remote\s+Desktop\s+Users|Event\s+Log\s+Readers|Backup\s+Operators)[^\n]{0,60}/add",
       tags=("account", "privilege")),
    _i("IND-LATERAL-NEW-LOCALUSER", "PowerShell account creation",
       "lateral", "critical",
       "New-LocalUser / Add-LocalGroupMember used to create or elevate an "
       "account.",
       r"(?:New-LocalUser|Add-LocalGroupMember)[^\n]{0,90}",
       tags=("account", "powershell")),
    _i("IND-LATERAL-ENABLE-ACCOUNT", "Account (re)enabled",
       "lateral", "high",
       "A disabled account is switched back on (classic backdoor account).",
       r"net(?:\.exe)?\s+user[^\n]{0,60}/active:yes",
       r"Enable-LocalUser[^\n]{0,40}",
       tags=("account", "persistence")),
    _i("IND-LATERAL-SAM-ACCOUNT-REG", "SAM account registry edit",
       "lateral", "critical",
       "Direct registry manipulation under HKLM\\SAM\\SAM\\Domains\\Account "
       "to create or hide an account.",
       r"SAM\\\\SAM\\\\Domains\\\\Account[^\n]{0,80}",
       tags=("sam", "account")),
    _i("IND-LATERAL-DSRM-ADMIN", "DSRM admin logon enabled",
       "lateral", "critical",
       "DsrmAdminLogonBehavior set so the Directory Services Restore Mode "
       "account can log on normally — a documented domain backdoor.",
       r"DsrmAdminLogonBehavior",
       tags=("domain", "backdoor")),
    _i("IND-LATERAL-DOMAIN-ENUM", "Active Directory enumeration",
       "lateral", "medium",
       "Directory queries for users, groups or computers (nltest, dsquery, "
       "AdFind, Get-ADUser, net group).",
       r"(?:nltest|dsquery|adfind|Get-ADUser|Get-ADComputer|Get-ADGroupMember)[^\n]{0,80}",
       r"net(?:\.exe)?\s+group[^\n]{0,40}\"?(?:Domain Admins|Enterprise Admins)\"?",
       tags=("ad", "discovery")),
    _i("IND-LATERAL-BLOODHOUND", "BloodHound collection",
       "lateral", "high",
       "SharpHound/BloodHound collecting AD relationships (attack-path "
       "mapping).",
       r"(?:SharpHound|bloodhound)(?:\.exe)?[^\n]{0,80}(?:-c\s+All|CollectionMethods|-c All)",
       tags=("ad", "tooling")),
    _i("IND-LATERAL-SHARE-ENUM", "Network share enumeration",
       "lateral", "low",
       "Shares or network resources enumerated (net view / net share).",
       r"net(?:\.exe)?\s+(?:view|share)[^\n]{0,60}",
       tags=("discovery", "smb")),
    _i("IND-LATERAL-SESSION-ENUM", "Session enumeration",
       "lateral", "low",
       "Logged-on sessions listed on a host (net sessions) — target "
       "selection.",
       r"net(?:\.exe)?\s+sessions?\b",
       tags=("discovery", "windows")),
    _i("IND-LATERAL-NETWORK-SWEEP", "Subnet sweep",
       "lateral", "medium",
       "Broadcast-ICMP or ARP sweeping to map a network.",
       r"(?:arp-scan|netdiscover|fping\s+-a|nmap\s+-sn|nmap\s+-sP)[^\n]{0,60}",
       tags=("discovery", "network")),
    _i("IND-LATERAL-NTLM-RELAY", "NTLM relay tooling",
       "lateral", "critical",
       "ntlmrelayx / Responder-style coercion and relay of NTLM "
       "authentication.",
       r"(?:ntlmrelayx|Responder\.py|Inveigh)[^\n]{0,80}",
       tags=("ntlm", "tooling")),
    _i("IND-LATERAL-SMB-TOOLKIT", "SMB attack toolkit",
       "lateral", "high",
       "CrackMapExec/NetExec-style SMB operations against remote hosts.",
       r"(?:crackmapexec|cme|nxc|netexec)\s+(?:smb|winrm|mssql)[^\n]{0,80}",
       tags=("smb", "tooling")),
    _i("IND-LATERAL-SSH-TUNNEL", "SSH tunnel / port forward",
       "lateral", "medium",
       "ssh used to forward ports or run a SOCKS proxy (pivoting).",
       r"ssh[^\n]{0,80}(?:-R\s+\d{2,5}|-L\s+\d{2,5}|-D\s+\d{2,5}|DynamicForward|socks)",
       tags=("ssh", "pivot")),

    # ------------------------------------------------- command & control
    _i("IND-EXFIL-RCLONE", "rclone exfiltration",
       "exfil", "critical",
       "rclone copying or syncing data to a remote (the default "
       "cloud-exfiltration tool in intrusions).",
       r"rclone(?:\.exe)?[^\n]{0,90}(?:copy|sync|move|config\s+create)",
       tags=("exfil", "cloud")),
    _i("IND-EXFIL-MEGA", "MEGA cloud upload",
       "exfil", "high",
       "megacmd / mega.nz upload of collected data.",
       r"(?:megacmd|mega-sdk|mega\.nz)[^\n]{0,60}|mega(?:cmd)?[^\n]{0,30}\bput\b[^\n]{0,40}",
       tags=("exfil", "cloud")),
    _i("IND-EXFIL-CLOUD-DRIVE", "Public cloud storage API",
       "exfil", "high",
       "Direct calls to Dropbox / Google Drive / OneDrive upload APIs.",
       r"(?:api\.dropboxapi\.com|content\.dropboxapi\.com|www\.googleapis\.com/upload/drive|graph\.microsoft\.com[^\n]{0,40}/drive)",
       r"(?:dropbox|onedrive|Google\s*Drive)[^\n]{0,40}(?:upload|put)"
       r"[^\n]{0,40}",
       tags=("exfil", "cloud")),
    _i("IND-EXFIL-FILE-SHARING", "Anonymous file-sharing drop",
       "exfil", "high",
       "Upload to a no-signup file-sharing or paste host commonly used for "
       "staging.",
       r"(?:transfer\.sh|file\.io|0x0\.st|anonfiles|gofile\.io|bashupload|"
       r"temp\.sh|catbox\.moe|uguu\.se|pixeldrain)",
       tags=("exfil", "sharing")),
    _i("IND-EXFIL-PASTE-API", "Paste service API",
       "exfil", "medium",
       "Programmatic upload to a paste service (pastebin API key, tty "
       "paste hosts).",
       r"(?:pastebin\.com/api|hastebin\.com|ghostbin|termbin\.com|paste\.ee|dpaste)",
       tags=("exfil", "paste")),
    _i("IND-EXFIL-TELEGRAM-API", "Telegram bot API",
       "exfil", "high",
       "Telegram bot endpoints (sendDocument / sendMessage) used as a dead "
       "drop.",
       r"api\.telegram\.org/bot[0-9]{6,}:",
       r"send(?:Document|Message|Photo)[^\n]{0,60}chat_id",
       tags=("exfil", "telegram")),
    _i("IND-EXFIL-SLACK-WEBHOOK", "Slack webhook",
       "exfil", "high",
       "Slack incoming-webhook URL used to move data out.",
       r"hooks\.slack\.com/services/[A-Za-z0-9/_+-]{10,}",
       tags=("exfil", "webhook")),
    _i("IND-EXFIL-DNS-TUNNEL", "DNS tunnelling tool",
       "exfil", "critical",
       "iodine / dnscat2 / dns2tcp / dnsteal — data exfiltration through "
       "DNS queries.",
       r"(?:iodine|dnscat2?|dns2tcp|dnsteal|heyoka)[^\n]{0,60}",
       tags=("exfil", "dns")),
    _i("IND-EXFIL-NGROK", "Tunnel service usage",
       "exfil", "high",
       "ngrok / localtunnel / serveo / pagekite or cloudflared/frp/chisel — "
       "exposes an internal service or tunnels C2 traffic.",
       r"(?:ngrok|localtunnel|serveo|pagekite)[^\n]{0,60}(?:http|tcp|start|authtoken)?",
       r"(?:cloudflared|chisel|frpc?)(?:\.exe)?[^\n]{0,60}(?:tunnel|client|-c\s)",
       tags=("tunnel", "c2")),
    _i("IND-EXFIL-SMTP", "Mail-based exfiltration",
       "exfil", "medium",
       "A script sending mail with an attachment/body through SMTP "
       "(sendmail, swaks, mailx).",
       r"(?:sendmail|swaks|mailx|blat)[^\n]{0,80}(?:-attach|-a\s|-f\s+[^\s]+@|mail\s+-s)",
       tags=("exfil", "smtp")),
    _i("IND-EXFIL-FTP-PUT", "FTP upload",
       "exfil", "medium",
       "FTP put/mput of collected files.",
       r"ftp[^\n]{0,60}\b(?:put|mput)\b[^\n]{0,60}",
       tags=("exfil", "ftp")),
    _i("IND-EXFIL-CURL-UPLOAD", "curl/wget upload",
       "exfil", "high",
       "curl -T / --upload-file or wget --post-file sending a local file to "
       "a remote host.",
       r"curl[^\n]{0,90}(?:-T\s|--upload-file|-F\s+[^\s]{1,24}=@)",
       r"wget[^\n]{0,80}--post-file",
       tags=("exfil", "upload")),
    _i("IND-EXFIL-PS-UPLOAD", "PowerShell web upload",
       "exfil", "high",
       "Invoke-WebRequest/Invoke-RestMethod posting a file or body to a "
       "remote endpoint.",
       r"(?:Invoke-WebRequest|Invoke-RestMethod|curl\.exe)[^\n]{0,90}(?:-Method\s+(?:Post|Put)|-InFile|-Body)",
       tags=("exfil", "powershell")),
    _i("IND-EXFIL-BASE64-PIPE", "Base64 piped to a network client",
       "exfil", "high",
       "A file is base64-encoded and piped straight into curl/nc (no "
       "temporary file).",
       r"base64[^\n]{0,60}\|\s*(?:curl|wget|nc|ncat|openssl)",
       tags=("exfil", "pipe")),
    _i("IND-EXFIL-TOR-PROXY", "Tor / SOCKS proxy usage",
       "exfil", "medium",
       "Traffic routed through Tor or a local SOCKS proxy "
       "(127.0.0.1:9050/1080, proxychains).",
       r"(?:SocksPort|Socks5[^\n]{0,20}(?:127\.0\.0\.1|localhost):(?:9050|9150|1080))",
       r"proxychains[^\n]{0,60}",
       tags=("tor", "proxy")),
    _i("IND-EXFIL-SOCKS-ENV", "SOCKS proxy environment",
       "exfil", "medium",
       "Proxy environment variables pointed at a SOCKS endpoint (pivoting "
       "through an implant).",
       r"(?:ALL_PROXY|HTTPS?_PROXY|http_proxy)\s*=\s*socks[45]?h?://",
       tags=("proxy", "pivot")),
    _i("IND-EXFIL-AWS-S3", "AWS S3 data movement",
       "exfil", "high",
       "aws s3 cp/sync/mv used to push or pull data from object storage.",
       r"aws\s+s3\s+(?:cp|sync|mv|rb|rm)[^\n]{0,90}",
       tags=("cloud", "exfil")),
    _i("IND-EXFIL-GCS", "Google Cloud Storage movement",
       "exfil", "high",
       "gsutil copying or rsyncing to a bucket.",
       r"gsutil\s+(?:cp|rsync|mv)[^\n]{0,80}",
       tags=("cloud", "exfil")),
    _i("IND-EXFIL-AZURE-BLOB", "Azure Blob upload",
       "exfil", "high",
       "az storage blob upload / AzCopy transfer.",
       r"(?:az\s+storage\s+blob\s+upload|azcopy\s+(?:copy|sync))[^\n]{0,90}",
       tags=("cloud", "exfil")),
    _i("IND-EXFIL-STAGE-ARCHIVE", "Collection archive built in a temp path",
       "exfil", "medium",
       "tar/zip/7z writing a staging archive into /tmp or %TEMP% before "
       "exfiltration.",
       r"(?:tar|zip|7z|rar)[^\n]{0,80}(?:/tmp/|%TEMP%|C:\\Windows\\Temp)[^\n]{0,40}",
       tags=("staging", "collection")),
    _i("IND-EXFIL-CURL-TO-IP", "Upload to a bare IP address",
       "exfil", "high",
       "Data POSTed/uploaded to a hard-coded IP literal rather than a "
       "domain.",
       r"curl[^\n]{0,70}https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?[^\n]{0,50}(?:-T|-F|--data|-d\s)",
       tags=("exfil", "ip")),
    _i("IND-EXFIL-WEBSOCKET-C2", "WebSocket command channel",
       "exfil", "medium",
       "A WebSocket connection to a hard-coded endpoint (interactive C2 "
       "channel).",
       r"wss?://[A-Za-z0-9._-]{4,60}(?::\d{2,5})?/[A-Za-z0-9._/-]{0,60}",
       tags=("c2", "websocket")),

    # -------------------------------------------------------------- impact
    _i("IND-IMPACT-PHYSICALDRIVE-WRITE", "Raw physical disk write",
       "impact", "critical",
       "A handle opened on \\\\.\\PhysicalDrive0 — direct disk overwrite "
       "(MBR/boot destroyer).",
       r"\\\\\.\\\\PhysicalDrive[0-9]",
       tags=("wiper", "mbr")),
    _i("IND-IMPACT-BOOT-DEVICE-WRITE", "Boot device overwrite",
       "impact", "critical",
       "dd/writing to a whole block device (/dev/sda, /dev/nvme0n1).",
       r"\bdd\b[^\n]{0,80}(?:of=/dev/(?:sd[a-z]|nvme[0-9]n[0-9]|hd[a-z])|if=/dev/(?:zero|urandom)[^\n]{0,40}of=)",
       tags=("wiper", "linux")),
    _i("IND-IMPACT-VSS-STORAGE-RESIZE", "Shadow storage shrunk",
       "impact", "high",
       "vssadmin resize shadowstorage reducing snapshots to a minimum "
       "(pre-encryption step).",
       r"vssadmin[^\n]{0,60}resize[^\n]{0,40}shadowstorage",
       tags=("ransomware", "vss")),
    _i("IND-IMPACT-WMI-SHADOW-DELETE", "Snapshot deletion through WMI",
       "impact", "critical",
       "Win32_ShadowCopy accessed to delete snapshots through WMI.",
       r"Win32_ShadowCopy[^\n]{0,80}",
       r"(?:Get-WmiObject|Get-CimInstance)[^\n]{0,60}ShadowCopy[^\n]{0,60}Delete",
       tags=("ransomware", "vss")),
    _i("IND-IMPACT-BACKUP-SOFTWARE-KILL", "Backup/DB processes killed",
       "impact", "critical",
       "Backup, database or VSS services stopped or killed so files can be "
       "encrypted.",
       r"(?:net|sc|Stop-Service)[^\n]{0,30}(?:stop|Stop-Service)[^\n]{0,40}(?:Veeam|Backup|SQLSERVER|MSSQL|SQLWriter|Exchange|ShadowProtect)",
       r"taskkill[^\n]{0,80}/im[^\n]{0,40}(?:sqlservr|oracle|veeam|backup|excel|word|outlook|mysqld|postgres)",
       tags=("ransomware", "impact")),
    _i("IND-IMPACT-VSS-COM-DELETE", "VSS component snapshot deletion",
       "impact", "critical",
       "The Volume Shadow Copy COM interface used to delete snapshots.",
       r"(?:IVssBackupComponents|DeleteSnapshots|VSS_OBJECT_SNAPSHOT)",
       tags=("ransomware", "vss")),
    _i("IND-IMPACT-MASS-ENCRYPT-LOOP", "Mass file-encryption loop",
       "impact", "critical",
       "A loop walking files and encrypting each one (openssl/gpg/cipher "
       "inside a directory iteration).",
       r"(?:for\s+/[rf]\s|Get-ChildItem|find\s+[^\n]{0,40}-type\s+f)[^\n]{0,120}(?:openssl|gpg|cipher\.encrypt|Encrypt\(|AES\.new)",
       tags=("ransomware", "encryption")),
    _i("IND-IMPACT-FILE-ENCRYPT-API", "File encryption routine",
       "impact", "medium",
       "Crypto library calls writing encrypted content back over files "
       "(context needed — can be legitimate software).",
       r"(?:Fernet|AES\.MODE_CBC|RijndaelManaged|CryptEncrypt)[^\n]{0,90}(?:open\([^\n]{0,30}'wb'|write|FileStream)",
       tags=("ransomware", "encryption")),
    _i("IND-IMPACT-RENAME-ENCRYPTED", "Files renamed to a crypto extension",
       "impact", "critical",
       "A rename/move loop appending an encryption-style extension.",
       r"(?:os\.rename|Move-Item|move\s+)[^\n]{0,90}(?:\.encrypted\b|\.locked\b|\.crypt(?:ed)?\b|\.enc\b)",
       tags=("ransomware", "rename")),
    _i("IND-IMPACT-BCD-DELETE-ENTRY", "Boot entry deleted",
       "impact", "critical",
       "bcdedit /delete of the current boot entry — system won't start.",
       r"bcdedit[^\n]{0,70}/delete[^\n]{0,30}\{?(?:current|default|bootmgr)\}?",
       tags=("boot", "wiper")),
    _i("IND-IMPACT-DISKPART-CLEAN", "Disk partition table wiped",
       "impact", "critical",
       "diskpart clean / clean all destroys the partition table.",
       r"diskpart[^\n]{0,100}(?:^|\s)clean(?:\s+all)?(?:\s|$)",
       r"select\s+disk\s+[0-9][^\n]{0,60}clean",
       tags=("wiper", "disk")),
    _i("IND-IMPACT-HOSTS-TAMPER", "Hosts file rewritten",
       "impact", "high",
       "The hosts file is appended to, redirected, or overwritten (DNS "
       "hijack / security-tool blocking).",
       r"(?:>>?|Add-Content|Set-Content|tee)[^\n]{0,60}(?:/etc/hosts|drivers\\\\etc\\\\hosts)",
       tags=("hosts", "hijack")),
    _i("IND-IMPACT-OVERWRITE-WIPE", "File/disk overwrite wiping",
       "impact", "high",
       "Data overwritten in place (dd from /dev/zero, sdelete -z, cipher "
       "/w).",
       r"\bdd\s+if=/dev/(?:zero|urandom)[^\n]{0,60}of=",
       r"sdelete(?:64)?(?:\.exe)?[^\n]{0,50}-z",
       tags=("wiper", "anti-forensics")),
    _i("IND-IMPACT-RANSOM-DECRYPT-PORTAL", "Ransomware payment portal URL",
       "impact", "critical",
       "Decryption/payment portal URL pattern used by ransomware notes.",
       r"(?:https?://)?[a-z0-9-]{4,40}\.(?:onion|top|cc|xyz)/(?:portal|decrypt|payment|key|unlock)",
       tags=("ransomware", "payment")),
    _i("IND-IMPACT-RANSOM-TIMER-DEADLINE", "Ransom deadline wording",
       "impact", "high",
       "Ransom-note wording about a payment deadline / countdown (the note "
       "body, not the file name).",
       r"(?:your files (?:have been|are) encrypted|all your files)",
       r"(?:pay(?:ment)? (?:within|before)|deadline|countdown|price doubles)",
       r"do not (?:try to )?(?:rename|modify|use third[- ]party)",
       tags=("ransomware", "note")),
)

CHECKS = CHECKS + _BATCH_4


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


#: Indicator categories mapped to the ATT&CK tactic they support, in kill
#: chain order.  ``antivirus matrix`` and ``matrix_summary()`` both use this
#: table, so a new category cannot silently fall out of the coverage view.
TACTICS: Tuple[Tuple[str, str, str], ...] = (
    ("execution", "TA0002 Execution",
     "Running attacker code: shells, script hosts, LOLBins, macros."),
    ("persistence", "TA0003 Persistence",
     "Surviving a reboot: Run keys, services, scheduled tasks, WMI."),
    ("evasion", "TA0005 Defense Evasion",
     "Hiding from tools: packing, obfuscation, log clearing, AMSI/ETW."),
    ("credential", "TA0006 Credential Access",
     "Stealing secrets: LSASS, SAM, browser stores, keylogging."),
    ("lateral", "TA0008 Lateral Movement",
     "Moving between hosts: SMB, WMI, WinRM, PsExec-style tooling."),
    ("exfil", "TA0010 Exfiltration",
     "Getting data out: paste sites, tunnels, archives, cloud uploads."),
    ("impact", "TA0040 Impact",
     "Damaging the host: shadow copies, ransom notes, disk wipers."),
    ("office", "Initial Access / Office",
     "Documents and their launchers: macros, DDE, embedded objects."),
)


def matrix_summary(checks: Optional[Iterable[Indicator]] = None) -> Dict:
    """Coverage of the check library by tactic.

    Returns ``{"total", "tactics": [...], "unmapped": n}`` where *unmapped*
    counts checks whose category is missing from :data:`TACTICS` – a number
    that must stay 0, and that the self test asserts.
    """
    items = list(CHECKS if checks is None else checks)
    by_category: Dict[str, List[Indicator]] = {}
    for ind in items:
        by_category.setdefault(ind.category, []).append(ind)
    known = {category for category, _, _ in TACTICS}
    tactics = []
    for category, pretty, blurb in TACTICS:
        entries = by_category.get(category, [])
        severities: Dict[str, int] = {}
        tags: Dict[str, int] = {}
        for ind in entries:
            severities[ind.severity] = severities.get(ind.severity, 0) + 1
            for tag in ind.tags:
                tags[tag] = tags.get(tag, 0) + 1
        tactics.append({
            "category": category, "tactic": pretty, "description": blurb,
            "checks": len(entries), "by_severity": severities,
            "tags": sorted(tags.items(), key=lambda kv: (-kv[1], kv[0]))[:8],
            "example": entries[0].id if entries else "",
        })
    return {
        "total": len(items),
        "tactics": tactics,
        "extra_categories": sorted(set(by_category) - known),
        "unmapped": sum(len(v) for k, v in by_category.items() if k not in known),
    }
