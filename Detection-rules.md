# Detection Rules

## 1. Encoded PowerShell Command Detected

```spl
index=main
sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*EncodedCommand*"
```

---

## 2. Mimikatz Execution Detected

```spl
index=main
sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*mimikatz*"
```

---

## 3. SMB Brute Force Detected

```spl
index=main
sourcetype="WinEventLog:Security" EventCode=4625
| stats count by host
| where count > 3
```

---

## 4. Suspicious Service Created — Lateral Movement

```spl
index=main
sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*services.exe*" User="NT AUTHORITY\\SYSTEM"
```
