# SIEM-Detection-Lab-Threat-Simulation-Log-Analysis
## 🎯 Project Title & Brief Overview

> Built a cybersecurity lab using Kali Linux, Windows 10, Sysmon, and Splunk.  
> Simulated SMB enumeration, lateral movement, credential dumping, and encoded PowerShell attacks.
> Created Splunk dashboards and detection rules to monitor and alert on malicious activity.

---

## ⚙️ Technologies & Tools Used

| Component | Description |
|------------|-------------|
| **Machines** | Windows 11(Host Laptop)/ Kali Linux VM(Attacker)/ Windows 10(Target) |
| **SIEM Platform** | Splunk Enterprise (Free version for local setup) |
| **Log Collection** | Sysmon, SplunkUniversalForwarder |
| **Virtualization** | Oracle VirtualBox |

---

## 🌐 Lab Environment / Architecture

<img width="1408" height="768" alt="Diagram" src="https://github.com/user-attachments/assets/4158e718-f381-49da-9036-bb7a15aa9aeb" />


---

## 🚨 Attack Scenarios

### Attack 1 — SMB Enumeration (Reconnaissance)
- Targeted the Windows 10 VM over SMB (port 445) using the administrator account with incorrect credentials multiple times, simulating an attacker attempting to enumerate network shares and gain unauthorized access.
- SMB enumeration is one of the first steps in lateral movement — attackers probe for accessible shares and weak credentials before moving deeper into a network.
- **Tool Used:** smbclient on Kali Linux
- **MITRE ATT&CK:** T1021.002 — Remote Services: SMB/Windows Admin Shares

---

### Attack 2 — Lateral Movement
- Using valid administrator credentials obtained during enumeration, we used impacket-psexec to remotely upload a payload to the ADMIN$ share, create a Windows service, and execute it — establishing remote access to the target machine.
- psexec-style attacks allow attackers to move laterally across a network using legitimate credentials and built-in Windows functionality, making detection harder without proper monitoring.
- **Tool Used:** impacket-psexec on Kali Linux
- **MITRE ATT&CK:** T1570 — Lateral Tool Transfer

---

### Attack 3 — Credential Dumping 
- Executed Mimikatz directly on the compromised endpoint with debug privileges, then ran sekurlsa::logonpasswords and lsadump::sam to extract credentials and password hashes stored in Windows memory (LSASS process).
- Credential dumping allows attackers to harvest plaintext passwords and hashes from memory, which can then be used for further lateral movement or privilege escalation across the network.
- **Tool Used:** Mimikatz 2.2.0 on the Windows 10 VM
- **MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

---

### Attack 4 — PowerShell Encoded Command (Living off the Land)
- Executed a Base64 encoded PowerShell command simulating a malware download cradle — a technique where malicious code is hidden inside an encoded string to evade basic signature-based detection tools.
- Using built-in Windows tools like PowerShell allows attackers to blend in with normal system activity. Encoding commands adds an extra layer of obfuscation making it harder for basic security tools to detect malicious intent.
- **Tool Used:** Built-in Windows PowerShell on the Windows 10 VM
- **MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell / T1027 — Obfuscated Files or Information
---

---

## Recommendations

| Attack | Defensive Recommendation |
|--------|------------------------|
| SMB Enumeration | Implement account lockout policy, disable SMBv1, enforce MFA |
| Lateral Movement | Apply principle of least privilege, disable default admin shares, deploy EDR |
| Credential Dumping | Enable Windows Credential Guard, enable LSA protection, disable WDigest authentication |
| Encoded PowerShell | Enable PowerShell Constrained Language Mode, enable script block logging, deploy AMSI |

---

## Key Takeaways

- Sysmon with SwiftOnSecurity config provides significantly richer telemetry than default Windows logging
- Attackers using legitimate tools (impacket, PowerShell) can still be detected through behavioral patterns in process creation logs
- MITRE ATT&CK framework provides a structured way to map detections to real-world threat actor techniques
- A layered detection approach combining Security logs and Sysmon gives the most comprehensive coverage

---

## Connect

**LinkedIn:** www.linkedin.com/in/yash-kumar-parmar  
**Email:** yashparmar.contact@gmail.com
```
