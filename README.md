# Wazuh SIEM Threat Hunting Home Lab

This repository documents my personal Blue Team / SOC home lab built around **Wazuh SIEM**.  
The goal is to learn **threat hunting, incident detection, and log analysis** using real systems and real security events in a controlled lab.

---

## 🧠 Lab Objectives

- Build and manage a **Wazuh SIEM** environment from scratch  
- Collect logs from multiple endpoints (Linux, macOS, Windows, Kali – in progress)  
- Practice **threat hunting** and interpreting alerts  
- Map events to the **MITRE ATT&CK** framework  
- Create a portfolio-ready project showing real SOC skills

---

## 🏗️ Lab Architecture

Current layout:

- **Wazuh Manager**
  - OS: Ubuntu Server (VM)
  - Role: Runs Wazuh server, dashboard, and threat hunting module
  - IP: `192.168.164.7` (lab subnet)

- **Agent: DJ-Mac**
  - Device: macOS (MacBook)
  - Role: Wazuh agent sending host logs to the manager
  - Use: Daily driver + monitored endpoint

- **Agent: wazuh-1**
  - Device: Linux host (same or separate VM)
  - Role: Generates system, auth, and security logs for analysis

Planned additions:

- **Windows 11 VM (incoming)**
  - Use: Windows event logs, PowerShell events, login failures, etc.

- **Kali Linux VM (incoming)**
  - Use: Simulated attacker box for safe testing and detection

---

## ⚙️ Wazuh Features Enabled

So far, the lab is successfully doing:

- **Authentication monitoring**
  - PAM login session opened / closed
  - Successful logins
  - (Planned) failed login/brute force simulations

- **Privilege escalation detection**
  - `Successful sudo to ROOT executed`
  - Correlated to **MITRE ATT&CK – Privilege Escalation**

- **Service failure monitoring**
  - `Systemd: Service exited due to a failure`
  - Useful for tracking unstable or crashed services

- **Linux security policy violations**
  - `AppArmor DENIED`
  - Shows when AppArmor blocks restricted actions

- **Host-based anomaly detection (rootcheck)**
  - `Host-based anomaly detection event (rootcheck)`
  - Checks for:
    - Suspicious files / directories
    - Weak or insecure configurations
    - Signs of possible compromise

- **MITRE ATT&CK mapping**
  - Wazuh dashboard groups events under ATT&CK techniques
  - Helps think like a SOC analyst while investigating alerts

---

## 📸 Screenshots

Screenshots used in this project:

1. **Threat Hunting Dashboard Overview**  
   File: `screenshots/wazuh-threat-hunting-dashboard.png`  
   - Shows total alerts, authentication successes, and MITRE ATT&CK donut chart.

2. **Event List View (sudo, AppArmor, rootcheck)**  
   File: `screenshots/wazuh-events-sudo-apparmor-rootcheck.png`  
   - Shows:
     - PAM login sessions opened/closed  
     - Successful sudo to ROOT  
     - AppArmor DENIED events  
     - Rootcheck anomaly detection

_These screenshots demonstrate that the lab is live, collecting events, and correlating them properly._

---

## 🔍 Example Events Observed

Some real events captured in the lab (from the Wazuh Threat Hunting module):

- `PAM: Login session opened`
- `PAM: Login session closed`
- `Successful sudo to ROOT executed`
- `Systemd: Service exited due to a failure`
- `Apparmor DENIED`
- `Host-based anomaly detection event (rootcheck)`
- `Wazuh server started`
- `Log file rotated`

These show that:

- Authentication is being monitored  
- Privilege escalation is detected  
- System-level failures are tracked  
- Security controls like AppArmor are actively enforced  
- Wazuh’s rootcheck is performing baseline security scans

---

## 🕵️‍♂️ Threat Hunting Mindset

Questions I’m learning to ask for each alert:

- **Who** generated this event? (user, host, agent)
- **What** action was taken? (login, sudo, denied, failure)
- **When** did it happen? (timestamp, sequence of events)
- **Where** did it originate? (which agent)
- **Why** could this be suspicious?
  - Is this normal behavior for this host/user?
  - Is it part of a bigger pattern?

---

## 🚧 Work in Progress / Next Steps

Planned improvements:

- Add **Windows 11 VM** as a Wazuh agent
  - Monitor failed logins, RDP, PowerShell activity

- Add **Kali Linux VM** as an “attacker box”
  - Run safe scans and attacks against lab machines
  - Confirm Wazuh detects the behavior

- Build **playbooks** for:
  - Investigating authentication failures
  - Investigating privilege escalation
  - Investigating AppArmor denials

- Export **reports/dashboards** to show:
  - Daily summary of alerts
  - Top MITRE techniques observed

---

## 🧩 Why This Project Matters

This lab shows hands-on experience with:

- SIEM deployment and configuration
- Log collection from multiple OS types
- Event correlation and MITRE ATT&CK mapping
- Threat hunting and Blue Team skills
- Documenting technical work clearly for others to follow

This repository is part of my journey into **cybersecurity and SOC operations** under my DaCyborg / Kilovisionmedia / Eyegaveyoupower brand.
