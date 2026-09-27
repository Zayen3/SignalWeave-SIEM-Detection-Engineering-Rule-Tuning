# Detection Engineering & Rule Tuning Lab

## Project Overview

This project documents a hands-on Detection Engineering lab focused on crafting custom SIEM detection rules, analyzing endpoint telemetry, and tuning out false positives. Instead of relying on out-of-the-box alerts, I built custom detections from scratch using **Wazuh SIEM** and **Microsoft Sysmon** to catch specific adversary techniques mapped to the MITRE ATT&CK framework.

The main focus of this lab was **quality over quantity**—making sure every rule was thoroughly tested offline, verified against live endpoint telemetry, and tuned to avoid alerting on normal administrative activity.

---

## Lab Architecture & Tech Stack

* **SIEM / Wazuh Manager:** Ubuntu 24.04 LTS (`poo`) running Wazuh Manager 4.x & Wazuh Dashboard (`192.168.183.132`).
* **Monitored Endpoint:** Windows 11 Enterprise (`Waveeee`) running Sysmon and the Wazuh Agent (`192.168.183.1`).
* **Telemetry Source:** `Microsoft-Windows-Sysmon/Operational` (specifically process creation telemetry via Event ID 1).

---

## The Detections At a Glance

| Rule ID | MITRE ATT&CK | Technique | Severity | Detection Logic Summary |
| :--- | :--- | :--- | :--- | :--- |
| **100002** | `T1033` | System Owner/User Discovery | Level 7 | Sysmon Event ID 1 filtering on `whoami.exe` execution |
| **100003** | `T1053.005` | Scheduled Task Persistence | Level 7 | Sysmon Event ID 1 matching `schtasks.exe` with `/create` flags |
| **100004** | `T1027` / `T1059.001` | Obfuscated PowerShell | Level 8 | Sysmon Event ID 1 matching `powershell.exe` encoded command flags (`-e`, `-enc`, etc.) |

---

## Custom Rules File (`local_rules.xml`)

```xml
<group name="windows, sysmon,">

  <!-- Rule 100002: T1033 - System Owner/User Discovery via whoami.exe -->
  <rule id="100002" level="7">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)whoami\.exe</field>
    <description>Discovery: System Owner/User Discovery via Whoami executed on Windows (Host: $(win.system.computer))</description>
    <mitre>
      <id>T1033</id>
    </mitre>
  </rule>

  <!-- Rule 100003: T1053.005 - Scheduled Task Creation via schtasks.exe -->
  <rule id="100003" level="7">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)schtasks\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
    <description>Persistence: Scheduled Task Created via schtasks.exe on Windows (Host: $(win.system.computer))</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

  <!-- Rule 100004: T1027 / T1059.001 - Encoded PowerShell Execution -->
  <rule id="100004" level="8">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\s+-(e|enc|encodedcommand)\s+</field>
    <description>Defense Evasion: Encoded PowerShell Command Line Execution on Windows (Host: $(win.system.computer))</description>
    <mitre>
      <id>T1027</id>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
```
Visual Verification & Proofs
1. Custom Rules Configuration

Here is the active configuration inside /var/ossec/etc/rules/local_rules.xml on the Ubuntu Manager showing the exact PCRE2 regex logic and Event ID constraints.

2. Live SIEM Alerts

A view from the Wazuh Dashboard showing live detections firing in real-time as synthetic test commands were executed on the Windows endpoint.

3. Deep-Dive Event Telemetry

An expanded event log showing rich Sysmon process creation telemetry, including execution paths, command-line arguments (whoami.exe /all), parent process details, and SHA256 hashes.

Rule Engineering & Tuning Breakdown
1. User Discovery (whoami.exe)

The Goal: Detect attackers running basic discovery commands right after gaining an initial foothold.

The Issue: Early iterations matched broadly on whoami.exe, which generated noise from administrative termination events and background checks.

The Fix: Added an explicit filter targeting Sysmon Event ID 1 (win.system.eventID: ^1$) to strictly isolate process creation events.

2. Scheduled Task Persistence (schtasks.exe)

The Goal: Detect persistence mechanisms attempting to schedule tasks.

The Issue: Matching on schtasks.exe alone catches legitimate system queries (e.g., schtasks /query), leading to frequent false alarms.

The Fix: Added a secondary regex requirement checking commandLine specifically for /create flags, ignoring routine query actions.

3. Obfuscated PowerShell Execution

The Goal: Detect command-line attempts to run Base64 encoded PowerShell commands to bypass static inspection.

The Issue: Standard keyword matching easily misses variations like -e, -enc, or -encodedcommand.

The Fix: Built a PCRE2 regular expression (?i)\s+-(e|enc|encodedcommand)\s+ with boundary spaces to catch the listed encoded-command flag variants while preventing partial word matches
