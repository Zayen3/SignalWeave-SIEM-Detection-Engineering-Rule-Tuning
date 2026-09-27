# Detection Engineering & Rule Tuning Lab

## Project Overview

This project documents a hands-on Detection Engineering lab focused on crafting custom SIEM detection rules, analyzing endpoint telemetry, and tuning out false positives. Instead of relying on out-of-the-box alerts, built a custom detections from scratch using **Wazuh SIEM** and **Microsoft Sysmon** to catch specific adversary techniques mapped to the MITRE ATT&CK framework.

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

