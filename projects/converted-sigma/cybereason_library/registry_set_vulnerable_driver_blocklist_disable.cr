// Title: Windows Vulnerable Driver Blocklist Disabled
// ID: d526c60a-e236-4011-b165-831ffa52ab70
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-01-26
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects when the Windows Vulnerable Driver Blocklist is set to disabled. This setting is crucial for preventing the loading of known vulnerable drivers,
// and its modification may indicate an attempt to bypass security controls. It is often targeted by threat actors to facilitate the installation of malicious or vulnerable drivers,
// particularly in scenarios involving Endpoint Detection and Response (EDR) bypass techniques.
// This rule applies to systems that support the Vulnerable Driver Blocklist feature, including Windows 10 version 1903 and later, and Windows Server 2022 and later.
// Note that this change will require a reboot to take effect, and this rule only detects the registry modification action.
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetObject="*\\Control\\CI\\Config\\VulnerableDriverBlocklistEnable" AND Details == "DWORD (0x00000000)")
