// Title: UAC Bypass via Windows Firewall Snap-In Hijack
// ID: e52cb31c-10ed-4aea-bcb7-593c9f4a315b
// Status: test
// Level: medium
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-27
// Tags: attack.privilege-escalation, attack.t1548
// Description: Detects attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\mmc.exe" and actor_process_command_line contains "WF.msc") and not ((action_process_image_path endswith "\\WerFault.exe")))
