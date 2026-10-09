// Title: Suspicious ScreenSave Change by Reg.exe
// ID: 0fc35fc3-efe6-4898-8a37-0b233339524f
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-08-19
// Tags: attack.persistence, attack.privilege-escalation, attack.t1546.002
// Description: Adversaries may establish persistence by executing malicious content triggered by user inactivity.
// Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\reg.exe" AND (CommandLine contains "HKEY_CURRENT_USER\\Control Panel\\Desktop" OR CommandLine contains "HKCU\\Control Panel\\Desktop")) AND (((CommandLine contains "/v ScreenSaveActive" AND CommandLine contains "/t REG_SZ" AND CommandLine contains "/d 1" AND CommandLine contains "/f")) OR ((CommandLine contains "/v ScreenSaveTimeout" AND CommandLine contains "/t REG_SZ" AND CommandLine contains "/d " AND CommandLine contains "/f")) OR ((CommandLine contains "/v ScreenSaverIsSecure" AND CommandLine contains "/t REG_SZ" AND CommandLine contains "/d 0" AND CommandLine contains "/f")) OR ((CommandLine contains "/v SCRNSAVE.EXE" AND CommandLine contains "/t REG_SZ" AND CommandLine contains "/d " AND CommandLine contains ".scr" AND CommandLine contains "/f"))))
