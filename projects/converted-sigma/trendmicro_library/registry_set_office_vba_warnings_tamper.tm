// Title: Office Macros Warning Disabled
// ID: 91239011-fe3c-4b54-9f24-15c86bb65913
// Status: test
// Level: high
// Author: Trent Liffick (@tliffick), Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-05-22
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects registry changes to Microsoft Office "VBAWarning" to a value of "1" which enables the execution of all macros, whether signed or unsigned.
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetObject="*\\Security\\VBAWarnings" AND Details: "DWORD (0x00000001)")
