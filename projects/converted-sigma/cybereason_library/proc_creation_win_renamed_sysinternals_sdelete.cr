// Title: Renamed Sysinternals Sdelete Execution
// ID: c1d867fe-8d95-4487-aab4-e53f2d339f90
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-09-06
// Tags: attack.impact, attack.t1485
// Description: Detects the use of a renamed SysInternals Sdelete, which is something an administrator shouldn't do (the renaming)
// Converted by: Sigma Universal SIEM/EDR CLI

((OriginalFileName == "sdelete.exe") AND NOT (((Image="*\\sdelete.exe" OR Image="*\\sdelete64.exe" OR Image="*\\sdelete64a.exe"))))
