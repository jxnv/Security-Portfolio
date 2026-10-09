// Title: LSASS Process Crashed - Application
// ID: a18e0862-127b-43ca-be12-1a542c75c7c5
// Status: experimental
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-07
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects Windows error reporting events where the process that crashed is LSASS (Local Security Authority Subsystem Service).
// This could be the cause of a provoked crash by techniques such as Lsass-Shtinkering to dump credentials.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Provider_Name = "Application Error" and EventID = 1000 and AppName = "lsass.exe" and ExceptionCode = "c0000001")
