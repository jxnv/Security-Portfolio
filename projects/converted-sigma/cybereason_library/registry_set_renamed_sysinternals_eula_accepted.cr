// Title: Usage of Renamed Sysinternals Tools - RegistrySet
// ID: 8023f872-3f1d-4301-a384-801889917ab4
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-24
// Tags: attack.resource-development, attack.t1588.002
// Description: Detects non-sysinternals tools setting the "accepteula" key which normally is set on sysinternals tool execution
// Converted by: Sigma Universal SIEM/EDR CLI

(((TargetObject contains "\\PsExec" OR TargetObject contains "\\ProcDump" OR TargetObject contains "\\Handle" OR TargetObject contains "\\LiveKd" OR TargetObject contains "\\Process Explorer" OR TargetObject contains "\\PsLoglist" OR TargetObject contains "\\PsPasswd" OR TargetObject contains "\\Active Directory Explorer") AND TargetObject="*\\EulaAccepted") AND NOT (((Image="*\\PsExec.exe" OR Image="*\\PsExec64.exe" OR Image="*\\PsExec64a.exe" OR Image="*\\procdump.exe" OR Image="*\\procdump64.exe" OR Image="*\\procdump64a.exe" OR Image="*\\handle.exe" OR Image="*\\handle64.exe" OR Image="*\\handle64a.exe" OR Image="*\\livekd.exe" OR Image="*\\livekd64.exe" OR Image="*\\procexp.exe" OR Image="*\\procexp64.exe" OR Image="*\\procexp64a.exe" OR Image="*\\psloglist.exe" OR Image="*\\psloglist64.exe" OR Image="*\\psloglist64a.exe" OR Image="*\\pspasswd.exe" OR Image="*\\pspasswd64.exe" OR Image="*\\pspasswd64a.exe" OR Image="*\\ADExplorer.exe" OR Image="*\\ADExplorer64.exe" OR Image="*\\ADExplorer64a.exe"))) AND NOT ((NOT Image=*)))
