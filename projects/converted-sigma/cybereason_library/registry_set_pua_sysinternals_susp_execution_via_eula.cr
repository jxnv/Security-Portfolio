// Title: PUA - Sysinternals Tools Execution - Registry
// ID: c7da8edc-49ae-45a2-9e61-9fd860e4e73d
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-24
// Tags: attack.resource-development, attack.t1588.002
// Description: Detects the execution of some potentially unwanted tools such as PsExec, Procdump, etc. (part of the Sysinternals suite) via the creation of the "accepteula" registry key.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject contains "\\Active Directory Explorer" OR TargetObject contains "\\Handle" OR TargetObject contains "\\LiveKd" OR TargetObject contains "\\Process Explorer" OR TargetObject contains "\\ProcDump" OR TargetObject contains "\\PsExec" OR TargetObject contains "\\PsLoglist" OR TargetObject contains "\\PsPasswd" OR TargetObject contains "\\SDelete" OR TargetObject contains "\\Sysinternals") AND TargetObject="*\\EulaAccepted")
