-- Title: PUA - Sysinternals Tools Execution - Registry
-- ID: c7da8edc-49ae-45a2-9e61-9fd860e4e73d
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-24
-- Tags: attack.resource-development, attack.t1588.002
-- Description: Detects the execution of some potentially unwanted tools such as PsExec, Procdump, etc. (part of the Sysinternals suite) via the creation of the "accepteula" registry key.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\Active Directory Explorer%' OR TargetObject LIKE '%\\Handle%' OR TargetObject LIKE '%\\LiveKd%' OR TargetObject LIKE '%\\Process Explorer%' OR TargetObject LIKE '%\\ProcDump%' OR TargetObject LIKE '%\\PsExec%' OR TargetObject LIKE '%\\PsLoglist%' OR TargetObject LIKE '%\\PsPasswd%' OR TargetObject LIKE '%\\SDelete%' OR TargetObject LIKE '%\\Sysinternals%') AND TargetObject="*\\EulaAccepted")
