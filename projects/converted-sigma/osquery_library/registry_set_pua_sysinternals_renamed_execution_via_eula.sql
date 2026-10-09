-- Title: Suspicious Execution Of Renamed Sysinternals Tools - Registry
-- ID: f50f3c09-557d-492d-81db-9064a8d4e211
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-24
-- Tags: attack.resource-development, attack.t1588.002
-- Description: Detects the creation of the "accepteula" key related to the Sysinternals tools being created from executables with the wrong name (e.g. a renamed Sysinternals tool)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%\\Active Directory Explorer%' OR TargetObject LIKE '%\\Handle%' OR TargetObject LIKE '%\\LiveKd%' OR TargetObject LIKE '%\\ProcDump%' OR TargetObject LIKE '%\\Process Explorer%' OR TargetObject LIKE '%\\PsExec%' OR TargetObject LIKE '%\\PsLoggedon%' OR TargetObject LIKE '%\\PsLoglist%' OR TargetObject LIKE '%\\PsPasswd%' OR TargetObject LIKE '%\\PsPing%' OR TargetObject LIKE '%\\PsService%' OR TargetObject LIKE '%\\SDelete%') AND TargetObject="*\\EulaAccepted") AND NOT (((Image="*\\ADExplorer.exe" OR Image="*\\ADExplorer64.exe" OR Image="*\\ADExplorer64a.exe" OR Image="*\\handle.exe" OR Image="*\\handle64.exe" OR Image="*\\handle64a.exe" OR Image="*\\livekd.exe" OR Image="*\\livekd64.exe" OR Image="*\\procdump.exe" OR Image="*\\procdump64.exe" OR Image="*\\procdump64a.exe" OR Image="*\\procexp.exe" OR Image="*\\procexp64.exe" OR Image="*\\procexp64a.exe" OR Image="*\\PsExec.exe" OR Image="*\\PsExec64.exe" OR Image="*\\PsExec64a.exe" OR Image="*\\PsLoggedon.exe" OR Image="*\\PsLoggedon64.exe" OR Image="*\\psloglist.exe" OR Image="*\\psloglist64.exe" OR Image="*\\psloglist64a.exe" OR Image="*\\pspasswd.exe" OR Image="*\\pspasswd64.exe" OR Image="*\\pspasswd64a.exe" OR Image="*\\PsPing.exe" OR Image="*\\PsPing64.exe" OR Image="*\\PsPing64a.exe" OR Image="*\\PsService.exe" OR Image="*\\PsService64.exe" OR Image="*\\PsService64a.exe" OR Image="*\\sdelete.exe"))))
