-- Title: Suspicious Execution Of Renamed Sysinternals Tools - Registry
-- ID: f50f3c09-557d-492d-81db-9064a8d4e211
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-24
-- Tags: attack.resource-development, attack.t1588.002
-- Description: Detects the creation of the "accepteula" key related to the Sysinternals tools being created from executables with the wrong name (e.g. a renamed Sysinternals tool)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%\\Active Directory Explorer%' OR TargetObject ILIKE '%\\Handle%' OR TargetObject ILIKE '%\\LiveKd%' OR TargetObject ILIKE '%\\ProcDump%' OR TargetObject ILIKE '%\\Process Explorer%' OR TargetObject ILIKE '%\\PsExec%' OR TargetObject ILIKE '%\\PsLoggedon%' OR TargetObject ILIKE '%\\PsLoglist%' OR TargetObject ILIKE '%\\PsPasswd%' OR TargetObject ILIKE '%\\PsPing%' OR TargetObject ILIKE '%\\PsService%' OR TargetObject ILIKE '%\\SDelete%') AND TargetObject ILIKE '%\\EulaAccepted') AND NOT (((Image ILIKE '%\\ADExplorer.exe' OR Image ILIKE '%\\ADExplorer64.exe' OR Image ILIKE '%\\ADExplorer64a.exe' OR Image ILIKE '%\\handle.exe' OR Image ILIKE '%\\handle64.exe' OR Image ILIKE '%\\handle64a.exe' OR Image ILIKE '%\\livekd.exe' OR Image ILIKE '%\\livekd64.exe' OR Image ILIKE '%\\procdump.exe' OR Image ILIKE '%\\procdump64.exe' OR Image ILIKE '%\\procdump64a.exe' OR Image ILIKE '%\\procexp.exe' OR Image ILIKE '%\\procexp64.exe' OR Image ILIKE '%\\procexp64a.exe' OR Image ILIKE '%\\PsExec.exe' OR Image ILIKE '%\\PsExec64.exe' OR Image ILIKE '%\\PsExec64a.exe' OR Image ILIKE '%\\PsLoggedon.exe' OR Image ILIKE '%\\PsLoggedon64.exe' OR Image ILIKE '%\\psloglist.exe' OR Image ILIKE '%\\psloglist64.exe' OR Image ILIKE '%\\psloglist64a.exe' OR Image ILIKE '%\\pspasswd.exe' OR Image ILIKE '%\\pspasswd64.exe' OR Image ILIKE '%\\pspasswd64a.exe' OR Image ILIKE '%\\PsPing.exe' OR Image ILIKE '%\\PsPing64.exe' OR Image ILIKE '%\\PsPing64a.exe' OR Image ILIKE '%\\PsService.exe' OR Image ILIKE '%\\PsService64.exe' OR Image ILIKE '%\\PsService64a.exe' OR Image ILIKE '%\\sdelete.exe'))))
