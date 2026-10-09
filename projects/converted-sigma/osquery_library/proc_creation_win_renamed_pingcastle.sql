-- Title: Renamed PingCastle Binary Execution
-- ID: 2433a154-bb3d-42e4-86c3-a26bdac91c45
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
-- Date: 2024-01-11
-- Tags: attack.execution, attack.stealth, attack.t1059, attack.t1202
-- Description: Detects the execution of a renamed "PingCastle" binary based on the PE metadata fields.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((OriginalFileName = 'PingCastleReporting.exe' OR OriginalFileName = 'PingCastleCloud.exe' OR OriginalFileName = 'PingCastle.exe')) OR ((CommandLine LIKE '%--scanner aclcheck%' OR CommandLine LIKE '%--scanner antivirus%' OR CommandLine LIKE '%--scanner computerversion%' OR CommandLine LIKE '%--scanner foreignusers%' OR CommandLine LIKE '%--scanner laps_bitlocker%' OR CommandLine LIKE '%--scanner localadmin%' OR CommandLine LIKE '%--scanner nullsession%' OR CommandLine LIKE '%--scanner nullsession-trust%' OR CommandLine LIKE '%--scanner oxidbindings%' OR CommandLine LIKE '%--scanner remote%' OR CommandLine LIKE '%--scanner share%' OR CommandLine LIKE '%--scanner smb%' OR CommandLine LIKE '%--scanner smb3querynetwork%' OR CommandLine LIKE '%--scanner spooler%' OR CommandLine LIKE '%--scanner startup%' OR CommandLine LIKE '%--scanner zerologon%')) OR (CommandLine LIKE '%--no-enum-limit%') OR ((CommandLine LIKE '%--healthcheck%' AND CommandLine LIKE '%--level Full%')) OR ((CommandLine LIKE '%--healthcheck%' AND CommandLine LIKE '%--server %'))) AND NOT (((Image="*\\PingCastleReporting.exe" OR Image="*\\PingCastleCloud.exe" OR Image="*\\PingCastle.exe"))))
