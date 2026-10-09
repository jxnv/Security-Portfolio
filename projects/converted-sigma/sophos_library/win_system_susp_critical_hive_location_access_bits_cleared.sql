-- Title: Critical Hive In Suspicious Location Access Bits Cleared
-- ID: 39f919f3-980b-4e6f-a975-8af7e507ef2b
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-05-15
-- Tags: attack.credential-access, attack.t1003.002
-- Description: Detects events from the Kernel-General ETW indicating that the access bits of a hive with a system like hive name located in the temp directory have been reset.
-- This occurs when an application tries to access a hive and the hive has not be recognized since the last 7 days (by default).
-- Registry hive dumping utilities such as QuarksPwDump were seen emitting this behavior.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 16 AND Provider_Name = 'Microsoft-Windows-Kernel-General' AND (HiveName ILIKE '%\\Temp\\SAM%' OR HiveName ILIKE '%\\Temp\\SECURITY%'))
