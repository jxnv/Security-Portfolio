-- Title: Failed Event Log Clear Via WMI NTEventLogFile ClearEventLog
-- ID: d4f1a2b3-7c8e-4d5f-b6a9-1e0c2d3f4e5b
-- Status: test
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-07-01
-- Tags: attack.defense-impairment, attack.t1685.005
-- Description: Detects failed attempts to clear Windows event logs via the WMI NTEventLogFile ClearEventLog method.
-- Event 5858 in the WMI-Activity operational log is an error event, meaning it is only generated
-- when the WMI operation encounters an error (e.g. access denied, provider failure).
-- It could be an indication of an attacker attempting to clear event logs via WMI, but failing due to insufficient privileges or other issues.
-- Successful clearing operations will NOT produce this event; for those, correlate with
-- Security event 1102 or System event 104.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 5858 AND (Operation ILIKE '%Win32_NTEventlogFile%' AND Operation ILIKE '%cleareventlog%'))
