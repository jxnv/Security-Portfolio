-- Title: WMI Persistence - Security
-- ID: f033f3f3-fd24-4995-97d8-a3bb17550a88
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Gleb Sukhodolskiy, Timur Zinniatullin oscd.community
-- Date: 2017-08-22
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1546.003
-- Description: Detects suspicious WMI event filter and command line event consumer based on WMI and Security Logs.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 4662 AND ObjectType = 'WMI Namespace' AND ObjectName ILIKE '%subscription%')
