-- Title: Powershell DNSExfiltration
-- ID: d59d7842-9a21-4bc6-ba98-64bfe0091355
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-01-07
-- Tags: attack.exfiltration, attack.t1048
-- Description: DNSExfiltrator allows for transferring (exfiltrate) a file over a DNS request covert channel
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%Invoke-DNSExfiltrator%') OR ((ScriptBlockText ILIKE '% -i %' AND ScriptBlockText ILIKE '% -d %' AND ScriptBlockText ILIKE '% -p %' AND ScriptBlockText ILIKE '% -doh %' AND ScriptBlockText ILIKE '% -t %')))
