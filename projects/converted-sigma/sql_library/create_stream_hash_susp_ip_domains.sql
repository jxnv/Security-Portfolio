-- Title: Unusual File Download from Direct IP Address
-- ID: 025bd229-fd1f-4fdb-97ab-20006e1a5368
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
-- Date: 2022-09-07
-- Tags: attack.stealth, attack.t1564.004
-- Description: Detects the download of suspicious file type from URLs with IP
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (REGEXP_LIKE(Contents, 'http[s]?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') AND (TargetFilename ILIKE '%.ps1:Zone%' OR TargetFilename ILIKE '%.bat:Zone%' OR TargetFilename ILIKE '%.exe:Zone%' OR TargetFilename ILIKE '%.vbe:Zone%' OR TargetFilename ILIKE '%.vbs:Zone%' OR TargetFilename ILIKE '%.dll:Zone%' OR TargetFilename ILIKE '%.one:Zone%' OR TargetFilename ILIKE '%.cmd:Zone%' OR TargetFilename ILIKE '%.hta:Zone%' OR TargetFilename ILIKE '%.xll:Zone%' OR TargetFilename ILIKE '%.lnk:Zone%'))
