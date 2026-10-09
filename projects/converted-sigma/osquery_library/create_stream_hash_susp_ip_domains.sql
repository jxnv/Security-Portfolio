-- Title: Unusual File Download from Direct IP Address
-- ID: 025bd229-fd1f-4fdb-97ab-20006e1a5368
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
-- Date: 2022-09-07
-- Tags: attack.stealth, attack.t1564.004
-- Description: Detects the download of suspicious file type from URLs with IP
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (Contents=regex("http[s]?://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}") AND (TargetFilename LIKE '%.ps1:Zone%' OR TargetFilename LIKE '%.bat:Zone%' OR TargetFilename LIKE '%.exe:Zone%' OR TargetFilename LIKE '%.vbe:Zone%' OR TargetFilename LIKE '%.vbs:Zone%' OR TargetFilename LIKE '%.dll:Zone%' OR TargetFilename LIKE '%.one:Zone%' OR TargetFilename LIKE '%.cmd:Zone%' OR TargetFilename LIKE '%.hta:Zone%' OR TargetFilename LIKE '%.xll:Zone%' OR TargetFilename LIKE '%.lnk:Zone%'))
