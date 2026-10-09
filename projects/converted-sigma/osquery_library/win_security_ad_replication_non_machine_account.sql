-- Title: Active Directory Replication from Non Machine Account - DcSync Indicator
-- ID: 17d619c1-e020-4347-957e-1d1207455c93
-- Status: test
-- Level: medium
-- Author: Roberto Rodriguez @Cyb3rWard0g
-- Date: 2019-07-26
-- Tags: attack.credential-access, attack.t1003.006
-- Description: Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((EventID = '4662' AND (Properties LIKE '%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%' OR Properties LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%' OR Properties LIKE '%9923a32a-3607-11d2-b9be-0000f87a36b2%' OR Properties LIKE '%89e95b76-444d-4c62-991a-0facbeda640c%')) AND NOT ((SubjectUserName="*$")) AND NOT (((SubjectDomainName = 'Window Manager') OR ((SubjectUserName="NT AUT*" OR SubjectUserName="MSOL_*")))))
