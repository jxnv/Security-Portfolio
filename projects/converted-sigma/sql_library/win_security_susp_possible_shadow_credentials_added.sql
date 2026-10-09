-- Title: Possible Shadow Credentials Added
-- ID: f598ea0c-c25a-4f72-a219-50c44411c791
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Elastic (idea)
-- Date: 2022-10-17
-- Tags: attack.persistence, attack.credential-access, attack.defense-impairment, attack.t1556
-- Description: Detects possible addition of shadow credentials to an active directory object.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 5136 AND AttributeLDAPDisplayName = 'msDS-KeyCredentialLink')
