-- Title: AD Groups Or Users Enumeration Using PowerShell - PoshModule
-- ID: 815bfc17-7fc6-4908-a55e-2f37b98cedb4
-- Status: test
-- Level: low
-- Author: frack113
-- Date: 2021-12-15
-- Tags: attack.discovery, attack.t1069.001
-- Description: Adversaries may attempt to find domain-level groups and permission settings.
-- The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group.
-- Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((Payload LIKE '%get-ADPrincipalGroupMembership%') OR (ContextInfo LIKE '%get-ADPrincipalGroupMembership%')) OR (((Payload LIKE '%get-aduser%' AND Payload LIKE '%-f %' AND Payload LIKE '%-pr %' AND Payload LIKE '%DoesNotRequirePreAuth%')) OR ((ContextInfo LIKE '%get-aduser%' AND ContextInfo LIKE '%-f %' AND ContextInfo LIKE '%-pr %' AND ContextInfo LIKE '%DoesNotRequirePreAuth%'))))
