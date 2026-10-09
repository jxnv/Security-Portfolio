-- Title: Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock
-- ID: a861d835-af37-4930-bcd6-5b178bfb54df
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-12-28
-- Tags: attack.credential-access, attack.t1558.003
-- Description: Detects PowerShell scripts that utilize native PowerShell Identity modules to request Kerberos tickets.
-- This behavior is typically seen during a Kerberoasting or silver ticket attack. A TGS request is issued by
-- the KerberosRequestorSecurityToken constructor, resulting tickets are cached in LSA and become
-- extractable by other tools later on.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ScriptBlockText ILIKE '%System.IdentityModel.Tokens.KerberosRequestorSecurityToken%')
