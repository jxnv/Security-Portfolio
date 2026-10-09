-- Title: PUA - Adidnsdump Execution
-- ID: 26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160
-- Status: test
-- Level: low
-- Author: frack113
-- Date: 2022-01-01
-- Tags: attack.discovery, attack.t1018
-- Description: This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks Python 3 and python.exe must be installed,
-- Usee to Query/modify DNS records for Active Directory integrated DNS via LDAP
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%\\python.exe' AND CommandLine ILIKE '%adidnsdump%')
