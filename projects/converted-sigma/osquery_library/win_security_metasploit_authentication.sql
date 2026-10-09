-- Title: Metasploit SMB Authentication
-- ID: 72124974-a68b-4366-b990-d30e0b2a190d
-- Status: test
-- Level: high
-- Author: Chakib Gzenayi (@Chak092), Hosni Mribah
-- Date: 2020-05-06
-- Tags: attack.lateral-movement, attack.t1021.002
-- Description: Alerts on Metasploit host's authentications on the domain.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((EventID = '4625' OR EventID = '4624') AND LogonType = '3' AND AuthenticationPackageName = 'NTLM' AND WorkstationName=regex("^[A-Za-z0-9]{16}$")) OR (EventID = '4776' AND Workstation=regex("^[A-Za-z0-9]{16}$")))
