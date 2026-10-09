-- Title: WCE wceaux.dll Access
-- ID: 1de68c67-af5c-4097-9c85-fe5578e09e67
-- Status: test
-- Level: critical
-- Author: Thomas Patzke
-- Date: 2017-06-14
-- Tags: attack.credential-access, attack.t1003, attack.s0005
-- Description: Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((EventID = '4656' OR EventID = '4663') AND ObjectName="*\\wceaux.dll")
