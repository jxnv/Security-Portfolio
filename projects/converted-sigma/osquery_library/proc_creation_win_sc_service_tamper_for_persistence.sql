-- Title: Potential Persistence Attempt Via Existing Service Tampering
-- ID: 38879043-7e1e-47a9-8d46-6bec88e201df
-- Status: test
-- Level: medium
-- Author: Sreeman
-- Date: 2020-09-29
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1543.003, attack.t1574.011
-- Description: Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%sc %' AND CommandLine LIKE '%config %' AND CommandLine LIKE '%binpath=%')) OR ((CommandLine LIKE '%sc %' AND CommandLine LIKE '%failure%' AND CommandLine LIKE '%command=%'))) OR (((CommandLine LIKE '%.sh%' OR CommandLine LIKE '%.exe%' OR CommandLine LIKE '%.dll%' OR CommandLine LIKE '%.bin$%' OR CommandLine LIKE '%.bat%' OR CommandLine LIKE '%.cmd%' OR CommandLine LIKE '%.js%' OR CommandLine LIKE '%.msh$%' OR CommandLine LIKE '%.reg$%' OR CommandLine LIKE '%.scr%' OR CommandLine LIKE '%.ps%' OR CommandLine LIKE '%.vb%' OR CommandLine LIKE '%.jar%' OR CommandLine LIKE '%.pl%')) AND (((CommandLine LIKE '%reg %' AND CommandLine LIKE '%add %' AND CommandLine LIKE '%FailureCommand%')) OR ((CommandLine LIKE '%reg %' AND CommandLine LIKE '%add %' AND CommandLine LIKE '%ImagePath%')))))
