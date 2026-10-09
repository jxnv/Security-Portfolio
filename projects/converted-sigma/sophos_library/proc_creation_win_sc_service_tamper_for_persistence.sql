-- Title: Potential Persistence Attempt Via Existing Service Tampering
-- ID: 38879043-7e1e-47a9-8d46-6bec88e201df
-- Status: test
-- Level: medium
-- Author: Sreeman
-- Date: 2020-09-29
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1543.003, attack.t1574.011
-- Description: Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%sc %' AND CommandLine ILIKE '%config %' AND CommandLine ILIKE '%binpath=%')) OR ((CommandLine ILIKE '%sc %' AND CommandLine ILIKE '%failure%' AND CommandLine ILIKE '%command=%'))) OR (((CommandLine ILIKE '%.sh%' OR CommandLine ILIKE '%.exe%' OR CommandLine ILIKE '%.dll%' OR CommandLine ILIKE '%.bin$%' OR CommandLine ILIKE '%.bat%' OR CommandLine ILIKE '%.cmd%' OR CommandLine ILIKE '%.js%' OR CommandLine ILIKE '%.msh$%' OR CommandLine ILIKE '%.reg$%' OR CommandLine ILIKE '%.scr%' OR CommandLine ILIKE '%.ps%' OR CommandLine ILIKE '%.vb%' OR CommandLine ILIKE '%.jar%' OR CommandLine ILIKE '%.pl%')) AND (((CommandLine ILIKE '%reg %' AND CommandLine ILIKE '%add %' AND CommandLine ILIKE '%FailureCommand%')) OR ((CommandLine ILIKE '%reg %' AND CommandLine ILIKE '%add %' AND CommandLine ILIKE '%ImagePath%')))))
