-- Title: Service Reconnaissance Via Wmic.EXE
-- ID: 76f55eaa-d27f-4213-9d45-7b0e4b60bbae
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-14
-- Tags: attack.execution, attack.t1047
-- Description: An adversary might use WMI to check if a certain remote service is running on a remote device.
-- When the test completes, a service information will be displayed on the screen if it exists.
-- A common feedback message is that "No instance(s) Available" if the service queried is not running.
-- A common error message is "Node - (provided IP or default) ERROR Description =The RPC server is unavailable" if the provided remote host is unreachable
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%service%') AND ((Image ILIKE '%\\WMIC.exe') OR (OriginalFileName = 'wmic.exe'))) AND NOT ((((CommandLine ILIKE '%stopservice%' OR CommandLine ILIKE '%startservice%')) OR ((CommandLine ILIKE '%Change%' OR CommandLine ILIKE '%Create%' OR CommandLine ILIKE '%Delete%' OR CommandLine ILIKE '%PauseService%' OR CommandLine ILIKE '%ResumeService%' OR CommandLine ILIKE '%SetSecurityDescriptor%' OR CommandLine ILIKE '%StartService%' OR CommandLine ILIKE '%StopService%' OR CommandLine ILIKE '%UserControlService%')))))
