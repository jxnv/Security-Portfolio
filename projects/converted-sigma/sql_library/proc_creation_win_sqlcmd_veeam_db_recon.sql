-- Title: Veeam Backup Database Suspicious Query
-- ID: 696bfb54-227e-4602-ac5b-30d9d2053312
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-04
-- Tags: attack.collection, attack.t1005
-- Description: Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%BackupRepositories%' OR CommandLine ILIKE '%Backups%' OR CommandLine ILIKE '%Credentials%' OR CommandLine ILIKE '%HostCreds%' OR CommandLine ILIKE '%SmbFileShares%' OR CommandLine ILIKE '%Ssh_creds%' OR CommandLine ILIKE '%VSphereInfo%')) AND (Image ILIKE '%\\sqlcmd.exe' AND (CommandLine ILIKE '%VeeamBackup%' AND CommandLine ILIKE '%From %')))
