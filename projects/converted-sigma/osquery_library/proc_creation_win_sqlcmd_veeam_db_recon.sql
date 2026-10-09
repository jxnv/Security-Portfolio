-- Title: Veeam Backup Database Suspicious Query
-- ID: 696bfb54-227e-4602-ac5b-30d9d2053312
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-04
-- Tags: attack.collection, attack.t1005
-- Description: Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%BackupRepositories%' OR CommandLine LIKE '%Backups%' OR CommandLine LIKE '%Credentials%' OR CommandLine LIKE '%HostCreds%' OR CommandLine LIKE '%SmbFileShares%' OR CommandLine LIKE '%Ssh_creds%' OR CommandLine LIKE '%VSphereInfo%')) AND (Image="*\\sqlcmd.exe" AND (CommandLine LIKE '%VeeamBackup%' AND CommandLine LIKE '%From %')))
