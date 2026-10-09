-- Title: Triple Cross eBPF Rootkit Default LockFile
-- ID: c0239255-822c-4630-b7f1-35362bcb8f44
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-05
-- Tags: attack.stealth
-- Description: Detects the creation of the file "rootlog" which is used by the TripleCross rootkit as a way to check if the backdoor is already running.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (TargetFilename = '/tmp/rootlog')
