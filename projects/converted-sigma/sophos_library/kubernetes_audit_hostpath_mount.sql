-- Title: Container With A hostPath Mount Created
-- ID: 402b955c-8fe0-4a8c-b635-622b4ac5f902
-- Status: test
-- Level: low
-- Author: Leo Tsaousis (@laripping)
-- Date: 2024-03-26
-- Tags: attack.t1611, attack.privilege-escalation
-- Description: Detects creation of a container with a hostPath mount.
-- A hostPath volume mounts a directory or a file from the node to the container.
-- Attackers who have permissions to create a new pod in the cluster may create one with a writable hostPath volume and chroot to escape to the underlying node.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (verb = 'create' AND objectRef.resource = 'pods' AND hostPath = '*')
