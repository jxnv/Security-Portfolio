-- Title: VolumeShadowCopy Symlink Creation Via Mklink
-- ID: 40b19fa6-d835-400c-b301-41f3a2baacaf
-- Status: stable
-- Level: high
-- Author: Teymur Kheirkhabarov, oscd.community
-- Date: 2019-10-22
-- Tags: attack.credential-access, attack.t1003.002, attack.t1003.003
-- Description: Shadow Copies storage symbolic link creation using operating systems utilities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%mklink%' AND CommandLine ILIKE '%HarddiskVolumeShadowCopy%'))
