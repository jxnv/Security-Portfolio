-- Title: System Information Discovery Using Ioreg
-- ID: 2d5e7a8b-f484-4a24-945d-7f0efd52eab0
-- Status: test
-- Level: medium
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date: 2023-12-20
-- Tags: attack.discovery, attack.t1082
-- Description: Detects the use of "ioreg" which will show I/O Kit registry information.
-- This process is used for system information discovery.
-- It has been observed in-the-wild by calling this process directly or using bash and grep to look for specific strings.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%-l%' OR CommandLine ILIKE '%-c%')) AND ((CommandLine ILIKE '%AppleAHCIDiskDriver%' OR CommandLine ILIKE '%IOPlatformExpertDevice%' OR CommandLine ILIKE '%Oracle%' OR CommandLine ILIKE '%Parallels%' OR CommandLine ILIKE '%USB Vendor Name%' OR CommandLine ILIKE '%VirtualBox%' OR CommandLine ILIKE '%VMware%')) AND ((Image ILIKE '%/ioreg') OR (CommandLine ILIKE '%ioreg%')))
