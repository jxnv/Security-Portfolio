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

SELECT * FROM processes WHERE (((CommandLine LIKE '%-l%' OR CommandLine LIKE '%-c%')) AND ((CommandLine LIKE '%AppleAHCIDiskDriver%' OR CommandLine LIKE '%IOPlatformExpertDevice%' OR CommandLine LIKE '%Oracle%' OR CommandLine LIKE '%Parallels%' OR CommandLine LIKE '%USB Vendor Name%' OR CommandLine LIKE '%VirtualBox%' OR CommandLine LIKE '%VMware%')) AND ((Image="*/ioreg") OR (CommandLine LIKE '%ioreg%')))
