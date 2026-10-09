// Title: Potentially Suspicious Shell Script Creation in Profile Folder
// ID: 13f08f54-e705-4498-91fd-cce9d9cee9f1
// Status: test
// Level: low
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-06-02
// Tags: attack.persistence
// Description: Detects the creation of shell scripts under the "profile.d" path.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_file_path contains "/etc/profile.d/" and (action_file_path endswith ".csh" or action_file_path endswith ".sh"))
