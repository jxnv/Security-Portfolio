# Nmap Scan Utility

This is a simple utility script that performs an Nmap scan on a target IP address and saves the scan results to a file.

## Prerequisites

- Nmap should be installed on your system. You can download it from the [official Nmap website](https://nmap.org/).

## Usage

1. Update the `target` variable in the code to specify the IP address or hostname of the target you want to scan.

2. Adjust the port range and other Nmap options in the `nmap_scan` method to fit your specific requirements.

3. Run the script using the following command:

   ```bash
   ruby nmap_scan.rb
The script will execute the Nmap scan and save the results to a file named scannedresults.txt.

The scan results will be written to the file, and a message will be displayed in the console indicating that the scan results have been written.
Example
Here is an example of how to use this utility:

ruby
Copy code
# Set the target IP address or hostname
target = '192.168.0.1'

# Perform the Nmap scan and save the results
scan_result = nmap_scan(target)

# Write the scan results to a file
File.open('scannedresults.txt', 'w') do |file|
  file.puts "Scan Result for #{target}:"
  file.puts scan_result
end

puts "Scan results written to scannedresults.txt"
Note
This utility assumes that Nmap is properly installed and available in the system's PATH.
