require 'open3'

#main nmap scan structure, ports, and 'command' variable can be adujusted to fit certain situations.
def nmap_scan(target)
  command = "nmap -p 1-1000 -T4 -A -v #{target}"
  stdout, stderr, status = Open3.capture3(command)

  if status.success?
    return stdout
  else
    puts "Command execution failed: #{stderr}"
    return nil
  end
end

#replace values as needed
#+++++++++++++++++++++
target = '0.0.0.0'
scan_result = nmap_scan(target)
#+++++++++++++++++++++
File.open('scannedresults.txt', 'w') do |file|
  file.puts "Scan Result for #{target}:"
  file.puts scan_result
end

puts "Scan results written to scannedresults.txt"

