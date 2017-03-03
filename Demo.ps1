#Need DNS or HostFile entry for OLRoot.
Install-WindowsFeature RSAT-DNS-Server
Add-DnsServerResourceRecordA -IPv4Address 192.168.3.20 -ComputerName DC1 -ZoneName company.pri -name OLRoot

#Not a good idea to try to push the config from a remote machine, but if you insist.
set-item trustedhosts -Value "*"
Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\xADCSDeployment" -Destination "\\OLRoot.company.pri\C`$\Program Files\WindowsPowerShell\Modules" -Recurse -Force

Start-DscConfiguration -ComputerName OLRoot.company.pri -Path "C:\DSC\Configs" -Verbose -Wait -Credential Get-Credential