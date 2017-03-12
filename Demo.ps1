#Need DNS or HostFile entry for OLRoot.
Install-WindowsFeature RSAT-DNS-Server
Add-DnsServerResourceRecordA -IPv4Address 192.168.3.20 -ComputerName DC1 -ZoneName company.pri -name OLRoot

#Not a good idea to try to push the config from a remote machine, but if you insist.
set-item trustedhosts -Value "*"
Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\xADCSDeployment" -Destination "\\OLRoot.company.pri\C`$\Program Files\WindowsPowerShell\Modules" -Recurse -Force
Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\xSMBShare" -Destination "\\olroot.company.pri\C`$\Program Files\WindowsPowerShell\Modules" -recurse -Force
Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\xADCSDeployment" -Destination "\\EntRoot.company.pri\C`$\Program Files\WindowsPowerShell\Modules" -Recurse -Force
Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\xSMBShare" -Destination "\\EntRoot.company.pri\C`$\Program Files\WindowsPowerShell\Modules" -recurse -Force
Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\xDNSServer" -Destination "\\DC1.company.pri\C`$\Program Files\WindowsPowerShell\Modules" -recurse -Force
Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\xWebAdministration" -Destination "\\EntRoot.company.pri\C`$\Program Files\WindowsPowerShell\Modules" -recurse -Force


Start-DscConfiguration -ComputerName OLRoot.company.pri -Path "C:\DSC\Configs" -Verbose -Wait -Credential Get-Credential

#After registry settings, need certsvc restart:
restart-service certsvc

#and publish the CRL
certutil -crl

#Publish the root certificate through LDAP.
#Optionally, distribute through group policy.
#Optionally, distribute through DSC.  This may not work for credential encryption.
certutil -dspublish -f C:\Temp\OLROOT_CompanyRoot.crt RootCA 

#Script Resources (or certutil custom resource) to dspublish and addroot or put it in GPO
        #certutil –dspublish –f orca1_ContosoRootCA.crt RootCA
        #certutil –addstore –f root orca1_ContosoRootCA.crt
        #certutil –addstore –f root ContosoRootCA.crl

