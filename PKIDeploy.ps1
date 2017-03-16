﻿Configuration PKIDeploy {

        Import-DSCresource -ModuleName PSDesiredStateConfiguration,
            @{ModuleName="xADCSDeployment";ModuleVersion="1.1.0.0"},
            @{ModuleName="xSMBShare";ModuleVersion="2.0.0.0"},
            @{ModuleName="xDNSServer";ModuleVersion="1.7.0.0"},
            @{ModuleName="xWebAdministration";ModuleVersion="1.17.0.0"},
            @{ModuleName="mACLs";ModuleVersion="1.0.0.0"},
            @{ModuleName="xPendingReboot";ModuleVersion="0.3.0.0"}

    Node $AllNodes.Where{$_.Role -eq "ADCSRoot"}.NodeName {

        #Set up all the variables
        $ADCSRoot = $ConfigurationData.ADCSRoot
        $Secure = ConvertTo-SecureString -String "$($Node.Password)" -AsPlainText -Force 
        $Credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure 

        #Install Windows Features
        foreach ($Feature in $ADCSRoot.Features) {

            WindowsFeature $Feature {
                Name = $Feature
                Ensure = 'Present'
                }
                
        }
        #If CA hasn't been installed yet, set $DSCMachineStatus to $True to set up for reboot after.
        script SetForReboot {
            testScript = {
                    try {
                        Install-AdcsCertificationAuthority -whatif -ErrorAction Stop
                        return $False
                    }
                    catch {
                        return $True
                    }
            }
            setScript = {
                $DSCMachineStatus = 1
                }
            getscript = {
                return @{Result = $DSCMachineStatus}
            }
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
        }


        #Configure Root CA         
            xAdcsCertificationAuthority ADCSConfig {
                CAType = $ADCSRoot.CAType
                Credential = $Credential
                CryptoProviderName = $Node.ADCSCryptoProviderName
                HashAlgorithmName = $Node.ADCSHashAlgorithmName
                KeyLength = $Node.ADCSKeyLength
                CACommonName = $ADCSRoot.CACN
                CADistinguishedNameSuffix = $ADCSRoot.CADNSuffix
                DatabaseDirectory = $Node.CADatabasePath
                LogDirectory = $Node.CALogPath
                ValidityPeriod = $Node.ADCSValidityPeriod
                ValidityPeriodUnits = $Node.ADCSValidityPeriodUnits
                Ensure = 'Present'
                DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
                }
        
        #Configure Root CA settings:  CRL and Cert publication URLs
        
        #certutil -crl

        $Key = "HKEY_Local_Machine\System\CurrentControlSet\Services\CertSvc\Configuration\$($ADCSRoot.CACN)"
        foreach ($Setting in $ADCSRoot.RegistrySettings) {

            Registry $Setting.Name  {
                Ensure = 'Present'
                Key = "$Key"
                ValueName = "$($Setting.Name)"
                ValueType = "$($Setting.Type)"
                ValueData = "$($Setting.Value)"
                DependsOn = '[xADCSCertificationAuthority]ADCSConfig'
                }
            }

            #Reboot to pick up certutil settings if needed, but only if previous script set the flag for reboot.
            xPendingReboot RebootforCertsvc {
                Name = 'Reboot'
                DependsOn = '[Registry]DSConfigDN','[Script]SetForReboot'
            }

            #certutil -crl

            #Change this into a file resource that puts the file somewhere else if time
            xSMBShare RootShare {
                Name = "RootShare"
                Path = "C:\Windows\System32\certsrv\certenroll"
                }   

            WaitForAll WFADCSSub {
                NodeName = 'ENTROOT'
                ResourceName = '[xADCSCertificationAuthority]ADCSSub'
                RetryIntervalSec = 60
                RetryCount = 30
                }


        }  #End ADCSRoot

    Node $AllNodes.Where({$_.Role -eq "DC"}).NodeName {
        
        #Create a DNS record for www.company.pri
        xDnsRecord PKIRecord {
            Name = "www"
            Zone = $Node.DNSSuffix
            PsDscRunAsCredential = $DACredential
            Ensure = 'Present'
            Type = 'ARecord'
            Target = $Node.EntRootIP
            }
    }

        #ADCS Subordinate region
        
        Node $AllNodes.Where{$_.Role -eq "ADCSSub"}.NodeName {

        $Secure = ConvertTo-SecureString -String "$($Node.Password)" -AsPlainText -Force 
        $Credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure 
        $DACredential = New-Object -TypeName Pscredential -ArgumentList "Company.pri\administrator", $Secure

        #NonNodeData
        $ADCSSub = $ConfigurationData.ADCSSub
        $ADCSRoot = $ConfigurationData.ADCSRoot
        $DomainData = $ConfigurationData.DomainData

        $OLRoot = $AllNodes.Where({$_.Role -eq "ADCSRoot"}).NodeName
        
        WaitForAll WFADCSRootInstall {
            NodeName = 'olroot.company.pri'
            ResourceName = '[xSMBShare]RootShare'
            RetryIntervalSec = 60
            RetryCount = 30
            }
        
        #Copy Root Cert from OLRoot
        File RootCert {
            SourcePath = "\\$OLRoot\RootShare"
            DestinationPath = "C:\temp"
            Ensure = 'Present'
            MatchSource = $True
            Recurse = $True
            Credential = $Credential
            }
#>
        $RootFile = "$($OlRoot.Split(".")[0])_$($ADCSRoot.CACN).crt"

        #Import Root Cert into Trusted Root Store on SubCA
        Script ImportRoot {
            TestScript = {
                $Issuer = $Using:ADCSRoot.CaCN
                $Cert = get-childitem -Path Cert:\LocalMachine\Root | Where-Object {$_.Issuer -like "*$issuer*"}
                if ($Cert -eq $Null) {return $False}
                else {return $True}
                }
            SetScript = {
                Import-Certificate -FilePath "C:\temp\$Using:RootFile" -CertStoreLocation "Cert:\LocalMachine\Root"
                }
            GetScript = {
                $Issuer = $Using:ADCSRoot.CaCN
                $Result = Get-ChildItem -path Cert:\LocalMachine\Root | where-object {$_Issuer -like "$Issuer*"} | select-object Subject
                return @{Result=$Result}
                }
            }
          
          #Certutil -addstore -root CRLFile - need code
           
          foreach ($Feature in $ADCSSub.Features) {

            WindowsFeature $Feature {
                Name = $Feature
                Ensure = 'Present'
                }
                
        }
           
            #Create directory structure for virtual directory
            File PKICRLDir {
                Ensure = 'Present'
                Type = 'Directory'
                DestinationPath = 'C:\pki'
                }
           
           #Create file
            File PKICRL {
                Ensure = 'Present'
                Type = 'File'
                DestinationPath = 'C:\pki\cps.txt'
                Contents = 'Example CPS Statement'
                }
            #Create Share

            xSmbShare PKIShare {
                Name = 'PKI'
                Path = 'C:\pki'
                FullAccess = "SYSTEM","Company\Domain Admins"
                ChangeAccess = "Company\Cert Publishers"
                }
        

        #Install website for CRL distribution
            xWebvirtualDirectory PKI {
                Website = "Default Web Site"
                Name = 'PKI'
                PhysicalPath = 'C:\pki'
                Ensure = 'Present'
                WebApplication = ''
                }

        #Set ACLs on folder for CRL publishing
            FileACLs CertPublishers {
                Path = "C:\PKI"
                IdentityReference = "Company\Cert Publishers"
                FileSystemRights = 'Modify'
                AccessControlType = 'Allow'
                InheritanceFlags = "ContainerInherit","ObjectInherit"
                PropagationFlags = "None"
                Ensure = 'Present'
            }

            FileACLs Anonymous {
                Path = "C:\PKI"
                IdentityReference = "IIS AppPool\DefaultAppPool"
                FileSystemRights = 'Read','ReadAndExecute','ListDirectory'
                AccessControlType = 'Allow'
                InheritanceFlags = "ContainerInherit","ObjectInherit"
                PropagationFlags = "None"
                Ensure = 'Present'
            }
 
            Script DoubleEscaping {
                TestScript = {
                    if ((Get-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath ‘IIS:\sites\Default Web Site\PKI’ | Select-Object AllowDoubleEscaping) -eq $True) {
                        return $True
                        }
                    else {return $False}
                    }
                SetScript = {
                    $filter = Get-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath ‘IIS:\sites\Default Web Site\PKI’
                    $Filter.AllowDoubleEscaping = $True
                    $Filter | Set-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath ‘IIS:\sites\Default Web Site\PKI'
                    }
                GetScript = {
                    $Filter = (Get-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath ‘IIS:\sites\Default Web Site\PKI’ | Select-Object AllowDoubleEscaping)
                    return @{Result = $Filter.AllowDoubleEscaping}
                    }
                }
                                               
            xAdcsCertificationAuthority ADCSSub {
                CAType = $ADCSSub.CAType
                Credential = $DACredential
                CryptoProviderName = $Node.ADCSCryptoProviderName
                HashAlgorithmName = $Node.ADCSHashAlgorithmName
                KeyLength = $Node.ADCSKeyLength
                CACommonName = $ADCSSub.CACN
                CADistinguishedNameSuffix = $ADCSSub.CADNSuffix
                DatabaseDirectory = $Node.CADatabasePath
                LogDirectory = $Node.CALogPath
                ParentCA = "$($OLRoot)\$($ADCSRoot.CACN)"
                Ensure = 'Present'
                DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
                }                 



            
<#            WindowsFeature RSAT-AD-PowerShell {
                Name = "RSAT-AD-PowerShell"
                Ensure = 'Present'
                }

            Script DSPublish {
                Credential = $DACredential
                TestScript = {
                    try {
                        Get-ADObject -Identity "CN=CompanyRoot,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=Company,DC=Pri"
                        Return $True
                    }
                    Catch {
                        Return $False
                        }
                    }
                SetScript = {
                    #optionally import-certificate -filepath C:\Temp\OLRoot_CompanyRoot.crt -CertStoreLocation Cert:\LocalMachine\Root
                    #$RootShort = $Using:OLRoot.split(".")[0]
                    #$CertName = "$(RootShort)_$Using:ADCSRoot.CACN
                    certutil -dspublish -f "C:\Temp\OLROOT_CompanyRoot.crt" RootCA -dc DC1 -v
                    }
                GetScript = {
                    Return @{Result = (Get-ADObject -Identity "CN=CompanyRoot,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=Company,DC=Pri").Name}
                    }
                }
#>            
        #Script Resources (or certutil custom resource) to dspublish and addroot or put it in GPO
        #certutil –dspublish –f orca1_ContosoRootCA.crt RootCA
        #certutil –addstore –f root orca1_ContosoRootCA.crt
        #certutil –addstore –f root ContosoRootCA.crl

    }
}

PKIDeploy -ConfigurationData .\PKIDeploy.psd1 -outputpath "C:\DSC\Configs"
