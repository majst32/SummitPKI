Configuration PKIDeploy {

        Import-DSCresource -ModuleName PSDesiredStateConfiguration,
            @{ModuleName="xADCSDeployment";ModuleVersion="1.1.0.0"},
            @{ModuleName="xSMBShare";ModuleVersion="2.0.0.0"},
            @{ModuleName="xDNSServer";ModuleVersion="1.7.0.0"}

    Node $AllNodes.Where{$_.Role -eq "ADCSRoot"}.NodeName {

        $ADCSRoot = $ConfigurationData.ADCSRoot

        $Secure = ConvertTo-SecureString -String "$($Node.Password)" -AsPlainText -Force 
        $Credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure 

        foreach ($Feature in $ADCSRoot.Features) {

            WindowsFeature $Feature {
                Name = $Feature
                Ensure = 'Present'
                }
                
        }
                 
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
        
        #bunch of certutil stuff
        #Remove default CRL Distribution Points
        #Set new CRL Distribution Points
        # HKLM\System\CurrentControlSet\Services\Certsvc\Configuration\<YourCAName>
        # certutil -setreg CA\CRLPublicationURLs "1:C:\Windows\system32\CertSrv\CertEnroll\%3%8.crl\n2:http://www.contoso.com/pki/%3%8.crl"
        # certutil –setreg CA\CACertPublicationURLs "2:http://www.contoso.com/pki/%1_%3%4.crt"
        # Certutil -setreg CA\CRLOverlapPeriodUnits 12
        # Certutil -setreg CA\CRLOverlapPeriod "Hours"
        # Certutil -setreg CA\ValidityPeriodUnits 10
        #Certutil -setreg CA\ValidityPeriod "Years"
        #certutil -setreg CA\DSConfigDN CN=Configuration,DC=corp,DC=contoso,DC=com
        
        #Still need?
        
        #restart-service certsvc
        #certutil -crl

        $Key = "HKEY_Local_Machine\System\CurrentControlSet\Services\CertSvc\Configuration\$($ADCSRoot.CACN)"
        foreach ($Setting in $ADCSRoot.RegistrySettings) {

            Registry $Setting.Name  {
                Ensure = 'Present'
                Key = "$Key"
                ValueName = "$($Setting.Name)"
                ValueType = "$($Setting.Type)"
                ValueData = "$($Setting.Value)"
                }
            }

            xSMBShare RootShare {
                Name = "RootShare"
                Path = "C:\Windows\System32\certsrv\certenroll"
                }   

        }  #End ADCSRoot

    Node $AllNodes.Where({$_.Role -eq "DC"}).NodeName {
        
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
          
          #Certutil -addstore -root CRLFile
           
          foreach ($Feature in $ADCSSub.Features) {

            WindowsFeature $Feature {
                Name = $Feature
                Ensure = 'Present'
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
                 



 <#       xCertificateImport RootImport {
            Ensure = "Present"
            Path = "\\OLRoot\RootShare\OLROOT_CompanyRoot.crt"
            Location = 'LocalMachine'
            Store = 'Root'
        }
#>
            
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
