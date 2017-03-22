Configuration PKIDeploy {

        Import-DSCresource -ModuleName PSDesiredStateConfiguration,
            @{ModuleName="xADCSDeployment";ModuleVersion="1.1.0.0"},
            @{ModuleName="xSMBShare";ModuleVersion="2.0.0.0"},
            @{ModuleName="xDNSServer";ModuleVersion="1.7.0.0"},
            @{ModuleName="xWebAdministration";ModuleVersion="1.17.0.0"},
            #@{ModuleName="mACLs";ModuleVersion="1.0.0.0"},
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

        script SetCRLCDP {
            TestScript = {
                if ((Get-CACrlDistributionPoint).count -ne 2) {Return $False}
                else {Return $True}
                }
            SetScript = {
               $crllist = Get-CACrlDistributionPoint; foreach ($crl in $crllist) {Remove-CACrlDistributionPoint $crl.uri -Force}
               Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl -PublishToServer -Force
               $CRLURL = $using:ADCSRoot.CRLURL
               Add-CACRLDistributionPoint -Uri "http://$($CRLURL)/pki/%3%8.crl" -AddToCertificateCDP -Force
               }
            getScript = {
               return @{Result=(Get-CACrlDistributionPoint).Count}
               }
            }

        script ClearAIAList {
            TestScript = {
                if ((Get-CAAuthorityInformationAccess).Count -ne 0) {return $False}
                else {Return $True}
                }
            SetScript = {
                $aialist = Get-CAAuthorityInformationAccess; foreach ($aia in $aialist) {Remove-CAAuthorityInformationAccess $aia.uri -Force}
                }
            GetScript = {
                return @{Result=(Get-CAAuthorityInformationAccess).Count}
                }
            }

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

            #publish CRL
            script PublishCRL {
                testScript = {
                    try {
                        #$CACN=$Using:ADCSRoot.CACN
                        get-childitem -Path "C:\Windows\System32\certsrv\certenroll\$($CACN).crl" -erroraction stop
                        return $True
                        }
                    catch {
                        return $False
                        }
                    }
                setscript = {
                    certutil -crl
                    }
                getscript = {
                    Return @{Result = "None"}
                    }
            }

            #Copy the root certificate into a temp directory so don't have to get it from the admin share
            File CopyRootCert {
                Type = 'Directory'
                DestinationPath = "C:\temp"
                SourcePath = "C:\Windows\System32\certsrv\certenroll"
                Recurse = $true
                MatchSource = $true
                Ensure = 'Present'
                DependsOn = '[xAdcsCertificationAuthority]ADCSConfig'
                }
            
            #Share folder so subCA and dc can get to the certificate
            xSMBShare RootShare {
                Name = "RootShare"
                Path = "C:\temp"
                DependsOn = '[xADCSCertificationAuthority]ADCSConfig'
                }   

            #Now wait until the subCA is complete
            WaitForAll WFADCSSub {
                NodeName = 'ENTSUB'
                ResourceName = '[xADCSCertificationAuthority]ADCSSub'
                RetryIntervalSec = 60
                RetryCount = 30
                DependsOn = '[xSMBShare]RootShare'
                }

            #After subordinate is installed, copy the cert request to the root.
            File ADCSCertReq {
                Ensure = 'Present'
                SourcePath = "\\ENTSub\C$\ENTSub.$($node.DNSSuffix)_IssuingCA-$($ADCSRoot.CACN).req"
                DestinationPath = "C:\ENTSub.$($node.DNSSuffix)_IssuingCA-$($ADCSRoot.CACN).req"
                #Contents =  "$($Node.Nodename).$($node.DNSSuffix)_IssuingCA-$($ADCSRoot.CompanyRoot).req"
                MatchSource = $True
                Type = 'File'
                Credential = $Credential
                }
                
        

        }  #End ADCSRoot

    Node $AllNodes.Where({$_.Role -eq "DC"}).NodeName {

    $Secure = ConvertTo-SecureString -String "$($Node.Password)" -AsPlainText -Force 
    $Credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure 
    $OLRoot = $AllNodes.Where({$_.Role -eq "ADCSRoot"}).NodeName
        
        #Create a DNS record for www.company.pri
        xDnsRecord PKIRecord {
            Name = "www"
            Zone = $Node.DNSSuffix
            PsDscRunAsCredential = $DACredential
            Ensure = 'Present'
            Type = 'ARecord'
            Target = $Node.ENTSubIP
        }
        
        
        #Wait for share with root certificate to be available
        WaitForAll WaitForRoot {
            NodeName = 'OLRoot.company.pri'
            ResourceName = '[xSMBShare]RootShare'
            Retryintervalsec = 60
            RetryCount = 30
        }

          File RootCerttoDC {
            SourcePath = "\\$OLRoot\RootShare"
            DestinationPath = "C:\temp"
            Type = 'Directory'
            MatchSource = $True
            Recurse = $True
            Ensure = 'Present'
            Credential = $Credential
            DependsOn = '[WaitForAll]WaitForRoot'
            }

        #publish root certificate to AD
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
                    certutil -dspublish -f "C:\Temp\OLROOT_CompanyRoot.crt" RootCA
                    }
                GetScript = {
                    Return @{Result = (Get-ADObject -Identity "CN=CompanyRoot,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=Company,DC=Pri").Name}
                    }
                }
 
    }

        #ADCS Subordinate region
        
        Node $AllNodes.Where{$_.Role -eq "ADCSSub"}.NodeName {

        $Secure = ConvertTo-SecureString -String "$($Node.Password)" -AsPlainText -Force 
        $Credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure 
        $DACredential = new-Object -typeName pscredential -ArgumentList "Company.pri\administrator", $secure

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
            PsDscRunAsCredential = $Credential
            }
        
        WaitForAll WFDSPublish {
            NodeName = 'DC1'
            ResourceName = '[Script]DSPublish'
            RetryIntervalSec = 60
            RetryCount = 30
            PsDscRunAsCredential = $Credential
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
        #certutil –addstore –f root orca1_ContosoRootCA.crt
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
          <#
            $Store = certutil -store root

            $count = 0
            foreach ($obj in $store) { 
                if ($obj -like "*CRL*") {
                    if ($store[$count+1] -like "*TestRoot*") {
                        write-host "True"
                        $count++
                        }
                    else {$Count++}
                    }
                }
            #>
           
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
                FullAccess = "$($Node.DomainShortName)\Domain Admins","NT AUTHORITY\SYSTEM"
                ChangeAccess = "$($Node.DomainShortName)\Cert Publishers"
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
            Script CertPub {
                TestScript = {
                    $DomainDN = $Using:Node.DomainShortName
                    $UserID = "$($DomainDN)\Cert Publishers"
                    $ACL = (get-ACL -Path C:\PKI).Access | Where-Object {($_.FileSystemRights -like "*Modify*") -and ($_.IdentityReference -eq $UserID) -and ($_.AccessControlType -eq "Allow")}
                    if ($ACL -ne $Null) {
                        return $True
                    }
                    else {
                        return $False
                    }
                }
                SetScript = {
                    icacls C:\PKI /grant "Cert Publishers:(OI)(CI)(M)"
                }
                GetScript = {
                    $UserID = "$Using:Node.DomainShortName\Cert Publishers"
                    return @{Result = (get-ACL -Path C:\PKI).Access | Where-Object {($_.FileSystemRights -like "*Modify*") -and ($_.IdentityReference -eq $Userid) -and ($_.AccessControlType -eq "Allow")}}
                }
            }
       
        #Set ACLs on folder for CRL publishing
            Script Anonymous {
                TestScript = {
                    $ACL = (get-ACL -Path C:\PKI).Access | Where-Object {($_.FileSystemRights -like "*ReadAndExecute*") -and ($_.IdentityReference -eq "IIS AppPool\DefaultAppPool") -and ($_.AccessControlType -eq "Allow")}
                    if ($ACL -ne $Null) {
                        return $True
                    }
                    else {
                        return $False
                    }
                }
                SetScript = {
                    icacls C:\PKI /grant "IIS AppPool\DefaultAppPool:(OI)(CI)(GR)"
                }
                GetScript = {
                    return @{Result = (get-ACL -Path C:\PKI).Access | Where-Object {($_.FileSystemRights -like "*ReadAndExecute*") -and ($_.IdentityReference -eq "IIS AppPool\DefaultAppPool") -and ($_.AccessControlType -eq "Allow")}}
                }
            } 

<#
            FileACLs Anonymous {
                Path = "C:\PKI"
                IdentityReference = "IIS AppPool\DefaultAppPool"
                FileSystemRights = 'Read','ReadAndExecute','ListDirectory'
                AccessControlType = 'Allow'
                InheritanceFlags = "ContainerInherit","ObjectInherit"
                PropagationFlags = "None"
                Ensure = 'Present'
            }
 #>
            Script DoubleEscaping {
                TestScript = {
                    $Test = (Get-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath ‘IIS:\sites\Default Web Site\PKI’ | Select-Object AllowDoubleEscaping)
                    if ($Test.allowDoubleEscaping -eq $True) {
                        return $True
                        }
                    else {return $False}
                    }
                SetScript = {
                    $filter = Get-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath 'IIS:\sites\Default Web Site\PKI'
                    $Filter.AllowDoubleEscaping = $True
                    $Filter | Set-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath 'IIS:\sites\Default Web Site\PKI'
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
  <#          
            file tmpdir {
                Ensure =  'Present'
                DestinationPath = "C:\tmp"
                Type = 'Directory'
                SourcePath = "C:\$($Node.Nodename).$($Node.DNSSuffix)_IssuingCA-$($ADCSRoot.CACN).req"
                }

            xSmbShare CertReq {
                Name = 'Temp'
                Path = "C:\Tmp"
                }
  #>              

           
        #Script Resources (or certutil custom resource) to dspublish and addroot or put it in GPO
        #certutil –addstore –f root orca1_ContosoRootCA.crt
        #certutil –addstore –f root ContosoRootCA.crl

    }
}

PKIDeploy -ConfigurationData .\PKIDeploy.psd1 -outputpath "C:\DSC\Configs"
