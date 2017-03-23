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
<#        
        The intent here is to set a flag so that if this is the first time through the config, and ADCS isn't configured yet, 
        set a flag so that either the server reboots, or that the certsvc is restarted after all the registry settings are configured.

        ##### DO NOT USE THIS.  THIS MAKES THE SERVER REBOOT ITSELF OVER AND OVER.  #####

        script SetForReboot {
            testScript = {
                    try {
                        Install-AdcsCertificationAuthority -whatif -ErrorAction Stop
                        return $False
                    }
                    catch {
                        if ($Error[0] -like "*already installed*") {return $True}
                        else {return $False}
                    }
            }
            setScript = {
                $global:DSCMachineStatus = 1
                }
            getscript = {
                return @{Result = $global:DSCMachineStatus}
            }
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
        }

#>
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
        #Changed from registry resource to script resource, untested

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
            DependsOn = '[xADCSCertificationAuthority]ADCSConfig'
            }

        #Changed from registry resource to script resource, untested
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
            DependsOn = '[xADCSCertificationAuthority]ADCSConfig'
            }

        #Other registry settings that can be set using registry resource

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

            #publish CRL
            #Originally skipped with comment, untested

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
                DependsOn = '[xPendingReboot]RebootForCertsvc'
            }

            #Copy the root certificate into a temp directory so don't have to get it from the admin share
            File CopyRootCert {
                Type = 'Directory'
                DestinationPath = "C:\temp"
                SourcePath = "C:\Windows\System32\certsrv\certenroll"
                Recurse = $true
                MatchSource = $true
                Ensure = 'Present'
                DependsOn = '[Script]PublishCRL'
                }
            
            #Share folder so subCA and dc can get to the certificate
            xSMBShare RootShare {
                Name = "RootShare"
                Path = "C:\temp"
                DependsOn = '[File]CopyRootCert'
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
                
            #Then it gets icky - and unfinished
            #certreq -submit "C:\ENTSub.$($node.DNSSuffix)_IssuingCA-$($ADCSRoot.CACN).req"
            #certutil -resubmit <request number from previous step> to issue the certificate
            #certreq -retrieve <request number from previous step" C:\somePathtoCertificate

            #After that copy the root and root CRL to the pki folder on EntSub
            #Copy the issuing to somewhere on EntSub too
            #certutil -InstallCertificate C:\somewhere\nameofIssuingCert.crt
            #start-service certsvc
            #Copy issuing cert and issuing CRL from C:\windows\system32\certsvc\certenroll to C:\pki
            #Set CRL CDP, AIA, and other registry settings on issuing (use same code as on root)

            #Autoenrollment - have that coded
            #Web Server templates and DSC templates - have that coded



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
          #This was accidentally skipped and is new/untested

          script ImportCRL {
            TestScript = {
                $Store = certutil -store root
                $count = 0
                foreach ($obj in $store) { 
                    if ($obj -like "*= CRL*") {
                        $Next = $Count+1 
                        $CRLList = $Store[$Next..$Store.Count]
                        foreach ($Line in $CRLList) {
                            $CACN = $Using:ADCSRoot.CACN
                            if ($Line -like "*$CACN*") {
                                return $True
                                }
                            else {
                                return $False
                                }
                            }
                        }
                    else {$Count++}
                    }
                }
            SetScript = {
                $CRLName = $Using:ADCSRoot.CACN
                $CRLFile = "$CRLName.crl"
                certutil -addstore -f root "C:\temp\$CRLFile"
                }
            GetScript = {
             $Store = certutil -store root
             $count = 0
             foreach ($obj in $store) { 
                if ($obj -like "*= CRL*") {
                    $Next = $Count+1 
                    $CRLList = $Store[$Next..$Store.Count]
                    foreach ($Line in $CRLList) {
                        $CACN = $Using:ADCSRoot.CACN
                        if ($Line -like "*$CACN*") {
                            return @{Result=$True}
                                }
                            else {
                                return @{Result=$False}
                                }
                            }
                        }
                    else {$Count++}
                    }
                }
            }
 
 <#       The intent of this part of the code is to try to detect if this is the first time through the IIS settings portion and set a flag for
          a reboot (here) or iisreset after all the settings are set.
          
          ##### ONCE AGAIN, DO NOT USE THIS PART OF THE CODE, IT WILL CAUSE AN INFINITE REBOOT LOOP.  FUN TIMES FOR ALL.  #####
            
          script SetForIISReboot {
            testScript = {
                    if ((get-windowsfeature -name Web-Server).Installed -eq $False) 
                        {return $False}
                    else {return $True}
            }
            setScript = {
                $global:DSCMachineStatus = 1
                }
            getscript = {
                return @{Result = $global:DSCMachineStatus}
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

<#          A fun little custom resource attempt at setting NTFS permissions.  Currently doesn't work, there are problems with Test-TargetResource.
            Could use some help on the resource and don't plan on giving up on it, just gave up for this presentation.

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

            #Set the double escaping checkbox in IIS

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
            
            #Reboot to pick up IIS settings (can be changed to iisreset) if needed, but won't do anything until the code to indicate it's necessary is fixed.
            xPendingReboot RebootforIIS {
                Name = 'RebootEntSub'
                DependsOn = '[Script]DoubleEscaping'
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
            
    }
}

PKIDeploy -ConfigurationData .\PKIDeploy.psd1 -outputpath "C:\DSC\Configs"
#PKIDeploy -ConfigurationData .\PKIDeploy2.psd1 -outputpath "C:\DSC\Configs"
