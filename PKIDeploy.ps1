Configuration PKIDeploy {

        Import-DSCresource -ModuleName PSDesiredStateConfiguration,@{ModuleName="xADCSDeployment";ModuleVersion="1.1.0.0"}

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
                CADistinguishedNameSuffix = $Node.CADNSuffix
                DatabaseDirectory = $Node.CADatabasePath
                LogDirectory = $Node.CALogPath
                ValidityPeriod = $Node.ADCSValidityPeriod
                ValidityPeriodUnits = $Node.ADCSValidityPeriodUnits
                Ensure = 'Present'
                DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
                }
        
        #bunch of certutil stuff
        # HKLM\System\CurrentControlSet\Services\Certsvc\Configuration\<YourCAName>
        # certutil -setreg CA\CRLPublicationURLs "1:C:\Windows\system32\CertSrv\CertEnroll\%3%8.crl\n2:http://www.contoso.com/pki/%3%8.crl"
        # certutil –setreg CA\CACertPublicationURLs "2:http://www.contoso.com/pki/%1_%3%4.crt"
        # Certutil -setreg CA\CRLOverlapPeriodUnits 12
        # Certutil -setreg CA\CRLOverlapPeriod "Hours"
        # Certutil -setreg CA\ValidityPeriodUnits 10
        #Certutil -setreg CA\ValidityPeriod "Years"
        #certutil -setreg CA\DSConfigDN CN=Configuration,DC=corp,DC=contoso,DC=com
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
         #>
             
        #Remove default CRL Distribution Points
        #Set new CRL Distribution Points


        #Export the certificate to a .cer file

        #ADCS Subordinate region

        #File resource to copy the .cer file

        #Script Resources (or certutil custom resource) to dspublish and addroot or put it in GPO


    }
}

PKIDeploy -ConfigurationData .\PKIDeploy.psd1 -outputpath "C:\DSC\Configs"
