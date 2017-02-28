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
                CryptoProviderName = $ADCSRoot.ADCSCryptoProviderName
                HashAlgorithmName = $ADCSRoot.ADCSHashAlgorithmName
                KeyLength = $ADCSRoot.ADCSKeyLength
                CACommonName = $ADCSRoot.CACN
                CADistinguishedNameSuffix = $ADCSRoot.CADNSuffix
                DatabaseDirectory = $ADCSRoot.CADatabasePath
                LogDirectory = $ADCSRoot.CALogPath
                ValidityPeriod = $ADCSRoot.ADCSValidityPeriod
                ValidityPeriodUnits = $ADCSRoot.ADCSValidityPeriodUnits
                Ensure = 'Present'
                DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
                }
    }
}

PKIDeploy -ConfigurationData .\PKIDeploy.psd1 
