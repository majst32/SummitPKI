@{
    AllNodes = @(
        @{
            NodeName = '*'
            PSDscAllowPlainTextPassword = $true
           }
      
     @{
            NodeName = 'TgtPull'
            Role = 'ADCSRoot'
            Password = 'P@ssw0rd'
        }
    )
    ADCSRoot = @{
            # ADCS Certificate Services information  for offline root
            Features = @('ADCS-Cert-Authority';'RSAT-ADCS-Mgmt')
            CAType = 'StandaloneRootCA'
            CACN = 'CompanyRoot'
            CADNSuffix = 'C=US,L=Philadelphia,S=Pennsylvania,O=Company'
            CADatabasePath = 'C:\windows\system32\CertLog'
            CALogPath = 'C:\CA_Logs'
            ADCSCryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
            ADCSHashAlgorithmName = 'SHA256'
            ADCSKeyLength = '2048'
            ADCSValidityPeriod = 'Years'
            ADCSValidityPeriodUnits = '2'
            }

    #ADCSSub = @{
            # ADCS Certificate Services info for Enterprise Subordinate
 }