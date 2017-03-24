Configuration Test {
    
    import-dscresource -ModuleName "mACLs" -moduleversion "1.0.0.0"

    Node EntRoot {

        FileACLs test{
            Path = "C:\PKI"
            IdentityReference = "Company\Cert Publishers"
            FileSystemRights = 'Read'
            AccessControlType = 'Allow'
            InheritanceFlags = "ContainerInherit"
            PropagationFlags = "None"
            Ensure = 'Present'
            }

      }
    }

Test -OutputPath C:\DSC\Configs
        

    