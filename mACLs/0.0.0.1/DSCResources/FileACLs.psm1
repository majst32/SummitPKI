function Test-TargetResource {

    [CmdletBinding()]
    [OutputType([System.Boolean])]

    param (
        [parameter(Mandatory=$True)]
        [string]$Path,

        [parameter(Mandatory=$True)]
        [string]$IdentityReference,

        [System.Security.AccessControl.FileSystemRights]$FileSystemRights,

        [ValidateSet("Allow","Deny")]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,

        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags,

        [bool]$IsInherited,

        [ValidateSet("None","InheritOnly","NoPropagateInheritance")]
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags,
        
        [parameter(Mandatory=$True)]
        [ValidateSet("Present","Absent")]
        [string]$Ensure="Present"
        )
        
        if ($Ensure -eq'Absent') {
            $ACL = (get-acl -Path $Path).Access | Where-Object {$_.IdentityReference -eq $IdentityReference}
            if ($ACL -eq $Null) {
                write-verbose -Message ("Desired State is $Ensure and no ACL exists for $IdentityReference.  Desired State is correct.")
                Return $True
                }
            else {
                write-verbose -Message ("Desired State is $Ensure and an ACL exists for $IdentityReference.  Desired State is not correct.")
                return $False}
            }
        else {
            
            $ACL = (get-acl -Path $Path).Access | Where-Object {$_.IdentityReference -eq $IdentityReference}
            If ($ACL -ne $Null) {
                $Params = 'AccessControlType','FileSystemRights','IdentityReference','IsInherited','PropagationFlags','InheritanceFlags'
                if ($PSBoundParameters.Keys.Where({$_ -in $Params}) | ForEach-Object {Compare-Object -ReferenceObject $PSBoundParameters.$_ -DifferenceObject $ACL.$_ -Verbose})
                    { 
                        write-verbose "ACL found for $IdentityReference, but parameters do not match."
                        return $false

                    }
                else {
                    write-verbose "ACL is in Desired State."
                    return $true
                    }
            }
        }
}
 
 function Set-TargetResource {
    [CmdletBinding()]

    param (
        [parameter(Mandatory=$True)]
        [string]$Path,

        [parameter(Mandatory=$True)]
        [string]$IdentityReference,

        [ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete","DeleteSubdirectoriesAndFiles", `
            "ExecuteFile","FullControl","ListDirectory","Modify","Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes", `
            "ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttibutes","WriteData","WriteExtendedAttributes")]
        [System.Security.AccessControl.FileSystemRights]$FileSystemRights,

        [ValidateSet("Allow","Deny")]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,

        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags,

        [bool]$IsInherited,

        [ValidateSet("None","InheritOnly","NoPropagateInheritance")]
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags,
        
        [parameter(Mandatory=$True)]
        [ValidateSet("Present","Absent")]
        [string]$Ensure="Present"
        )
     
     $ACL = Get-Acl -Path $Path 
     $ACE = New-Object System.Security.AccessControl.FileSystemAccessRule $IdentityReference,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType
     if ($Ensure -eq "Absent") {
            $ACL.RemoveAccessRuleAll($ACE)
            Set-Acl -Path $Path -AclObject $ACL
            Write-Verbose -Message "ACL for $IdentityReference has been removed."
            }
     
     else {
        $ACL.AddAccessRule($ACE)
        set-ACL -Path $Path -AclObject $ACL
        write-verbose -Message ("$FileSystemRights Permissions set for $IdentityReference.")
        }
 }
                     
 function Get-TargetResource {
    [CmdletBinding()]

    param (
        [parameter(Mandatory=$True)]
        [string]$Path,

        [parameter(Mandatory=$True)]
        [string]$IdentityReference,

        [ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete","DeleteSubdirectoriesAndFiles", `
            "ExecuteFile","FullControl","ListDirectory","Modify","Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes", `
            "ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttibutes","WriteData","WriteExtendedAttributes")]
        [System.Security.AccessControl.FileSystemRights]$FileSystemRights,

        [ValidateSet("Allow","Deny")]
        [System.Security.AccessControl.AccessControlType]$AccessControlType,

        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags,

        [bool]$IsInherited,

        [ValidateSet("None","InheritOnly","NoPropagateInheritance")]
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags,
        
        [parameter(Mandatory=$True)]
        [ValidateSet("Present","Absent")]
        [string]$Ensure="Present"
        )

        $ACL = (get-acl -path $Path).Access | Where-Object {$_.IdentityReference -eq $IdentityReference}
        if ($ACL -ne $Null) {
            return $ACL
            }
        else {
            Return @{}
            }
}
                 