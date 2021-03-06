﻿function Test-TargetResource {

    [CmdletBinding()]
    [OutputType([System.Boolean])]

    param (
        [parameter(Mandatory=$True)]
        [string]$Path,

        [parameter(Mandatory=$True)]
        [string]$IdentityReference,

        [parameter(Mandatory=$True)]
        [ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete","DeleteSubdirectoriesAndFiles", `
            "ExecuteFile","FullControl","ListDirectory","Modify","Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes", `
            "ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttributes","WriteData","WriteExtendedAttributes")]
        [string[]]$FileSystemRights,

        [ValidateSet("Allow","Deny")]
        [string]$AccessControlType,

        [ValidateSet("ContainerInherit","ObjectInherit","None")]
        [string[]]$InheritanceFlags,

        [ValidateSet("None","InheritOnly","NoPropagateInherit")]
        [string]$PropagationFlags,
        
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
        
        #Ensure = Present
        #This Test is not working.  It will return false every time.
        else {
            
            $ACL = (get-acl -Path $Path).Access | Where-Object {$_.IdentityReference -eq $IdentityReference}
            $RefACL = New-Object -typename System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($IdentityReference,$FileSystemRights,$InheritanceFlags,$PropagationFlags,$AccessControlType)
                If ($ACL -ne $Null) {
                    foreach ($A in $ACL) {
                            Write-Verbose "$($A.FileSystemRights) $($A.InheritanceFlags) $($A.AccessControlType)"
                            if ((Compare-Object -ReferenceObject $RefACL -DifferenceObject $A -Property FileSystemRights,InheritanceFlags,AccessControlType) -eq $Null) { 
                                    write-verbose "ACL is in desired state."
                                    return $True
                                }
                            else {
                                write-verbose "ACL is not in Desired State.  Continuing search."
                                }
                        }
                    return $False
                    }
                #ACL = Null
                else {
                    write-verbose "No ACL was found, but should be set."
                    return $false  
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

        [parameter(Mandatory=$True)]
        [ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete","DeleteSubdirectoriesAndFiles", `
            "ExecuteFile","FullControl","ListDirectory","Modify","Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes", `
            "ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttributes","WriteData","WriteExtendedAttributes")]
        [string[]]$FileSystemRights,

        [ValidateSet("Allow","Deny")]
        [string]$AccessControlType,

        [ValidateSet("ContainerInherit","ObjectInherit","None")]
        [string[]]$InheritanceFlags,
        
        [ValidateSet("None","InheritOnly","NoPropagateInherit")]
        [string]$PropagationFlags,

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

        [parameter(Mandatory=$True)]
        [ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete","DeleteSubdirectoriesAndFiles", `
            "ExecuteFile","FullControl","ListDirectory","Modify","Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes", `
            "ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttributes","WriteData","WriteExtendedAttributes")]
        [string[]]$FileSystemRights,

        [ValidateSet("Allow","Deny")]
        [string]$AccessControlType,

        [ValidateSet("ContainerInherit","ObjectInherit","None")]
        [string[]]$InheritanceFlags,

        [ValidateSet("None","InheritOnly","NoPropagateInherit")]
        [string]$PropagationFlags,
        
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
                 