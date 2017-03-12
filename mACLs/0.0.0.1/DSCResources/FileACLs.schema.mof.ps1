
[ClassVersion("1.0.0.0"), FriendlyName("FileACLs")]
class MSFT_xSmbShare : OMI_BaseResource
{
    [Key, Description("File or Folder Path")] String Path;
    [Required, Description("User for whom to grant or deny permissions")] String IdentityReference;
    [Write, Description("File system rights")] System.Security.AccessControl.FileSystemRights FileSystemRights;
    [Write, Description("Specifies if the permission is allowed or denied")] System.Security.AccessControl.AccessControlType AccessControlType;
    [Write, Description("Specifies the inheritance flags for the ACE.")] [System.Security.AccessControl.InheritanceFlags] InheritanceFlags;
    [Write, Description("Specifies if the permission is inherited")] Boolean IsInherited;
    [Write, Description("Specifies the propagation flags"] [System.Security.AccessControl.PropagationFlags] PropagationFlags;
    [Write, Description("Specifies if the permission should be added or removed"), ValueMap{"Present","Absent"}, Values{"Present","Absent"}] String Ensure;
};



