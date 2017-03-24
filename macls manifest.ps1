$Params = @{
    Path = 'C:\Program Files\WindowsPowerShell\Modules\mACLs\0.0.0.1\mACLs.psd1'
    Author = 'Missy Januszko'
    ModuleVersion = '0.0.0.1'
    }

New-ModuleManifest @Params -Guid (new-guid) -DscResourcesToExport FileACLs