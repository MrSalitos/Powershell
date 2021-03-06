$kdrGrp = "Kdr"
$abteilungen = @("S1","S2","S3","S4","S6")
$kdrPos = @("Kdr","stvKdr","VorZi")
$abtPos = @("AbtLtr","AbtFw","GeZi")
$ntfsRechte = @("VZ","AE","L")
$sharePath = '\\bundeswehr.intern\AnwenderDaten\Arbeitsordner'
$userPath = '\\bundeswehr.intern\user'
$DC = "DC=BUNDESWEHR,DC=INTERN"
$verband = "VersBtl131"
$einheit = "Stab"
$path = $DC
New-ADOrganizationalUnit -Name $verband -Path $path -ProtectedFromAccidentalDeletion $false
$verbandOUName = "OU=" + $verband + "," + $path
New-ADOrganizationalUnit -Name $einheit -Path $verbandOUName -ProtectedFromAccidentalDeletion $false
$einheit = "OU=" + $einheit + "," + $verbandOUName
New-ADOrganizationalUnit -Name "G_Gruppen" -Path $verbandOUName -ProtectedFromAccidentalDeletion $false
    $g_groupPath = "OU=G_Gruppen," + $verbandOUName
New-ADOrganizationalUnit -Name "DL_Gruppen" -Path $verbandOUName -ProtectedFromAccidentalDeletion $false
    $dl_groupPath = "OU=DL_Gruppen," + $verbandOUName

foreach($abt IN $abteilungen){
    New-ADOrganizationalUnit -Name $abt -Path $einheit -ProtectedFromAccidentalDeletion $false

    $userName = "dummyUser"
    $userADPath = "OU=" + $abt + "," + $einheit
    $userPassword = "P@ssw0rd01"
    
    # Domänenlokale Gruppen anlegen
    foreach($ntfsRecht IN $ntfsRechte){
        $dl_groupName = "DL_" + $abt + "_" + $ntfsRecht
            New-ADGroup -Name $dl_groupName -Path $dl_groupPath -GroupScope DomainLocal
            #echo "Name: $dl_groupName, Pfad: $dl_groupPath"
    }
       
        
    # Globale Gruppen anlegen
        echo ""
        echo "globale Gruppen werden Mitglieder domänenlokaler Gruppen"
        echo "--------------------------------------------------------------------------------------------"
    foreach($pos IN $abtPos){
        $g_groupName = "G_" + $abt + "_" + $pos
           New-ADGroup -Name $g_groupName -Path $g_groupPath -GroupScope Global
           #echo "Name: $g_groupName, Pfad: $g_groupPath"
        $g_groupFqdn = "CN=" + $g_groupName + "," + $g_groupPath
        
        $identity = switch ($pos){
            "AbtLtr" {"DL_" + $abt + "_VZ"}
            "AbtFw" {"DL_" + $abt + "_AE"}
            "GeZi" {"DL_" + $abt + "_L"}
        }
        echo "$g_groupFqdn wird Mitglied von $identity"
        
        Add-ADGroupMember -Identity $identity -Members $g_groupFqdn
        }

    
    # Benutzerkonten anlegen
        echo ""
        echo "Benutzer werden Mitglieder globaler Gruppen"
        echo "--------------------------------------------------------------------------------------------"
    foreach($pos IN $abtPos){
        $userName = $abt + "_" + $pos
        $userGlobalGroup = "G_" + $abt + "_" + $pos
        $userFqdn = "CN=" + $userName + "," + $userADPath
        $userProfilePath = "$userPath\userProfile\{0}" -f $userName
        $userHomePath = "$userPath\userHome\{0}" -f $userName
        $userHomeDrive = "H:"

        New-ADUser -SamAccountName $userName -Name $userName -UserPrincipalName $userName -ProfilePath $userProfilePath -HomeDrive $userHomeDrive -HomeDirectory $userHomePath -Enabled $true -AccountPassword (ConvertTo-SecureString -AsPlainText $userPassword -Force) -PasswordNeverExpires $true -Path $userADPath
        
        $homeSharePath = "$userPath\userHome"
        $homeShare = New-Item -ItemType directory -Name $userName -Path $homeSharePath
        $acl = Get-Acl $homeShare

        # Vererbung deaktivieren
            $acl.SetAccessRuleProtection($true,$false)

        # Alle Berechtigungen entfernen
            foreach($access IN $acl.Access){
                $acl.RemoveAccessRule($access)
            }

        $fileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
        $accessControlType = [System.Security.AccessControl.AccessControlType]"Allow"
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]"none"

        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($userName, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType)
        $acl.AddAccessRule($accessRule)

        Set-Acl -Path $homeShare -AclObject $acl

        Add-ADGroupMember -Identity $userGlobalGroup -Members $userFqdn
        echo "$userFqdn wird Mitglied der Gruppe $userGlobalGroup "
    }

    foreach($share IN $abt){
        $shareName = $sharePath + '\' + $verband + '\' + $abt
        $testPath = Test-Path -Path $shareName
        if($testPath -eq $false){
            New-Item -Path $shareName -ItemType directory

            $dlVZ = "DL_" + $share + "_VZ"
            echo $dlAE
            $dlAE = "DL_" + $share + "_AE"
            echo $dlS
            $dlL = "DL_" + $share + "_L"
            echo $dlL

            # ACL holen
            $acl = Get-Acl $shareName

            # Vererbung deaktivieren
            $acl.SetAccessRuleProtection($true,$false)

            # Alle Berechtigungen entfernen
            foreach($access IN $acl.Access){
                $acl.RemoveAccessRule($access)
            }
            
        ## Berechtigungen setzen ##
        New-Object System.Security.AccessControl.FileSystemAccessRule("$dlL","Read,ExecuteFile","ContainerInherit,ObjectInherit","none","Allow") | %{$acl.SetAccessRule($_)}
        New-Object System.Security.AccessControl.FileSystemAccessRule("$dlAE","Modify","ContainerInherit,ObjectInherit","none","Allow") | %{$acl.SetAccessRule($_)}
        New-Object System.Security.AccessControl.FileSystemAccessRule("$dlVZ","FullControl","ContainerInherit,ObjectInherit","none","Allow") | %{$acl.SetAccessRule($_)}
        
         # ACL setzen
        Set-Acl $shareName $acl
        }

    }
}
