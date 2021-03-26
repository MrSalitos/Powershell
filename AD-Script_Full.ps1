###############################################################################################################################################
# Dieses Script erstellt einen OU-Pfad für jede Abteilung und anschließend für jede Abteilung die in den .csv-Dateien festgelegten globalen   #
# und domänenlokalen Gruppen in der jeweiligen Organisationseinheit                                                                           #
#                                                                                                                                             #
###############################################################################################################################################

###############################################
##### Definieren von "globalen" Variablen #####
###############################################
$users = Import-Csv ".\benutzer.csv"            # importiert die Benutzerinformationen aus der angegeben .csv-Datei
$abteilungen = Import-Csv ".\Abteilungen.csv"   # importiert die Abteilungsnamen
$g_gruppen = Import-Csv ".\G_Gruppen.csv"       # importiert die Positionsbezeichnungen innerhalb der Abteilung (z.B. "AbtLtr")
$dl_gruppen = Import-Csv ".\DL_Gruppen.csv"     # importert die Bezeichnungen der Zugriffsrechte für die DL-Gruppen (z.B. "VZ" für Vollzugrif, etc.)
$sharePath = "\\1106-fs01\freigaben"
$userSharePath = "\\1106-fs01\user"

$ouPath = ""
$userDnsDomain = $env:USERDNSDOMAIN.Split(".")
for($i=0; $i -lt $userDnsDomain.length; $i++){
    $ouPath = $ouPath + "DC=" + $userDnsDomain[$i]
    if($i -eq0){
        $ouPath = $ouPath + ","
    }
    echo $ouPath
}


#############################################################
##### Organisationseinheiten im ActiceDirectory anlegen #####
#############################################################
New-ADOrganizationalUnit -Name $env:USERDNSDOMAIN -Path $ouPath -ProtectedFromAccidentalDeletion $false
$ouPath = "OU=" + $env:USERDNSDOMAIN + "," + $ouPath
#New-ADOrganizationalUnit -Name "1106" -Path "OU=kit.schulung,DC=kit,DC=schulung" -ProtectedFromAccidentalDeletion $false
#$ouPath = "OU=1106," + $ouPath

foreach($abteilung IN $abteilungen){
    $abtName = $abteilung.Name
    $ouSearch = "OU=$abtName,$ouPath"
    ## Prüfen, ob die OU $abtName existiert. Falls nicht, wird sie mit drei Unter-OUs (Benutze, Computer, Gruppen) angelegt ##
    #if(Get-ADOrganizationalUnit -Identity "$ouSearch"){
   #     echo "$abtName existiert bereits."
   # }
   # else{
        echo "$ouSearch wird angelegt..."
        New-ADOrganizationalUnit -Name $abtname -Path "$ouPath" -ProtectedFromAccidentalDeletion $false
        $abtPath = "OU=$abtName,$ouPath"
        New-ADOrganizationalUnit -Name "Benutzer" -Path $abtPath -ProtectedFromAccidentalDeletion $false
        New-ADOrganizationalUnit -Name "Computer" -Path $abtPath -ProtectedFromAccidentalDeletion $false
        New-ADOrganizationalUnit -Name "Gruppen" -Path $abtPath -ProtectedFromAccidentalDeletion $false
    #}   
}

###########################################
##### ActiveDirectory-Gruppen anlegen #####
###########################################
foreach($abteilung IN $abteilungen){
    echo ""
    echo ""
    echo ""
    echo $abteilung.Name
    echo "--------------------"

    

    
    #######################################################################################
    #### Festlegen der Gruppennamen, getrennt nach Globalen und Domänenlokalen Gruppen ####
    #######################################################################################
    $ouPathGruppen = "OU=Gruppen, OU=" + $abteilung.Name + "," + $ouPath # Festlegen des OU-Pfads, wo die Gruppen angelegt werden sollen
    ############################################
    ### Erstellen der domänenlokalen Gruppen ###
    ############################################
    foreach($dl_gruppe IN $dl_gruppen){
        $dl_string = "DL_" + $abteilung.Name + "_" + $dl_gruppe.Zugriff # Zusammensetzen des Gruppennamens nach dem Schema DL_Abteilung_Zugriffsrecht
        #$groupcheck = Get-ADGroup -Identity $dl_string -ErrorAction SilentlyContinue

        if(Get-ADGroup -Filter {Name -eq $dl_string}){
            echo "Gruppe $dl_string existiert bereits"           
        }
        else{
            New-ADGroup -Name $dl_string -GroupScope DomainLocal -Path $ouPathGruppen -ErrorAction SilentlyContinue # Anlegen der oben definierten domänenlokalen Gruppe
            echo "$dl_string in $ouPath wurde angelegt." 
        }
    }
    ######################################
    ### Erstellen der globalen Gruppen ###
    ######################################
    foreach($g_gruppe IN $g_gruppen){ 
        $g_string = "G_" + $abteilung.Name + "_" + $g_gruppe.Position # Zusammensetzen des Gruppennamens nach dem Schema G_Abteilung_Position
        
        if(Get-ADGroup -Filter {Name -eq $g_string}){
            echo "Gruppe $g_string existiert bereits"
        }
        else{
            New-ADGroup -Name $g_string -GroupScope Global -Path $ouPathGruppen # Anlegen der oben definierten globalen Gruppe
            echo "$g_string in $ouPath wurde angelegt."
        }
        #+++++++++++++++++++++++++++++++++++++++++#
        #  Festlegen der Gruppenmitgliedschaften  #
        #+++++++++++++++++++++++++++++++++++++++++#
        echo "Gruppenmitgliedschaften festlegen"
         
        if($g_gruppe.Position -eq "AbtLtr"){
            $dl_string = "DL_" + $abteilung.Name + "_VZ"
            $membercheck = Get-ADGroupMember -Identity $dl_string | Where -Property name -eq $g_string -ErrorAction SilentlyContinue 
        if($membercheck -eq $null){
            Add-ADGroupMember -Identity $dl_string -Members $g_string
            echo "$g_string ist jetzt Mitglied in $dl_string"
        }
        else {
            echo "$g_string ist bereits Mitglied in der Domänenlokalen Gruppe $dl_string"
        }
    }
    elseif($g_gruppe.Position -eq "Mitarbeiter"){
        $dl_string = "DL_" + $abteilung.Name + "_AE"
        $membercheck = Get-ADGroupMember -Identity $dl_string | Where -Property name -eq $g_string
        if($membercheck -eq $null){
            Add-ADGroupMember -Identity $dl_string -Members $g_string
            echo "$g_string ist jetzt Mitglied in $dl_string"
        }
        else {
            echo "$g_string ist bereits Mitglied in der Domänenlokalen Gruppe $dl_string"
        }
    }
    elseif($g_gruppe.Position -eq "Praktikant"){
        $dl_string = "DL_" + $abteilung.Name + "_L"
        $membercheck = Get-ADGroupMember -Identity $dl_string | Where -Property name -eq $g_string -ErrorAction SilentlyContinue
        if($membercheck -eq $null){
            Add-ADGroupMember -Identity $dl_string -Members $g_string
            echo "$g_string ist jetzt Mitglied in $dl_string"
        }
        else {
            echo "$g_string ist bereits Mitglied in der Domänenlokalen Gruppe $dl_string"
        }
    }
    }
    echo ""
}

##################################################
##### ActiveDirectory-Benutzerkonten anlegen #####
##################################################
foreach($user in $users){
$password = $user.Passwort | ConvertTo-SecureString -AsPlainText -Force
$name = $user.Vorname + ' ' + $user.Nachname
$accountname = $user.Vorname + "." + $user.Nachname
$givenName = $user.Vorname
$surname = $user.Nachname
$abt = $user.abteilung
$abtPos = $user.Position
$ouPathBenutzer = "ou=Benutzer,ou=$abt,$ouPath"
$gGroupName = 'CN=G_' + $abt + '_' + $abtPos + ',OU=Gruppen,OU=' + $abt + ',' + $ouPath
$userFqdn = 'CN=' + $name + ',OU=Benutzer,OU=' + $abt + ',' + $ouPath
$checkaccount = Get-ADUser -LDAPFilter "(sAMAccountName=$accountname)"
$profilePath = "$userSharePath\profile\$accountname"
$homePath =  “$userSharePath\home\{0}” -f $accountname
$homeDrive = "H:"

    # Prüfen, ob Benutzerkonto aus der .csv-Datei bereits im AD exisitert
    if($checkaccount -eq $null){
        New-ADUser -name $name -GivenName $givenName -Surname $surname -SamAccountName $accountname -AccountPassword $password -Path $ouPath -Enabled $true -HomeDrive $homeDrive -HomeDirectory $homePath
        echo "Benutzer $accountname wurde angelegt."
        Add-ADGroupMember -Identity $gGroupName -Members $userFqdn
    }
    else{
        echo "Benutzer $accountname existiert bereits."
        #Remove-ADUser -Identity $accountname
        #echo "Benutzer $accountname wurde gelöscht."
    }
}

#################################################################
#### Freigaben für jede Abteilung auf dem Fileserver anlegen ####
#### und domänenlokalen Gruppen Berechtigungen zuweisen      ####
#################################################################
 
foreach($share in $abteilungen){
    $shareName = $sharePath + "\" + $share.Name
    $testPath = Test-Path -Path $shareName
    if($testPath -eq $false){ # Abfragen, ob der anzulegende Pfad bereits existiert

        ## Verzeichnis anlegen ##
        New-Item -Path $shareName -ItemType directory
        echo "Die Freigabe $shareName wurde angelegt..."
        $dlVZ = "DL_" + $share.name + "_VZ"
        $dlAE = "DL_" + $share.name + "_AE"
        $dlL = "DL_" + $share.name + "_L"
        $dlKZ = "DL_" + $share.name + "_KZ"

        ## ACL holen ##
        $acl = Get-Acl $shareName
		
        ## Vererbung deaktivieren ##
        $acl.SetAccessRuleProtection($true,$true)
		
		## Alle Berechtigungen löschen ##
		foreach($access in $acl.access) 
		{ 
			$acl.RemoveAccessRule($access)   
		}
		
        ## Berechtigungen setzen ##
        New-Object System.Security.AccessControl.FileSystemAccessRule("$dlL","ReadandExecute","ContainerInherit","InheritOnly","Allow") | %{$acl.SetAccessRule($_)}
        New-Object System.Security.AccessControl.FileSystemAccessRule("$dlAE","Modify","ContainerInherit","InheritOnly","Allow") | %{$acl.SetAccessRule($_)}
        New-Object System.Security.AccessControl.FileSystemAccessRule("$dlKZ","FullControl","ContainerInherit","InheritOnly","Deny") | %{$acl.SetAccessRule($_)}
        New-Object System.Security.AccessControl.FileSystemAccessRule("$dlVZ","FullControl","ContainerInherit","InheritOnly","Allow") | %{$acl.SetAccessRule($_)}
        
        ## ACL zurückschreiben ##
        Set-Acl $shareName $acl
    } 
    else{
        echo "Verzeichnis $shareName existiert bereits"
    } 
}
