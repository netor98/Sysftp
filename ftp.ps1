# Instalar la característica de servidor FTP
Install-WindowsFeature Web-FTP-Server -IncludeManagementTools -IncludeAllSubFeature
Install-WindowsFeature Web-Basic-Auth

$nameServer = Read-Host "Nombre del servidor FTP"
New-Item -ItemType Directory -Path "C:\ServidorFTP\" -Force
New-Item -ItemType Directory -Path "C:\ServidorFTP\General" -Force
New-Item -ItemType Directory -Path "C:\ServidorFTP\Reprobados" -Force
New-Item -ItemType Directory -Path "C:\ServidorFTP\Recursadores" -Force

# Crear un nuevo sitio FTP
New-WebFtpSite -Name "$nameServer" -IPAddress "*" -Port 21
Set-ItemProperty "IIS:\Sites\$nameServer" -Name physicalPath -Value 'C:\ServidorFTP\'

#Creación del grupo de usuarios que podrán acceder al FTP
$FTPUserGroupName = "reprobados"
$ADSI = [ADSI]"WinNT://$env:ComputerName"
$FTPUserGroup = $ADSI.Create("Group", "$FTPUserGroupName")
$FTPUserGroup.SetInfo()
$FTPUserGroup.Description = "Los miembros de este grupo podrán acceder al servidor FTP"
$FTPUserGroup.SetInfo()

#Creación del grupo de usuarios que podrán acceder al FTP
$FTPUserGroupName = "recursadores"
$ADSI = [ADSI]"WinNT://$env:ComputerName"
$FTPUserGroup = $ADSI.Create("Group", "$FTPUserGroupName")
$FTPUserGroup.SetInfo()
$FTPUserGroup.Description = "Los miembros de este grupo podrán acceder al servidor FTP"
$FTPUserGroup.SetInfo()

#Dar privilegios de lectura y escritura a los miembros del grupo FTP
Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";users="*";permissions=3} -PSPath IIS:\ -Location "$nameServer"
Remove-WebConfigurationProperty -PSPath IIS:\ -Location "$nameServer/General" -Filter "system.ftpServer/security/authorization" -Name "."
Remove-WebConfigurationProperty -PSPath IIS:\ -Location "$nameServer/Reprobados" -Filter "system.ftpServer/security/authorization" -Name "."
Remove-WebConfigurationProperty -PSPath IIS:\ -Location "$nameServer/Recursadores" -Filter "system.ftpServer/security/authorization" -Name "."

Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";users="*";permissions=1} -PSPath IIS:\ -Location "$nameServer/General"
Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="reprobados";permissions=3} -PSPath IIS:\ -Location "$nameServer/General"
Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="recursadores";permissions=3} -PSPath IIS:\ -Location "$nameServer/General"

Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="reprobados";permissions=3} -PSPath IIS:\ -Location "$nameServer/Reprobados"
Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="recursadores";permissions=3} -PSPath IIS:\ -Location "$nameServer/Recursadores"

#Habilitar las conexiones mediante SSL si es posible
#Set-ItemProperty "IIS:\Sites\FTP" -Name ftpServer.security.ssl.controlChannelPolicy -Value 
#Set-ItemProperty "IIS:\Sites\FTP" -Name ftpServer.security.ssl.dataChannelPolicy -Value 0

# Configurar el cortafuegos para permitir el tráfico FTP
New-NetFirewallRule -Name "FTP (TCP-In)" -DisplayName "FTP (TCP-In)" -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow

# Permitir la autenticación básica (opcional, según tus necesidades de seguridad)
#Set-WebConfigurationProperty -Filter "/system.ftpServer/security/authentication/basicAuthentication" -Name "enabled" -Value "True" -PSPath "IIS:\"
Set-ItemProperty "IIS:\Sites\$nameServer" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value 1
Set-ItemProperty "IIS:\Sites\$nameServer" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value 1
Set-ItemProperty "IIS:\Sites\$nameServer" -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow"
Set-ItemProperty "IIS:\Sites\$nameServer" -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow"

#New-LocalGroup -Name "reprobados"
#New-LocalGroup -Name "recursadores"

# Función para crear usuario FTP
function CrearUsuarioFTP {
    param(
        [string]$nombreUsuario,
        [string]$contrasena,
        [string]$rutaCarpetaPersonal,
	[string]$FTPUserGroupName
    )

    # Agregar usuario local
    #New-LocalUser -Name $nombreUsuario -Password (ConvertTo-SecureString $contrasena -AsPlainText -Force) -Description "Usuario FTP: $nombreUsuario" -UserMayNotChangePassword

    #Creación de los usuarios que añadiremos al grupo con permisos para acceder al FTP
    $CreateUserFTPUser = $ADSI.Create("User", "$nombreUsuario")
    $CreateUserFTPUser.SetInfo()
    $CreateUserFTPUser.SetPassword("$contrasena")
    $CreateUserFTPUser.SetInfo()

    #Unir los usuarios al grupo FTP
    $UserAccount = New-Object System.Security.Principal.NTAccount("$nombreUsuario")
    $SID = $UserAccount.Translate([System.Security.Principal.SecurityIdentifier])
    $Group = [ADSI]"WinNT://$env:ComputerName/$FTPUserGroupName,Group"
    $User = [ADSI]"WinNT://$SID"
    $Group.Add($User.Path)

}

# Pedir al usuario cuántos usuarios desea agregar a cada lista
$reprobadosCount = Read-Host "¿Cuantos usuarios reprobados desea agregar?"
$recursadoresCount = Read-Host "¿Cuantos usuarios recursadores desea agregar?"

# Crear lista de usuarios reprobados
$reprobados = @()
for ($i = 1; $i -le $reprobadosCount; $i++) {
    $usuario = Read-Host "Nombre de usuario reprobado $i"
    $contrasena = Read-Host "Contrasena para el usuario $usuario" -AsSecureString
    $contrasenaTextoPlano = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($contrasena))
    $reprobados += [PSCustomObject]@{
        Nombre = $usuario
        Contrasena = $contrasenaTextoPlano
    }
}

# Crear lista de usuarios recursadores
$recursadores = @()
for ($i = 1; $i -le $recursadoresCount; $i++) {
    $usuario = Read-Host "Nombre de usuario recursador $i"
    $contrasena = Read-Host "Contrasena para el usuario $usuario" -AsSecureString
    $contrasenaTextoPlano = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($contrasena))
    $recursadores += [PSCustomObject]@{
        Nombre = $usuario
        Contrasena = $contrasenaTextoPlano
    }
}

Set-ItemProperty "IIS:\Sites\$nameServer" -Name ftpServer.userIsolation.mode -Value "IsolateRootDirectoryOnly"
mkdir C:\ServidorFTP\LocalUser
Restart-WebItem "IIS:\Sites\$nameServer"

# Crear usuarios reprobados
foreach ($usuario in $reprobados) {
    $nombreUsuario = $usuario.Nombre
    $contrasena = $usuario.Contrasena
    $rutaCarpetaPersonal = "C:\ServidorFTP\LocalUser\$nombreUsuario\$nombreUsuario"
    New-Item -ItemType Directory -Path $rutaCarpetaPersonal -Force
    CrearUsuarioFTP -nombreUsuario $nombreUsuario -contrasena $contrasena -rutaCarpetaPersonal $rutaCarpetaPersonal -FTPUserGroupName "reprobados"
    
    #New-Item -ItemType Directory -Path "C:\ServidorFTP\LocalUser\$nombreUsuario\General" -Force
    #New-Item -ItemType Directory -Path "C:\ServidorFTP\LocalUser\$nombreUsuario\Reprobados_8" -Force

    cmd /c mklink /d "C:\ServidorFTP\LocalUser\$nombreUsuario\General\" "C:\ServidorFTP\General\"
    cmd /c mklink /d "C:\ServidorFTP\LocalUser\$nombreUsuario\Reprobados\" "C:\ServidorFTP\Reprobados\"

    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="reprobados";permissions=3} -PSPath IIS:\ -Location "$nameServer/LocalUser/$nombreUsuario/General"
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="reprobados";permissions=3} -PSPath IIS:\ -Location "$nameServer/LocalUser/$nombreUsuario/Reprobados"
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="reprobados";permissions=3} -PSPath IIS:\ -Location "$nameServer/LocalUser/$nombreUsuario/$nombreUsuario"
}

# Crear usuarios recursadores
foreach ($usuario in $recursadores) {
    $nombreUsuario = $usuario.Nombre
    $contrasena = $usuario.Contrasena
    $rutaCarpetaPersonal = "C:\ServidorFTP\LocalUser\$nombreUsuario\$nombreUsuario"
    New-Item -ItemType Directory -Path $rutaCarpetaPersonal -Force
    CrearUsuarioFTP -nombreUsuario $nombreUsuario -contrasena $contrasena -rutaCarpetaPersonal $rutaCarpetaPersonal -FTPUserGroupName "recursadores"

    # New-Item -ItemType Directory -Path "C:\ServidorFTP\LocalUser\$nombreUsuario\General" -Force
    # New-Item -ItemType Directory -Path "C:\ServidorFTP\LocalUser\$nombreUsuario\Recursadores_8" -Force

    cmd /c mklink /d "C:\ServidorFTP\LocalUser\$nombreUsuario\General\" "C:\ServidorFTP\General\"
    cmd /c mklink /d "C:\ServidorFTP\LocalUser\$nombreUsuario\Recursadores\" "C:\ServidorFTP\Recursadores\"

    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="recursadores";permissions=3} -PSPath IIS:\ -Location "$nameServer/LocalUser/$nombreUsuario/General"
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="recursadores";permissions=3} -PSPath IIS:\ -Location "$nameServer/LocalUser/$nombreUsuario/Recursadores"
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";roles="recursadores";permissions=3} -PSPath IIS:\ -Location "$nameServer/LocalUser/$nombreUsuario/$nombreUsuario"   
}

cmd /c mklink /d "C:\ServidorFTP\LocalUser\Public\" "C:\ServidorFTP\General"
Add-WebConfiguration "/system.ftpServer/security/authorization" -Value @{accessType="Allow";users="*";permissions=1} -PSPath IIS:\ -Location "$nameServer/LocalUser/Public"

Restart-WebItem "IIS:\Sites\$nameServer"

Write-Host "El servidor FTP ha sido configurado exitosamente."
Write-Host "Usuarios reprobados creados: $($reprobados.Nombre -join ', ')"
Write-Host "Usuarios recursadores creados: $($recursadores.Nombre -join ', ')"