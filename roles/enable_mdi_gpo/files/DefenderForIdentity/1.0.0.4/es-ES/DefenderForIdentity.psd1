# es-ES
ConvertFrom-StringData @'
	ACL_Set                                = Configurando las listas del control de acceso al sistema

	ADFS_ContainerNotFound                 = Contenedor de Microsoft ADFS no encontrado
	ADFS_ValidateAuditing                  = Validando la auditoría del contenedor de ADFS

	AdvancedPolicyCAs_Validate             = Validando la política de auditoría avanzada para los servidores de Autoridad Certificadora
	AdvancedPolicyCAs_Set                  = Configurando la política de auditoría avanzada para los servidores de Autoridad Certificadora

	AdvancedPolicyDCs_Validate             = Validando la política de auditoría avanzada para los controladores de dominio
	AdvancedPolicyDCs_Set                  = Configurando la política de auditoría avanzada para los controladores de dominio

	AdvancedPolicyEntra_Set                = Configuración de la política de auditoría avanzada para Entra Connect
	AdvancedPolicyEntra_Validate           = Validación de la política de auditoría avanzada para Entra Connect

	CAAuditing_NotCAServer                 = No se encontró el servicio CertSvc. Este no es un servidor de Autoridad Certificadora
	CAAuditing_Validate                    = Validando la configuración de auditoría del servidor de Autoridad Certificadora

	Configuration_Set                      = Establecimiento de configuración: {0}

	DeletedObjectsPermissions_StatusFail   = Falla al establecer los permisos de los objetos eliminados
	DeletedObjectsPermissions_CrossDomain  = No se admite la administración de permisos de objetos eliminados en un dominio diferente

	DomainControllerUnavailable			   = No se puede contactar con un controlador de dominio con AD Web Services ejecutándose

	DomainObject_ValidateAuditing          = Validando la auditoría de objetos de dominio

	DomainRecycleBin_Descriptor			   = Papelera de reciclaje de Active Directory
	DomainRecycleBin_Disabled			   = La papelera de reciclaje de Active Directory está deshabilitada
	DomainRecycleBin_Enabled			   = La papelera de reciclaje de Active Directory está habilitada
	DomainRecycleBin_EnableFailed		   = Error en la reconfiguración de la papelera de reciclaje de Active Directory
	DomainRecycleBin_EnableSuccess		   = La papelera de reciclaje de Active Directory se habilitó correctamente
	DomainRecycleBin_ForestDomainFail	   = El modo funcional de bosque y dominio debe ser al menos 2008R2
	DomainRecycleBin_Validation			   = Validación de la papelera de reciclaje de Active Directory

	DomainReport_CommandToFix              = Comando para solucionar errores
	DomainReport_Configuration             = Configuración
	DomainReport_CreatedBy                 = Creado por el módulo de PowerShell {0}
	DomainReport_DetailsMessage            = El archivo completo de detalles se puede encontrar en
	DomainReport_GpoHeader				   = Nombre de GPO
	DomainReport_GpoNotApplicable          = No aplicable
	DomainReport_HtmlMessage               = Creando reporte en html
	DomainReport_JsonMessage               = Creando reporte detallado en JSON
	DomainReport_NoteMessage               = Nota: Después de crear los objetos de política de grupo, la configuración puede tardar hasta 120 minutos en aplicarse
	DomainReport_Status                    = Estado
	DomainReport_StatusFail                = Fallido
	DomainReport_StatusPass                = Exitoso
	DomainReport_Subtitle                  = El reporte de configuración de MDI valida las SACL del dominio y la presencia de configuración relacionada
	DomainReport_Title                     = Reporte de configuración de MDI para: {0}

	DSA_CannotFindIdentity                 = No se puede encontrar la identidad especificada en el dominio: {0}
	DSA_CannotReadDeletedObjectsContainer  = No se pueden leer los permisos en el contenedor de objetos eliminados
	DSA_DeletedObjectsPermissionNotFound   = Identidad no encontrada en la lista de control de acceso de objetos eliminados
	DSA_TestDelegation                     = Probando delegación (ACL)
	DSA_TestDeletedObjectsAccess           = Probando acceso al contenedor de objetos eliminados
	DSA_TestGroupMembership                = Probando membresías de grupos
	DSA_TestManager                        = Probando asignaciones del administrador
	DSA_TestPasswordRetrieval               = Prueba de recuperación de contraseña de gMSA
	DSA_SkipGmsaTests                      = Omitiendo prueba de asignaciones del administrador porque la identidad proporcionada es una gMSA
	DSA_EnterpriseAdminGroupNotFound       = No se puede encontrar el grupo de administración empresarial
	DSA_CreatedAccount                     = Cuenta de servicio estándar creada
	DSA_CannotCreateAccount                = No se pudo crear la cuenta de servicio estándar
	DSA_CreatedKDSRootKey                  = Clave raíz de KDS creada
	DSA_CannotCreateKDSRootKey             = No se pudo crear la clave raíz de KDS. Si se trata de un dominio secundario, debe ser ADMINISTRADOR EMPRESARIAL para leer el KDS del bosque.
	DSA_FoundKDSRootKey                    = Se encontró la clave raíz de KDS existente
	DSA_CannotFindDomainControllersGroup   = No se puede determinar el nombre del grupo localizado para los controladores de dominio
	DSA_CreatedGMSAGroup                   = Creado grupo GMSA
	DSA_CannotCreateGMSAGroup              = No se pudo crear el grupo GMSA
	DSA_CannotCreateGMSAAccount            = No se pudo crear la cuenta GMSA
	DSA_CannotTestGMSAAccount			   = No se puede probar la recuperación de contraseña de GMSA en un dominio diferente
	DSA_GroupDescription                   = Los miembros de este grupo son objetos de equipo a los que se les permite recuperar la contraseña administrada para {0}

	DSSchema_Get                           = Obteniendo la versión del esquema

	Exchange_ContainerNotFound             = No se encontró el contenedor de servicios de Microsoft Exchange
	Exchange_ValidateAuditing              = Validando la auditoría del contenedor de configuración relacionada con Exchange

	GPO_Create                             = Creando GPO: {0}
	GPO_DelegationMismatch                 = La delegación de la GPO no coincide
	GPO_GetExtension                       = Obteniendo la extensión de la GPO
	GPO_GetLinks                           = Obteniendo enlaces de la GPO
	GPO_LinkedAndEnabled                   = GPO vinculado y habilitado en {0}
	GPO_LinkNotFound                       = Enlace(s) de la GPO no encontrado(s)
	GPO_ManualLinkRequired                 = GPO '{0}' requiere vinculación manual
	GPO_NotFound                           = GPO no encontrado
	GPO_NotLinkedOrEnabled                 = GPO no est� vinculado o habilitado
	GPO_SetDelegation                      = Configurando la delegación de la GPO
	GPO_SetExtension                       = Actualizando la extensión de la GPO
	GPO_SetLink                            = Configurando los enlaces de la GPO
	GPO_SettingsDisabled                   = La configuración de la GPO est� deshabilitada
	GPO_SettingsMismatch                   = La configuración de la GPO no coincide con la configuración requerida
	GPO_UnableToSetExtension               = No se pueden actualizar la versión y las extensiones de la GPO
	GPO_UnableToSetPermissions             = No se pueden actualizar los permisos de GPO
	GPO_UnableToUpdate                     = No se puede crear o actualizar la GPO
	GPO_UnableToUpdateLink                 = No se puede crear o actualizar el enlace de la GPO
	GPO_UpdateVersion                      = Actualizando la versión de la GPO
	GPO_Validate                           = Validando GPO: {0}

	NTLM_ValidateAuditing                  = Validando la auditoría de NTLM

	ProcessorPerformance_Validate          = Validación de el rendimiento del procesador

	RemoteSAM_Validate                     = Validación de SAM remoto
	RemoteSAM_NTLMWarn					   = SAM remoto solo debe usarse en entornos donde NTLM esté deshabilitado. Consulte la documentación en línea para obtener más información

	Sensor_ErrorReadingSensorConfiguration = No se puede leer la configuración de Defender for Identity Sensor
	Sensor_LocateConfigurationFile         = Localizando el archivo de configuración de Defender for Identity Sensor
	Sensor_ProxyConfigurationAction        = Configuración del proxy para Defender for Identity Sensor
	Sensor_ProxyConfigurationActionFail    = Falló la configuración del proxy del sensor de Defender for Identity
	Sensor_ReadConfigurationFile           = Leyendo el archivo de configuración de Defender for Identity Sensor
	Sensor_ServiceNotFound                 = No se encontró el servicio Defender for Identity Sensor
	Sensor_WriteSensorConfigurationFile    = Escribiendo el archivo de configuración de Defender for Identity Sensor

	ServiceAccount_NotFound                = Cuenta de servicio no encontrada

	Validation_Passed                      = Prueba exitosa
	Validation_Failed                      = Prueba fallida
'@

# SIG # Begin signature block
# MIIoRgYJKoZIhvcNAQcCoIIoNzCCKDMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBslCcZIwiQPkOA
# wI8u91RQ/BAIcJI1vZQI5XDSyzvmJKCCDXYwggX0MIID3KADAgECAhMzAAAEBGx0
# Bv9XKydyAAAAAAQEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjQwOTEyMjAxMTE0WhcNMjUwOTExMjAxMTE0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC0KDfaY50MDqsEGdlIzDHBd6CqIMRQWW9Af1LHDDTuFjfDsvna0nEuDSYJmNyz
# NB10jpbg0lhvkT1AzfX2TLITSXwS8D+mBzGCWMM/wTpciWBV/pbjSazbzoKvRrNo
# DV/u9omOM2Eawyo5JJJdNkM2d8qzkQ0bRuRd4HarmGunSouyb9NY7egWN5E5lUc3
# a2AROzAdHdYpObpCOdeAY2P5XqtJkk79aROpzw16wCjdSn8qMzCBzR7rvH2WVkvF
# HLIxZQET1yhPb6lRmpgBQNnzidHV2Ocxjc8wNiIDzgbDkmlx54QPfw7RwQi8p1fy
# 4byhBrTjv568x8NGv3gwb0RbAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU8huhNbETDU+ZWllL4DNMPCijEU4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMjkyMzAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIjmD9IpQVvfB1QehvpC
# Ge7QeTQkKQ7j3bmDMjwSqFL4ri6ae9IFTdpywn5smmtSIyKYDn3/nHtaEn0X1NBj
# L5oP0BjAy1sqxD+uy35B+V8wv5GrxhMDJP8l2QjLtH/UglSTIhLqyt8bUAqVfyfp
# h4COMRvwwjTvChtCnUXXACuCXYHWalOoc0OU2oGN+mPJIJJxaNQc1sjBsMbGIWv3
# cmgSHkCEmrMv7yaidpePt6V+yPMik+eXw3IfZ5eNOiNgL1rZzgSJfTnvUqiaEQ0X
# dG1HbkDv9fv6CTq6m4Ty3IzLiwGSXYxRIXTxT4TYs5VxHy2uFjFXWVSL0J2ARTYL
# E4Oyl1wXDF1PX4bxg1yDMfKPHcE1Ijic5lx1KdK1SkaEJdto4hd++05J9Bf9TAmi
# u6EK6C9Oe5vRadroJCK26uCUI4zIjL/qG7mswW+qT0CW0gnR9JHkXCWNbo8ccMk1
# sJatmRoSAifbgzaYbUz8+lv+IXy5GFuAmLnNbGjacB3IMGpa+lbFgih57/fIhamq
# 5VhxgaEmn/UjWyr+cPiAFWuTVIpfsOjbEAww75wURNM1Imp9NJKye1O24EspEHmb
# DmqCUcq7NqkOKIG4PVm3hDDED/WQpzJDkvu4FrIbvyTGVU01vKsg4UfcdiZ0fQ+/
# V0hf8yrtq9CkB8iIuk5bBxuPMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGiYwghoiAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAQEbHQG/1crJ3IAAAAABAQwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINNqhk7/LeHosKlMDxqBflTe
# QMCrTmGRKgSGv3UIy0fpMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAg7PuKKf475Xb1S2DzaSP+ALF0fksFW3mlyVrEI5stvNkwL+z8jA6Odgg
# juxTx7u9OeuMcAGtzjaYttMr6/ii9lsCyOcKZ9uhxsum1O0gWriRJ97gZhwkjnGb
# 8+C+eoxPNzFu9Bxpwchb7QpY7HGsPl5sHbfztx/OIDVg044iMffAKJuVV0d8UseT
# pr24ImKrR9ZYjvH2wKUgLQzkfiSQRDBLsQT6ChimScV6z8eU+wn/TOOKqfBkQmNu
# 7Lo0uQMbBroq5QauxetT/txdkT4nl6u9TsSpMwr1twKnlYxyaRIDR7pr6d1SNqyq
# ba2gAPY3ldCcsFD9pbQHaxflyqXwN6GCF7AwghesBgorBgEEAYI3AwMBMYIXnDCC
# F5gGCSqGSIb3DQEHAqCCF4kwgheFAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFaBgsq
# hkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDo5VUSh+51z5ZfhnM4BAo+N1+TV8iEHYKhuaCwbsmipQIGaC4JfAuk
# GBMyMDI1MDUyOTA4MjIxNS44MTRaMASAAgH0oIHZpIHWMIHTMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVT
# Tjo0QzFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEf4wggcoMIIFEKADAgECAhMzAAAB/xI4fPfBZdahAAEAAAH/MA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI0
# MDcyNTE4MzExOVoXDTI1MTAyMjE4MzExOVowgdMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjRDMUEt
# MDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyeiV0pB7bg8/qc/mkiDd
# JXnzJWPYgk9mTGeI3pzQpsyrRJREWcKYHd/9db+g3z4dU4VCkAZEXqvkxP5QNTtB
# G5Ipexpph4PhbiJKwvX+US4KkSFhf1wflDAY1tu9CQqhhxfHFV7vhtmqHLCCmDxh
# ZPmCBh9/XfFJQIUwVZR8RtUkgzmN9bmWiYgfX0R+bDAnncUdtp1xjGmCpdBMygk/
# K0h3bUTUzQHb4kPf2ylkKPoWFYn2GNYgWw8PGBUO0vTMKjYD6pLeBP0hZDh5P3f4
# xhGLm6x98xuIQp/RFnzBbgthySXGl+NT1cZAqGyEhT7L0SdR7qQlv5pwDNerbK3Y
# SEDKk3sDh9S60hLJNqP71iHKkG175HAyg6zmE5p3fONr9/fIEpPAlC8YisxXaGX4
# RpDBYVKpGj0FCZwisiZsxm0X9w6ZSk8OOXf8JxTYWIqfRuWzdUir0Z3jiOOtaDq7
# XdypB4gZrhr90KcPTDRwvy60zrQca/1D1J7PQJAJObbiaboi12usV8axtlT/dCeP
# C4ndcFcar1v+fnClhs9u3Fn6LkHDRZfNzhXgLDEwb6dA4y3s6G+gQ35o90j2i6am
# aa8JsV/cCF+iDSGzAxZY1sQ1mrdMmzxfWzXN6sPJMy49tdsWTIgZWVOSS9uUHhSY
# kbgMxnLeiKXeB5MB9QMcOScCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTD+pXk/rT/
# d7E/0QE7hH0wz+6UYTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAOSNN5MpLiyun
# m866frWIi0hdazKNLgRp3WZPfhYgPC3K/DNMzLliYQUAp6WtgolIrativXjOG1lI
# jayG9r6ew4H1n5XZdDfJ12DLjopap5e1iU/Yk0eutPyfOievfbsIzTk/G51+uiUJ
# k772nVzau6hI2KGyGBJOvAbAVFR0g8ppZwLghT4z3mkGZjq/O4Z/PcmVGtjGps2T
# CtI4rZjPNW8O4c/4aJRmYQ/NdW91JRrOXRpyXrTKUPe3kN8N56jpl9kotLhdvd89
# RbOsJNf2XzqbAV7XjV4caCglA2btzDxcyffwXhLu9HMU3dLYTAI91gTNUF7BA9q1
# EvSlCKKlN8N10Y4iU0nyIkfpRxYyAbRyq5QPYPJHGA0Ty0PD83aCt79Ra0IdDIMS
# uwXlpUnyIyxwrDylgfOGyysWBwQ/js249bqQOYPdpyOdgRe8tXdGrgDoBeuVOK+c
# RClXpimNYwr61oZ2/kPMzVrzRUYMkBXe9WqdSezh8tytuulYYcRK95qihF0irQs6
# /WOQJltQX79lzFXE9FFln9Mix0as+C4HPzd+S0bBN3A3XRROwAv016ICuT8hY1In
# yW7jwVmN+OkQ1zei66LrU5RtAz0nTxx5OePyjnTaItTSY4OGuGU1SXaH49JSP3t8
# yGYA/vorbW4VneeD721FgwaJToHFkOIwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIDWTCCAkECAQEwggEBoYHZpIHWMIHTMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVT
# Tjo0QzFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIjCgEBMAcGBSsOAwIaAxUAqROMbMS8JcUlcnPkwRLFRPXFspmggYMw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQsF
# AAIFAOviapIwIhgPMjAyNTA1MjkwNTA5MzhaGA8yMDI1MDUzMDA1MDkzOFowdzA9
# BgorBgEEAYRZCgQBMS8wLTAKAgUA6+JqkgIBADAKAgEAAgILRwIB/zAHAgEAAgIT
# MzAKAgUA6+O8EgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IBAQAKxEFQbXtS
# WEX2n5+upZD+ovNBvpnkt1Og6i4fq5jLAyP2AV5YyjTH3diiykNfeLVOccJlZ+xb
# 2TgaP6kzxSMNwli4caLJhesk7NXlQb9MXGmpsJBRGyLu0dYQzSDI+3p1nO0570RB
# sMlypg8N04iY9BLFAerwEYaWS0ySHvw5rL6DJdyAtx7EWVPgpK37PZb4XG3mY4cf
# dqe0mY6olJMJxjEsii9DEUyz8wKCo+uX5LUzI+BonbEREid/7aESkK4H8+Y1TNd7
# ikjUabg2uGYjbC/03HQkq1mNLmmtiZL+GBYzilAAs/AGInrevp4+QpBQng4rtYZi
# tV7hgHWvi+mAMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAH/Ejh898Fl1qEAAQAAAf8wDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgooBNjZ1r
# SRrk68r9vqKIpwjWTy5lsZb7SqOuzqwrWbswgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCDkMu++yQJ3aaycIuMT6vA7JNuMaVOI3qDjSEV8upyn/TCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB/xI4fPfBZdahAAEA
# AAH/MCIEIGiqsSIWsqPvmXb38/DhNyRFEGLdDhu7Zrf5LilVtPcgMA0GCSqGSIb3
# DQEBCwUABIICAKUID9U4jh43x9NRZUDzkSR46ROeB/FZVDMlPmv8rYFqrzOM/5K+
# g64bIsJyW6EnI2fEXOvCZdJrsuv8zyZ0c9BH/nuzhD/IRXfjZME/7CU6cqdK2+6t
# VRvo3Pj/GGxeAdCGndf1xe8wq8TEICBdd/A+0idUjl6BonMA5HcjYlwj0TmfRvN4
# uACWsPw28w/pGMcn0K+nFLMcCS3SUOmoJYwdUc9dwWCexzmaw9kaIrQUWqOGkmiP
# iMSE5mliS8bEOHflwkk8x/hEka9In8ZsBHP6rqxWyk4WhEFH8pZokvz9bfVGwSmF
# 2BZM2o7gXuh1hrSyj2SGwMYBXgGBLwLeU1JAXjtnbpiiitBEDZ1bLBHT3nnYEm0t
# 1ZtExKUF5/lOQTlrwBdMNmyoJ9UpJI3ltixhv2PEuN/ywoGbO8Q2DiTSqfmGaiD2
# HBbF49EOxiKvJB8pzgehYWE4DE/8f9oMiShFDuxz6ojL9CwYNxZjNZLJsYmWU/aA
# X/vXbqBYp90UQxcgieUJjeQWjChy4WXWrU1If89Xyg7KrgAIo8r+AJVSH91+U8vk
# JKfQjrzA8Hnqw/lefk6QqQ0h0R6DS+FucVL/n7xQqQBtyy5ne2KxG4oqeuGADkYo
# TfjIccCC8JvgjnS81TgT02DsOIMKyO6Wvd0xo1kfPz7c6xw1S8hCOTBl
# SIG # End signature block
