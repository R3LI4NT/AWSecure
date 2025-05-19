#!/usr/bin/env python3
import boto3
import os
import sys
from termcolor import colored
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
from tabulate import tabulate
from datetime import datetime

class AWSecure:
    def __init__(self):
        self.sesion = None
        self.regiones = []
        self.comprobar_credenciales_aws()
        self.iniciar_sesion_aws()
        self.obtener_regiones()
        self.menu_principal()

    def mostrar_banner(self):
        banner = """

  $$$$$$\  $$\      $$\  $$$$$$\                                                    
 $$  __$$\ $$ | $\  $$ |$$  __$$\                                                   
 $$ /  $$ |$$ |$$$\ $$ |$$ /  \__| $$$$$$\   $$$$$$$\ $$\   $$\  $$$$$$\   $$$$$$\  
 $$$$$$$$ |$$ $$ $$\$$ |\$$$$$$\  $$  __$$\ $$  _____|$$ |  $$ |$$  __$$\ $$  __$$\ 
 $$  __$$ |$$$$  _$$$$ | \____$$\ $$$$$$$$ |$$ /      $$ |  $$ |$$ |  \__|$$$$$$$$ |
 $$ |  $$ |$$$  / \$$$ |$$\   $$ |$$   ____|$$ |      $$ |  $$ |$$ |      $$   ____|
 $$ |  $$ |$$  /   \$$ |\$$$$$$  |\$$$$$$$\ \$$$$$$$\ \$$$$$$  |$$ |      \$$$$$$$\ 
 \__|  \__|\__/     \__| \______/  \_______| \_______| \______/ \__|       \_______| 
                                                                                
        """
        print(colored(banner, 'yellow'))
        print(colored("="*80, 'blue'))
        print(colored("Github: @R3LI4NT", 'white'))
        print(colored("Herramienta de Pentest AWS - Auditoría de seguridad en AWS", 'red'))
        print(colored("="*80, 'blue'))
        print()

    def comprobar_credenciales_aws(self):
        print(colored("[*] Verificando credenciales AWS...", 'blue'))
        if not os.path.exists(os.path.expanduser('~/.aws/credentials')):
            print(colored("[-] ERROR: No se encontraron credenciales AWS configuradas", 'red'))
            print(colored("[!] Configure sus credenciales con 'aws configure' primero", 'yellow'))
            sys.exit(1)
        
        try:
            sts = boto3.client('sts')
            id_cuenta = sts.get_caller_identity()['Account']
            print(colored(f"[+] Credenciales AWS válidas encontradas (Cuenta: {id_cuenta})", 'green'))
        except (NoCredentialsError, ClientError) as e:
            print(colored(f"[-] Error con las credenciales AWS: {str(e)}", 'red'))
            sys.exit(1)

    def iniciar_sesion_aws(self):
        try:
            self.sesion = boto3.Session()
            print(colored("[+] Sesión AWS establecida correctamente", 'green'))
        except BotoCoreError as e:
            print(colored(f"[-] Error al establecer sesión AWS: {str(e)}", 'red'))
            sys.exit(1)

    def obtener_regiones(self):
        ec2 = self.sesion.client('ec2')
        self.regiones = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        print(colored(f"[+] Regiones AWS disponibles: {', '.join(self.regiones)}", 'green'))

    def verificar_mfa(self):
        print(colored("\n[*] Comprobando estado MFA de usuarios IAM...", 'blue'))
        iam = self.sesion.client('iam')
        
        try:
            usuarios = iam.list_users()['Users']
            print(colored(f"[+] Encontrados [{len(usuarios)}] usuarios IAM", 'green'))
            print(colored("[+] Por favor, aguarde un momento mientras generamos la tabla...", 'cyan'))
            
            datos_tabla = []
            encabezados = ["Usuario", "MFA Activo", "Último acceso", "Acceso Clave"]
            
            for usuario in usuarios:
                nombre_usuario = usuario['UserName']
                
                # Verificar MFA
                dispositivos_mfa = iam.list_mfa_devices(UserName=nombre_usuario)['MFADevices']
                estado_mfa = colored("SÍ", 'green') if dispositivos_mfa else colored("NO", 'red')
                
                # Obtener último acceso
                ultimo_acceso = "Nunca"
                if 'PasswordLastUsed' in usuario:
                    ultimo_acceso = usuario['PasswordLastUsed'].strftime('%Y-%m-%d %H:%M:%S')
                
                # Verificar claves de acceso
                claves_acceso = iam.list_access_keys(UserName=nombre_usuario)['AccessKeyMetadata']
                estado_clave = []
                for clave in claves_acceso:
                    info_ultimo_uso = iam.get_access_key_last_used(AccessKeyId=clave['AccessKeyId'])
                    if 'LastUsedDate' in info_ultimo_uso['AccessKeyLastUsed']:
                        estado_clave.append(info_ultimo_uso['AccessKeyLastUsed']['LastUsedDate'].strftime('%Y-%m-%d'))
                
                acceso_clave = "\n".join(estado_clave) if estado_clave else "Nunca"
                
                datos_tabla.append([
                    nombre_usuario,
                    estado_mfa,
                    ultimo_acceso,
                    acceso_clave
                ])
            
            # Mostrar tabla 
            print("\n" + colored(tabulate(
                datos_tabla, 
                headers=encabezados, 
                tablefmt="grid",
                stralign="left",
                numalign="left"
            ), 'cyan'))
            
            # Resumen estadístico
            usuarios_con_mfa = sum(1 for fila in datos_tabla if "SÍ" in fila[1])
            usuarios_sin_mfa = len(datos_tabla) - usuarios_con_mfa
            claves_activas = sum(1 for fila in datos_tabla if "Nunca" not in fila[3])
            
            print("\n" + colored("Resumen de seguridad:", 'yellow'))
            print(colored(f"- Usuarios con MFA habilitado: {usuarios_con_mfa}/{len(datos_tabla)}", 
                  'green' if usuarios_con_mfa == len(datos_tabla) else 'red'))
            print(colored(f"- Usuarios sin MFA: {usuarios_sin_mfa}", 'red' if usuarios_sin_mfa > 0 else 'green'))
            print(colored(f"- Claves de acceso activas: {claves_activas}", 
                  'red' if claves_activas > 0 else 'green'))
            
        except ClientError as e:
            print(colored(f"[-] Error al obtener usuarios IAM: {str(e)}", 'red'))

    def snapshots_no_cifrados(self):
        print(colored("\n[*] Buscando snapshots EBS no cifrados...", 'blue'))
        
        todos_no_cifrados = []
        
        for region in self.regiones:
            print(colored(f"\n[*] Escaneando región {region}...", 'yellow'))
            ec2 = self.sesion.client('ec2', region_name=region)
            
            try:
                snapshots = ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
                no_cifrados = [s for s in snapshots if not s['Encrypted']]
                
                if no_cifrados:
                    print(colored(f"[!] Encontrados {len(no_cifrados)} snapshots no cifrados en {region}", 'red'))
                    
                    # Preparar datos para la tabla
                    datos_tabla = []
                    encabezados = ["Snapshot ID", "Región", "Tamaño (GB)", "Fecha creación", "Descripción"]
                    
                    for snap in no_cifrados:
                        datos_tabla.append([
                            snap['SnapshotId'],
                            region,
                            str(snap['VolumeSize']),
                            snap['StartTime'].strftime('%Y-%m-%d %H:%M:%S'),
                            snap.get('Description', 'N/A')[:50] + '...' if 'Description' in snap else 'N/A'
                        ])
                    
                    # Mostrar tabla regional
                    print("\n" + colored(tabulate(
                        datos_tabla,
                        headers=encabezados,
                        tablefmt="grid",
                        stralign="left",
                        numalign="center"
                    ), 'white'))
                    
                    todos_no_cifrados.extend(datos_tabla)
                else:
                    print(colored(f"[+] No se encontraron snapshots no cifrados en {region}", 'green'))
                    
            except ClientError as e:
                print(colored(f"[-] Error al obtener snapshots en {region}: {str(e)}", 'red'))
        
        # Mostrar resumen 
        if todos_no_cifrados:
            print(colored("\n" + "="*80, 'red'))
            print(colored("RESUMEN GLOBAL DE SNAPSHOTS NO CIFRADOS", 'red', attrs=['bold']))
            print(colored("="*80, 'red'))
            
            # Estadísticas
            tamaño_total = sum(float(fila[2]) for fila in todos_no_cifrados)
            regiones_afectadas = len(set(fila[1] for fila in todos_no_cifrados))
            mas_antiguo = min(fila[3] for fila in todos_no_cifrados)
            
            print(colored(f"\n• Snapshots no cifrados totales: {len(todos_no_cifrados)}", 'yellow'))
            print(colored(f"• Regiones afectadas: {regiones_afectadas}", 'yellow'))
            print(colored(f"• Espacio total en riesgo: {tamaño_total} GB", 'yellow'))
            print(colored(f"• Snapshot más antiguo: {mas_antiguo}", 'yellow'))
            
            # Mostrar tabla 
            todos_no_cifrados.sort(key=lambda x: x[3], reverse=True)
            
            print("\n" + colored(tabulate(
                todos_no_cifrados,
                headers=encabezados,
                tablefmt="grid",
                stralign="left",
                numalign="center"
            ), 'cyan'))
            
            # Recomendación de acción
            print(colored("\n[!] RECOMENDACIÓN DE SEGURIDAD:", 'red', attrs=['bold']))
            print(colored("1. Cifrar snapshots existentes usando 'aws ec2 copy-snapshot --encrypted'", 'yellow'))
            print(colored("2. Habilitar cifrado predeterminado con 'aws ec2 enable-ebs-encryption-by-default'", 'yellow'))
            print(colored("3. Eliminar snapshots no cifrados originales después de verificar las copias cifradas", 'yellow'))

    def volumenes_no_cifrados(self):
        print(colored("\n[*] Buscando volúmenes EBS no cifrados...", 'blue'))
        
        todos_no_cifrados = []
        
        for region in self.regiones:
            print(colored(f"\n[*] Escaneando región {region}...", 'yellow'))
            ec2 = self.sesion.client('ec2', region_name=region)
            
            try:
                volumenes = ec2.describe_volumes()['Volumes']
                no_cifrados = [v for v in volumenes if not v['Encrypted']]
                
                if no_cifrados:
                    print(colored(f"[!] Encontrados {len(no_cifrados)} volúmenes no cifrados en {region}", 'red'))
                    
                    # Preparar datos para la tabla
                    datos_tabla = []
                    encabezados = ["Volume ID", "Región", "Tamaño (GB)", "Tipo", "Estado", "Instancia Adjunta", "AZ"]
                    
                    for vol in no_cifrados:
                        instancia_adjunta = vol['Attachments'][0]['InstanceId'] if vol['Attachments'] else "Ninguna"
                        datos_tabla.append([
                            vol['VolumeId'],
                            region,
                            str(vol['Size']),
                            vol['VolumeType'],
                            vol['State'],
                            instancia_adjunta,
                            vol['AvailabilityZone']
                        ])
                    
                    # Mostrar tabla regional
                    print("\n" + colored(tabulate(
                        datos_tabla,
                        headers=encabezados,
                        tablefmt="grid",
                        stralign="left",
                        numalign="center"
                    ), 'white'))
                    
                    todos_no_cifrados.extend(datos_tabla)
                else:
                    print(colored(f"[+] No se encontraron volúmenes no cifrados en {region}", 'green'))
                    
            except ClientError as e:
                print(colored(f"[-] Error al obtener volúmenes en {region}: {str(e)}", 'red'))
        
        # Mostrar resumen 
        if todos_no_cifrados:
            print(colored("\n" + "="*80, 'red'))
            print(colored("RESUMEN GLOBAL DE VOLÚMENES NO CIFRADOS", 'red', attrs=['bold']))
            print(colored("="*80, 'red'))
            
            # Estadísticas
            tamaño_total = sum(float(fila[2]) for fila in todos_no_cifrados)
            regiones_afectadas = len(set(fila[1] for fila in todos_no_cifrados))
            volumenes_adjuntos = sum(1 for fila in todos_no_cifrados if fila[5] != "Ninguna")
            
            print(colored(f"\n• Volúmenes no cifrados totales: {len(todos_no_cifrados)}", 'yellow'))
            print(colored(f"• Regiones afectadas: {regiones_afectadas}", 'yellow'))
            print(colored(f"• Espacio total en riesgo: {tamaño_total} GB", 'yellow'))
            print(colored(f"• Volúmenes adjuntos a instancias: {volumenes_adjuntos}", 'yellow'))
            
            # Mostrar tabla 
            todos_no_cifrados.sort(key=lambda x: float(x[2]), reverse=True)
            
            print("\n" + colored(tabulate(
                todos_no_cifrados,
                headers=encabezados,
                tablefmt="grid",
                stralign="left",
                numalign="center"
            ), 'cyan'))
            
            # Recomendación de acción
            print(colored("\n[!] RECOMENDACIÓN DE SEGURIDAD:", 'red', attrs=['bold']))
            print(colored("1. Cifrar volúmenes existentes creando copias cifradas", 'yellow'))
            print(colored("2. Habilitar cifrado predeterminado con 'aws ec2 enable-ebs-encryption-by-default'", 'yellow'))
            print(colored("3. Para volúmenes adjuntos:", 'yellow'))
            print(colored("   a. Crear snapshot cifrado", 'yellow'))
            print(colored("   b. Crear volumen cifrado del snapshot", 'yellow'))
            print(colored("   c. Detener instancia, desacoplar volumen antiguo", 'yellow'))
            print(colored("   d. Acoplar volumen cifrado y reiniciar instancia", 'yellow'))

    def buckets_inseguros(self):
        print(colored("\n[*] Buscando buckets S3 con HTTP habilitado...", 'blue'))
        s3 = self.sesion.client('s3')
        
        try:
            buckets = s3.list_buckets()['Buckets']
            print(colored(f"[+] Encontrados [{len(buckets)}] buckets S3", 'green'))
            print(colored(f"[+] Por favor, aguarde un momento...", 'cyan'))
            
            buckets_inseguros = []
            
            for bucket in buckets:
                nombre_bucket = bucket['Name']
                try:
                    politica = s3.get_bucket_policy(Bucket=nombre_bucket)['Policy']
                    if '"aws:SecureTransport":"false"' in politica:
                        buckets_inseguros.append(nombre_bucket)
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        print(colored(f"[-] Error al verificar política de {nombre_bucket}: {str(e)}", 'red'))
            
            if buckets_inseguros:
                print(colored("\n[!] Buckets con HTTP habilitado encontrados:", 'red'))
                for bucket in buckets_inseguros:
                    print(colored(f"  - {bucket}", 'yellow'))
            else:
                print(colored("\n[+] No se encontraron buckets con HTTP habilitado", 'green'))
                
        except ClientError as e:
            print(colored(f"[-] Error al listar buckets S3: {str(e)}", 'red'))

    def politica_contrasenas(self):
        print(colored("\n[*] Analizando políticas de contraseñas para usuarios IAM...", 'blue'))
        iam = self.sesion.client('iam')
        
        try:
            try:
                politica_cuenta = iam.get_account_password_policy()['PasswordPolicy']
            except iam.exceptions.NoSuchEntityException:
                print(colored("[-] No se encontró política de contraseñas a nivel de cuenta", 'red'))
                politica_cuenta = {}
            
            
            print(colored("[-] Analizando política de contraseñas a nivel de usuarios. Por favor, aguarde un momento...", 'cyan'))
            usuarios = iam.list_users()['Users']
            
            # Preparar datos para la tabla
            datos_tabla = []
            encabezados = [
                "Usuario",
                "MFA Activo",
                "Claves de acceso",
                "Último uso contraseña",
                "Long. mínima",
                "Requisitos complejidad",
                "Rotación requerida",
                "Reuso contraseñas",
                "Política personalizada"
            ]
            
            for usuario in usuarios:
                nombre_usuario = usuario['UserName']
                
                # Verificar MFA
                dispositivos_mfa = iam.list_mfa_devices(UserName=nombre_usuario)['MFADevices']
                estado_mfa = colored("SÍ", 'green') if dispositivos_mfa else colored("NO", 'red')
                
                # Verificar claves de acceso
                claves_acceso = iam.list_access_keys(UserName=nombre_usuario)['AccessKeyMetadata']
                estado_clave = colored(f"{len(claves_acceso)} activas", 'red' if len(claves_acceso) > 0 else 'green')
                
                # Último uso de contraseña
                ultimo_uso = usuario.get('PasswordLastUsed', 'Nunca')
                if ultimo_uso != 'Nunca':
                    ultimo_uso = ultimo_uso.strftime('%Y-%m-%d')
                
                # Verificar si tiene política personalizada
                politicas_usuario = iam.list_user_policies(UserName=nombre_usuario)['PolicyNames']
                politicas_adjuntas = iam.list_attached_user_policies(UserName=nombre_usuario)['AttachedPolicies']
                politica_personalizada = colored("SÍ", 'yellow') if politicas_usuario or politicas_adjuntas else "NO"
                
                datos_tabla.append([
                    nombre_usuario,
                    estado_mfa,
                    estado_clave,
                    ultimo_uso,
                    politica_cuenta.get('MinimumPasswordLength', 'No definido'),
                    colored("SÍ", 'green') if politica_cuenta.get('RequireSymbols', False) else colored("NO", 'red'),
                    colored("SÍ", 'green') if politica_cuenta.get('RequireNumbers', False) else colored("NO", 'red'),
                    colored("SÍ", 'green') if politica_cuenta.get('RequireUppercaseCharacters', False) else colored("NO", 'red'),
                    colored("SÍ", 'green') if politica_cuenta.get('RequireLowercaseCharacters', False) else colored("NO", 'red'),
                    politica_cuenta.get('MaxPasswordAge', 'No definido'),
                    politica_cuenta.get('PasswordReusePrevention', 'No definido'),
                    politica_personalizada
                ])
            
            # Mostrar tabla 
            print("\n" + colored(tabulate(
                datos_tabla, 
                headers=encabezados, 
                tablefmt="grid",
                stralign="left",
                numalign="center"
            ), 'cyan'))
            
            # Mostrar resumen 
            print(colored("\n[+] Resumen de política de contraseñas a nivel de cuenta:", 'yellow'))
            print(colored(f"• Longitud mínima: {politica_cuenta.get('MinimumPasswordLength', 'No definido')}", 'cyan'))
            print(colored(f"• Requiere símbolos: {'Sí' if politica_cuenta.get('RequireSymbols', False) else 'No'}", 'cyan'))
            print(colored(f"• Requiere números: {'Sí' if politica_cuenta.get('RequireNumbers', False) else 'No'}", 'cyan'))
            print(colored(f"• Requiere mayúsculas: {'Sí' if politica_cuenta.get('RequireUppercaseCharacters', False) else 'No'}", 'cyan'))
            print(colored(f"• Requiere minúsculas: {'Sí' if politica_cuenta.get('RequireLowercaseCharacters', False) else 'No'}", 'cyan'))
            print(colored(f"• Edad máxima (días): {politica_cuenta.get('MaxPasswordAge', 'No definido')}", 'cyan'))
            print(colored(f"• Prevención de reuso: {politica_cuenta.get('PasswordReusePrevention', 'No definido')}", 'cyan'))
            
            # Recomendaciones de seguridad
            print(colored("\n[!] RECOMENDACIONES DE SEGURIDAD:", 'red', attrs=['bold']))
            if not politica_cuenta:
                print(colored("1. Configurar política de contraseñas a nivel de cuenta", 'yellow'))
            if politica_cuenta.get('MinimumPasswordLength', 0) < 12:
                print(colored("2. Aumentar longitud mínima a al menos 12 caracteres", 'yellow'))
            if not politica_cuenta.get('RequireSymbols', False):
                print(colored("3. Habilitar requisito de caracteres especiales", 'yellow'))
            if not politica_cuenta.get('MaxPasswordAge', False):
                print(colored("4. Establecer rotación obligatoria de contraseñas (90 días recomendado)", 'yellow'))
            
        except ClientError as e:
            print(colored(f"[-] Error al obtener políticas de contraseñas: {str(e)}", 'red'))

    def validacion_logs(self):
        print(colored("\n[*] Validando configuración de CloudTrail...", 'blue'))
        cloudtrail = self.sesion.client('cloudtrail')
        
        try:
            trails = cloudtrail.describe_trails()['trailList']
            
            if not trails:
                print(colored("[!] No se encontraron trails de CloudTrail configurados", 'red'))
                return
            
            # Preparar datos
            datos_tabla = []
            encabezados = [
                "Nombre del Trail",
                "Región",
                "Validación de Logs",
                "Multi-Región",
                "S3 Bucket",
                "Estado",
                "Notificaciones"
            ]
            
            for trail in trails:
                nombre_trail = trail['Name']
                region = trail.get('HomeRegion', 'N/A')
                
                estado_trail = cloudtrail.get_trail_status(Name=nombre_trail)
                estado_validacion = trail.get('LogFileValidationEnabled', False)
                es_multi_region = trail.get('IsMultiRegionTrail', False)
                logs_cw = trail.get('CloudWatchLogsLogGroupArn', 'No configurado')
                
                datos_tabla.append([
                    nombre_trail,
                    region,
                    colored("DESHABILITADA", 'red') if not estado_validacion else colored("HABILITADA", 'green'),
                    colored("SÍ", 'green') if es_multi_region else colored("NO", 'yellow'),
                    trail.get('S3BucketName', 'N/A'),
                    colored("ACTIVO", 'green') if estado_trail.get('IsLogging', False) else colored("INACTIVO", 'red'),
                    "CloudWatch: " + ("SÍ" if logs_cw != 'No configurado' else "NO")
                ])
            
            print("\n" + colored(tabulate(
                datos_tabla, 
                headers=encabezados, 
                tablefmt="grid",
                stralign="left",
                numalign="center"
            ), 'white'))
            
            # Identificar trails 
            trails_problematicos = [t[0] for t in datos_tabla if "DESHABILITADA" in t[2]]
            
            if trails_problematicos:
                print(colored("\n[!] SE ENCONTRARON TRAILS CON VALIDACIÓN DE LOGS DESHABILITADA:", 'red', attrs=['bold']))
                for trail in trails_problematicos:
                    print(colored(f"  - {trail}", 'yellow'))
                
                print(colored("\n[!] RIESGO DE SEGURIDAD:", 'red'))
                print(colored("La validación de archivos de log (Log File Validation) está deshabilitada.", 'red'))
                print(colored("Esto significa que no se puede detectar si los archivos de log han sido modificados o", 'red'))
                print(colored("alterados después de que CloudTrail los haya entregado.", 'red'))
                
                print(colored("\n[!] RECOMENDACIONES:", 'yellow'))
                print(colored("1. Habilitar Log File Validation en todos los trails de CloudTrail", 'yellow'))
                print(colored("2. Usar el siguiente comando para habilitarlo:", 'yellow'))
                print(colored(f"   aws cloudtrail update-trail --name {trails_problematicos[0]} --enable-log-file-validation", 'green'))
                print(colored("3. Considerar habilitar trails multi-región para cobertura completa", 'yellow'))
                print(colored("4. Habilitar integración con CloudWatch Logs para mayor seguridad", 'yellow'))
            else:
                print(colored("\n[+] Todos los trails tienen habilitada la validación de archivos de log", 'green'))
                
        except ClientError as e:
            print(colored(f"[-] Error al verificar CloudTrail: {str(e)}", 'red'))

    def politica_roles(self):
        print(colored("\n[*] Buscando políticas que permiten iam:PassRole sin restricciones...", 'blue'))
        iam = self.sesion.client('iam')
    
        try:
        # Obtener todas las políticas administradas 
            politicas = []
            for ambito in ['AWS', 'Local']:
                paginador = iam.get_paginator('list_policies')
                for pagina in paginador.paginate(Scope=ambito):
                    politicas.extend(pagina['Policies'])
        
            politicas_riesgosas = []
        
            for politica in politicas:
                try:
                # Obtener versión de la política
                    version_politica = iam.get_policy_version(
                        PolicyArn=politica['Arn'],
                        VersionId=politica['DefaultVersionId']
                    )['PolicyVersion']
                
                    if self._politica_permite_pasorol_todos_recursos(version_politica['Document']):
                        entidades_adjuntas = self._obtener_entidades_adjuntas(iam, politica['Arn'])
                        politicas_riesgosas.append({
                            'Nombre': politica['PolicyName'],
                            'ARN': politica['Arn'],
                            'Tipo': 'AWS Managed' if politica['Arn'].startswith('arn:aws:iam::aws:policy') else 'Custom',
                            'Adjunta a': ', '.join(entidades_adjuntas) if entidades_adjuntas else 'No adjunta'
                        })
                    
                except ClientError as e:
                    print(colored(f"  [-] Error al analizar política {politica['PolicyName']}: {str(e)}", 'red'))
                    continue
        
            if politicas_riesgosas:
                print(colored("\n[!] POLÍTICAS RIESGOSAS ENCONTRADAS:", 'red', attrs=['bold']))
                print(colored("Las siguientes políticas permiten iam:PassRole sobre todos los recursos (*)", 'red'))
                print(tabulate(
                    politicas_riesgosas,
                    headers="keys",
                    tablefmt="grid",
                    stralign="left"
                ))
            
                print(colored("\n[!] RIESGO DE SEGURIDAD:", 'red'))
                print(colored("Estas políticas permiten que entidades pasen cualquier rol IAM a servicios AWS,", 'red'))
                print(colored("lo que podría permitir escalamiento de privilegios si un atacante compromete", 'red'))
                print(colored("una entidad con estos permisos.", 'red'))
            
                print(colored("\n[!] RECOMENDACIONES:", 'yellow'))
                print(colored("1. Modificar las políticas para restringir iam:PassRole a roles específicos:", 'yellow'))
                print(colored("   Ejemplo de política segura:", 'green'))
                print(colored('   {"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::*:role/specific-role"}', 'green'))
                print(colored("2. Revisar todas las entidades (usuarios/roles) que tienen estas políticas adjuntas", 'yellow'))
                print(colored("3. Considerar usar condiciones adicionales como iam:PassedToService", 'yellow'))
            else:
                print(colored("\n[+] No se encontraron políticas que permitan iam:PassRole sin restricciones", 'green'))
            
        except ClientError as e:
            print(colored(f"[-] Error al verificar políticas IAM: {str(e)}", 'red'))

    def _politica_permite_pasorol_todos_recursos(self, documento_politica):
        import json

        if isinstance(documento_politica, str):
            try:
                documento_politica = json.loads(documento_politica)
            except json.JSONDecodeError:
                return False
    
        if not isinstance(documento_politica, dict):
            return False
        
        declaraciones = documento_politica.get('Statement', [])
        if isinstance(declaraciones, dict):
            declaraciones = [declaraciones]
    
        for declaracion in declaraciones:
            if declaracion.get('Effect') == 'Allow':
                acciones = declaracion.get('Action', [])
                if isinstance(acciones, str):
                    acciones = [acciones]
            
                recursos = declaracion.get('Resource', [])
                if isinstance(recursos, str):
                    recursos = [recursos]
            
            # Buscar iam:PassRole con recurso *
                if (any(accion.lower() in ['iam:passrole', 'iam:*', '*'] for accion in acciones)) and '*' in recursos:
                    return True
        return False

    def _obtener_entidades_adjuntas(self, cliente_iam, arn_politica):
        entidades = []
    
        try:
            paginador_usuarios = cliente_iam.get_paginator('list_entities_for_policy')
            for pagina in paginador_usuarios.paginate(PolicyArn=arn_politica, EntityFilter='User'):
                entidades.extend([f"user:{u['UserName']}" for u in pagina['PolicyUsers']])
        except ClientError:
            pass
    
        try:
            paginador_grupos = cliente_iam.get_paginator('list_entities_for_policy')
            for pagina in paginador_grupos.paginate(PolicyArn=arn_politica, EntityFilter='Group'):
                entidades.extend([f"group:{g['GroupName']}" for g in pagina['PolicyGroups']])
        except ClientError:
            pass

        try:
            paginador_roles = cliente_iam.get_paginator('list_entities_for_policy')
            for pagina in paginador_roles.paginate(PolicyArn=arn_politica, EntityFilter='Role'):
                entidades.extend([f"role:{r['RoleName']}" for r in pagina['PolicyRoles']])
        except ClientError:
            pass
    
        return entidades

    def menu_principal(self):
        self.mostrar_banner()
        
        while True:
            print(colored("\nMenú Principal:", 'magenta'))
            print(colored("1. Verificar estado MFA de usuarios", 'cyan'))
            print(colored("2. Buscar snapshots EBS no cifrados", 'cyan'))
            print(colored("3. Buscar volúmenes EBS no cifrados", 'cyan'))
            print(colored("4. Buscar buckets S3 con HTTP habilitado", 'cyan'))
            print(colored("5. Verificar políticas de contraseñas", 'cyan'))
            print(colored("6. Validar CloudTrail Log Validation", 'cyan')) 
            print(colored("7. Verificar políticas permisivas de iam:PassRole", 'cyan'))
            print(colored("8. Ejecutar todas las comprobaciones", 'cyan'))
            print(colored("9. Salir", 'cyan'))
            
            opcion = input(colored("\nSeleccione una opción (1-9): ", 'yellow'))
            
            if opcion == '1':
                self.verificar_mfa()
            elif opcion == '2':
                self.snapshots_no_cifrados()
            elif opcion == '3':
                self.volumenes_no_cifrados()
            elif opcion == '4':
                self.buckets_inseguros()
            elif opcion == '5':
                self.politica_contrasenas()
            elif opcion == '6':  
                self.validacion_logs()
            elif opcion == '7':
                self.politica_roles()
            elif opcion == '8':
                self.verificar_mfa()
                self.snapshots_no_cifrados()
                self.volumenes_no_cifrados()
                self.buckets_inseguros()
                self.politica_contrasenas()
                self.validacion_logs()
                self.politica_roles()
            elif opcion == '9':
                print(colored("\n[+] Saliendo de la herramienta. ¡Hasta luego!", 'green'))
                sys.exit(0)
            else:
                print(colored("\n[-] Opción no válida. Intente nuevamente.", 'red'))

if __name__ == "__main__":
    try:
        herramienta = AWSecure()
    except KeyboardInterrupt:
        print(colored("\n[!] Interrupción por usuario. Saliendo...", 'yellow'))
        sys.exit(1)