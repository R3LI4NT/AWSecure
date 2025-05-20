#!/usr/bin/env python3
import boto3
import os
import sys
from termcolor import colored
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
from tabulate import tabulate
from datetime import datetime
from modules.verificarMFA import MFAChecker
from modules.verificarSnapshots import SnapshotChecker
from modules.verificarVolumenesEBS import VolumeChecker
from modules.verificarPoliticaContraseñas import PasswordPolicyChecker
from modules.verificarLogsFile import CloudTrailLogsChecker
from modules.verificarBucketsInseguros import BucketSecurityChecker
from modules.verificarPoliticaRoles import RolePolicyChecker

class AWSecure:
    def __init__(self):
        self.sesion = None
        self.regiones = []
        self.mfa_results = []
        self.comprobar_credenciales_aws()
        self.iniciar_sesion_aws()
        self.obtener_regiones()
        self.mfa_checker = MFAChecker(self.sesion)
        self.snapshot_checker = SnapshotChecker(self.sesion)
        self.volume_checker = VolumeChecker(self.sesion)
        self.passwords_checker = PasswordPolicyChecker(self.sesion)
        self.logsvalidation_checker = CloudTrailLogsChecker(self.sesion)
        self.bucketsHTTP_checker = BucketSecurityChecker(self.sesion)
        self.role_policy_checker = RolePolicyChecker(self.sesion)
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

    def snapshots_no_cifrados(self):
        self.snapshot_checker.verificar_snapshots_no_cifrados()

    def volumenes_no_cifrados(self):
        self.volume_checker.verificar_volumenes_no_cifrados()

    def bucketsHTTP_inseguros(self):
        self.bucketsHTTP_checker.verificar_buckets_inseguros()

    def politica_de_contraseñas(self):
        self.volume_checker.verificar_politica_contraseña()

    def validacion_logs_cloudtrails(self):
        self.logsvalidation_checker.validacion_logs()

    def politica_roles(self):
        self.role_policy_checker.verificar_politicas_riesgosas()

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
            print(colored("8. Salir", 'cyan'))
            
            opcion = input(colored("\nSeleccione una opción (1-8): ", 'yellow'))
            
            if opcion == '1':
                self.mfa_checker.verificar_mfa()
            elif opcion == '2':
                self.snapshot_checker.verificar_snapshots_no_cifrados()
            elif opcion == '3':
                self.volume_checker.verificar_volumenes_no_cifrados()
            elif opcion == '4':
                self.bucketsHTTP_checker.verificar_buckets_inseguros()
            elif opcion == '5':
                self.passwords_checker.verificar_politica_contraseña()
            elif opcion == '6':  
                self.logsvalidation_checker.validacion_logs()
            elif opcion == '7':
                self.role_policy_checker.verificar_politicas_riesgosas()
            elif opcion == '8':
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
