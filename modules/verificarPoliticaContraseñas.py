import boto3
from termcolor import colored
from botocore.exceptions import ClientError
from tabulate import tabulate
from datetime import datetime
import os

class PasswordPolicyChecker:
    def __init__(self, session):
        self.sesion = session
        self.iam = self.sesion.client('iam')
        self.password_policy_results = []
        self.users_without_mfa = []
        self.users_with_old_passwords = []
        
    def verificar_politica_contraseña(self):
        print(colored("\n[*] Analizando políticas de contraseñas para usuarios IAM...", 'blue'))
        
        try:
            # Obtener política de contraseñas a nivel de cuenta
            try:
                account_policy = self.iam.get_account_password_policy()['PasswordPolicy']
                print(colored("[+] Política de contraseñas a nivel de cuenta encontrada", 'green'))
            except self.iam.exceptions.NoSuchEntityException:
                print(colored("[-] No se encontró política de contraseñas a nivel de cuenta", 'red'))
                account_policy = {}
            
            # Obtener todos los usuarios IAM
            users = []
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            print(colored(f"[+] Encontrados {len(users)} usuarios IAM", 'green'))
            print(colored("[+] Por favor, aguarde mientras se generan los datos...", 'cyan'))
            
            # Preparar datos para análisis
            self.password_policy_results = []
            password_stats = {
                'mfa_enabled': 0,
                'access_keys': 0,
                'password_never_used': 0,
                'custom_policies': 0
            }
            
            for user in users:
                user_name = user['UserName']
                
                # Verificar MFA
                mfa_devices = self.iam.list_mfa_devices(UserName=user_name)['MFADevices']
                has_mfa = bool(mfa_devices)
                if not has_mfa:
                    self.users_without_mfa.append(user_name)
                
                # Verificar claves de acceso
                access_keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                
                # Último uso de contraseña
                last_used = user.get('PasswordLastUsed', 'Nunca')
                if last_used == 'Nunca':
                    password_stats['password_never_used'] += 1
                else:
                    days_since_use = (datetime.now(last_used.tzinfo) - last_used).days
                    if days_since_use > 90:
                        self.users_with_old_passwords.append({
                            'user': user_name,
                            'last_used': last_used.strftime('%Y-%m-%d'),
                            'days': days_since_use
                        })
                
                # Verificar políticas personalizadas
                user_policies = self.iam.list_user_policies(UserName=user_name)['PolicyNames']
                attached_policies = self.iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
                has_custom_policy = bool(user_policies or attached_policies)
                if has_custom_policy:
                    password_stats['custom_policies'] += 1
                
                # Guardar datos para el reporte
                self.password_policy_results.append({
                    'user_name': user_name,
                    'mfa_enabled': has_mfa,
                    'access_keys': len(access_keys),
                    'last_password_use': last_used.strftime('%Y-%m-%d') if last_used != 'Nunca' else 'Nunca',
                    'has_custom_policy': has_custom_policy
                })
                
                # Actualizar estadísticas
                password_stats['mfa_enabled'] += 1 if has_mfa else 0
                password_stats['access_keys'] += len(access_keys)
            
            # Mostrar resumen inicial
            self.mostrar_resumen_inicial(account_policy, password_stats, len(users))
            
            # Generar reporte detallado
            self.generar_reporte_politica_contraseñas(account_policy)
            
            # Preguntar si generar reporte HTML
            self.preguntar_generar_reporte()
            
        except ClientError as e:
            print(colored(f"[-] Error al verificar políticas de contraseñas: {str(e)}", 'red'))
    
    def mostrar_resumen_inicial(self, account_policy, stats, total_users):
        print(colored("\n" + "="*80, 'blue'))
        print(colored("RESUMEN DE POLÍTICAS DE CONTRASEÑAS", 'blue', attrs=['bold']))
        print(colored("="*80, 'blue'))
        
        # Mostrar política de cuenta
        print(colored("\n[+] Política de contraseñas a nivel de cuenta:", 'yellow'))
        print(colored(f"• Longitud mínima: {account_policy.get('MinimumPasswordLength', 'No definido')}", 'cyan'))
        print(colored(f"• Requiere símbolos: {'Sí' if account_policy.get('RequireSymbols', False) else 'No'}", 'cyan'))
        print(colored(f"• Requiere números: {'Sí' if account_policy.get('RequireNumbers', False) else 'No'}", 'cyan'))
        print(colored(f"• Requiere mayúsculas: {'Sí' if account_policy.get('RequireUppercaseCharacters', False) else 'No'}", 'cyan'))
        print(colored(f"• Requiere minúsculas: {'Sí' if account_policy.get('RequireLowercaseCharacters', False) else 'No'}", 'cyan'))
        print(colored(f"• Rotación obligatoria: {'Sí' if account_policy.get('MaxPasswordAge', False) else 'No'}", 'cyan'))
        print(colored(f"• Prevención de reuso: {account_policy.get('PasswordReusePrevention', 'No definido')}", 'cyan'))
        
        # Mostrar estadísticas de usuarios
        print(colored("\n[+] Estadísticas de usuarios:", 'yellow'))
        print(colored(f"• Usuarios con MFA habilitado: {stats['mfa_enabled']}/{total_users} ({stats['mfa_enabled']/total_users*100:.1f}%)", 
              'green' if stats['mfa_enabled']/total_users > 0.8 else 'red'))
        print(colored(f"• Usuarios con claves de acceso: {stats['access_keys']}", 
              'green' if stats['access_keys'] == 0 else 'yellow'))
        print(colored(f"• Usuarios que nunca usaron su contraseña: {stats['password_never_used']}", 
              'green' if stats['password_never_used'] == 0 else 'yellow'))
        print(colored(f"• Usuarios con políticas personalizadas: {stats['custom_policies']}", 'cyan'))
        
        # Mostrar usuarios sin MFA si los hay
        if self.users_without_mfa:
            print(colored("\n[!] Usuarios sin MFA habilitado:", 'red'))
            for user in self.users_without_mfa:
                print(colored(f"  - {user}", 'yellow'))
        
        # Mostrar usuarios con contraseñas antiguas si los hay
        if self.users_with_old_passwords:
            print(colored("\n[!] Usuarios con contraseñas no usadas en más de 90 días:", 'red'))
            for user in self.users_with_old_passwords:
                print(colored(f"  - {user['user']} (último uso: {user['last_used']}, hace {user['days']} días)", 'yellow'))
    
    def generar_reporte_politica_contraseñas(self, account_policy):
        # Preparar datos para la tabla
        table_data = []
        headers = [
            "Usuario",
            "MFA Habilitado",
            "Claves de Acceso",
            "Último Uso",
            "Política Personalizada"
        ]
        
        for user in self.password_policy_results:
            table_data.append([
                user['user_name'],
                colored("SÍ", 'green') if user['mfa_enabled'] else colored("NO", 'red'),
                colored(str(user['access_keys']), 'red' if user['access_keys'] > 0 else 'green'),
                user['last_password_use'],
                colored("SÍ", 'yellow') if user['has_custom_policy'] else "NO"
            ])
        
        # Mostrar tabla
        print("\n" + colored(tabulate(
            table_data,
            headers=headers,
            tablefmt="grid",
            stralign="left",
            numalign="center"
        ), 'white'))
        
        # Mostrar recomendaciones
        self.mostrar_recomendaciones(account_policy)
    
    def mostrar_recomendaciones(self, account_policy):
        print(colored("\n[!] RECOMENDACIONES DE SEGURIDAD:", 'red', attrs=['bold']))
        
        if not account_policy:
            print(colored("1. Configurar política de contraseñas a nivel de cuenta", 'yellow'))
            print(colored("   aws iam update-account-password-policy --minimum-password-length 12 \\", 'green'))
            print(colored("   --require-symbols --require-numbers --require-uppercase-characters \\", 'green'))
            print(colored("   --require-lowercase-characters --max-password-age 90 \\", 'green'))
            print(colored("   --password-reuse-prevention 3", 'green'))
        else:
            if account_policy.get('MinimumPasswordLength', 0) < 12:
                print(colored("1. Aumentar longitud mínima a al menos 12 caracteres", 'yellow'))
                print(colored("   aws iam update-account-password-policy --minimum-password-length 12", 'green'))
            
            if not account_policy.get('RequireSymbols', False):
                print(colored("2. Habilitar requisito de caracteres especiales", 'yellow'))
                print(colored("   aws iam update-account-password-policy --require-symbols", 'green'))
            
            if not account_policy.get('MaxPasswordAge', False):
                print(colored("3. Establecer rotación obligatoria de contraseñas (90 días recomendado)", 'yellow'))
                print(colored("   aws iam update-account-password-policy --max-password-age 90", 'green'))
        
        if self.users_without_mfa:
            print(colored("4. Habilitar MFA para todos los usuarios, especialmente:", 'yellow'))
            for user in self.users_without_mfa[:5]:  # Mostrar solo los primeros 5 para no saturar
                print(colored(f"   - {user}", 'yellow'))
            print(colored("   Puede usar: aws iam create-virtual-mfa-device --virtual-mfa-device-name NombreDispositivo \\", 'green'))
            print(colored("   --outfile QRCode.png --bootstrap-mfa", 'green'))
        
        if self.users_with_old_passwords:
            print(colored("5. Forzar rotación de contraseñas para usuarios con contraseñas antiguas:", 'yellow'))
            for user in self.users_with_old_passwords[:3]:  # Mostrar solo los primeros 3 ejemplos
                print(colored(f"   - {user['user']} (último uso hace {user['days']} días)", 'yellow'))
            print(colored("   Puede forzar cambio en el próximo login con:", 'green'))
            print(colored("   aws iam update-login-profile --user-name USUARIO --password-reset-required", 'green'))
    
    def preguntar_generar_reporte(self):
        respuesta = input(colored("\n[?] ¿Desea generar un reporte HTML interactivo de estos resultados? (s/n): ", 'yellow'))
        if respuesta.lower() == 's':
            self.generarHTMLReport()
    
    def generarHTMLReport(self):
        print(colored("\n[*] Generando reporte HTML interactivo...", 'blue'))
        
        if not self.password_policy_results:
            print(colored("[!] No hay datos para generar el reporte", 'yellow'))
            return
        
        # Estadísticas para el reporte
        total_users = len(self.password_policy_results)
        mfa_enabled = sum(1 for u in self.password_policy_results if u['mfa_enabled'])
        mfa_percentage = mfa_enabled / total_users * 100
        access_keys = sum(u['access_keys'] for u in self.password_policy_results)
        never_used = sum(1 for u in self.password_policy_results if u['last_password_use'] == 'Nunca')
        custom_policies = sum(1 for u in self.password_policy_results if u['has_custom_policy'])
        
        # Preparar datos para la tabla
        table_rows = ""
        for user in self.password_policy_results:
            table_rows += f"""
            <tr>
                <td>{user['user_name']}</td>
                <td class="{ 'text-success' if user['mfa_enabled'] else 'text-danger' }">
                    {'SÍ' if user['mfa_enabled'] else 'NO'}
                </td>
                <td class="{ 'text-danger' if user['access_keys'] > 0 else 'text-success' }">
                    {user['access_keys']}
                </td>
                <td>{user['last_password_use']}</td>
                <td class="{ 'text-warning' if user['has_custom_policy'] else '' }">
                    {'SÍ' if user['has_custom_policy'] else 'NO'}
                </td>
            </tr>
            """
        
        # Preparar lista de usuarios sin MFA
        no_mfa_list = ""
        for user in self.users_without_mfa[:10]:  # Limitar a 10 para no hacer muy largo el reporte
            no_mfa_list += f"""
            <li class="list-group-item d-flex justify-content-between align-items-center">
                {user}
                <span class="badge bg-danger rounded-pill">Sin MFA</span>
            </li>
            """
        
        # Preparar lista de usuarios con contraseñas antiguas
        old_passwords_list = ""
        for user in sorted(self.users_with_old_passwords, key=lambda x: x['days'], reverse=True)[:5]:
            old_passwords_list += f"""
            <li class="list-group-item d-flex justify-content-between align-items-center">
                {user['user']}
                <span class="badge bg-warning text-dark rounded-pill">{user['days']} días sin uso</span>
            </li>
            """
        
        # Plantilla HTML
        html_template = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad AWS - Políticas de Contraseñas</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            padding: 20px;
        }}
        .report-header {{
            background-color: #343a40;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .card-positive {{
            background-color: #d4edda;
            border-left: 5px solid #28a745;
        }}
        .card-negative {{
            background-color: #f8d7da;
            border-left: 5px solid #dc3545;
        }}
        .card-warning {{
            background-color: #fff3cd;
            border-left: 5px solid #ffc107;
        }}
        .card-neutral {{
            background-color: #e2e3e5;
            border-left: 5px solid #6c757d;
        }}
        .table-responsive {{
            margin-top: 20px;
        }}
        .risk-description {{
            background-color: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 5px solid #ffc107;
        }}
        .list-group-item {{
            transition: all 0.3s;
        }}
        .list-group-item:hover {{
            background-color: #f8f9fa;
        }}
        .mfa-badge {{
            background-color: #dc3545;
        }}
        .old-password-badge {{
            background-color: #fd7e14;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header text-center">
            <h1>Reporte de Seguridad AWS</h1>
            <h2>Políticas de Contraseñas y MFA</h2>
            <p class="mb-0">Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="row">
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if mfa_percentage > 80 else 'card-negative' }">
                    <h5>MFA Habilitado</h5>
                    <h3>{mfa_percentage:.1f}%</h3>
                    <p class="mb-0">{mfa_enabled} de {total_users} usuarios</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if access_keys == 0 else 'card-warning' }">
                    <h5>Claves de Acceso</h5>
                    <h3>{access_keys}</h3>
                    <p class="mb-0">Total en todos los usuarios</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if never_used == 0 else 'card-warning' }">
                    <h5>Contraseñas Nunca Usadas</h5>
                    <h3>{never_used}</h3>
                    <p class="mb-0">Usuarios</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card card-neutral">
                    <h5>Políticas Personalizadas</h5>
                    <h3>{custom_policies}</h3>
                    <p class="mb-0">Usuarios</p>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="risk-description">
                    <h4><i class="bi bi-exclamation-triangle-fill"></i> Riesgos de Seguridad</h4>
                    <ul>
                        <li>Usuarios sin MFA son vulnerables a ataques de fuerza bruta</li>
                        <li>Contraseñas débiles pueden ser adivinadas o crackeadas</li>
                        <li>Claves de acceso permanentes son un riesgo si se filtran</li>
                        <li>Contraseñas antiguas aumentan el riesgo de compromiso</li>
                        <li>Políticas personalizadas podrían otorgar permisos excesivos</li>
                    </ul>
                </div>
            </div>
            <div class="col-md-6">
                <div class="recommendations">
                    <h4><i class="bi bi-check-circle-fill"></i> Recomendaciones</h4>
                    <ul class="list-group">
                        <li class="list-group-item">Habilitar MFA para todos los usuarios</li>
                        <li class="list-group-item">Implementar política de contraseñas fuertes</li>
                        <li class="list-group-item">Reemplazar claves de acceso permanentes con roles temporales</li>
                        <li class="list-group-item">Forzar rotación periódica de contraseñas</li>
                        <li class="list-group-item">Revisar políticas personalizadas para permisos excesivos</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <i class="bi bi-shield-exclamation"></i> Usuarios sin MFA ({len(self.users_without_mfa)})
                    </div>
                    <div class="card-body">
                        <ul class="list-group">
                            {no_mfa_list}
                            {f'<li class="list-group-item text-center">... y {len(self.users_without_mfa)-10} más</li>' if len(self.users_without_mfa) > 10 else ''}
                        </ul>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <i class="bi bi-clock-history"></i> Contraseñas Antiguas ({len(self.users_with_old_passwords)})
                    </div>
                    <div class="card-body">
                        <ul class="list-group">
                            {old_passwords_list}
                            {f'<li class="list-group-item text-center">... y {len(self.users_with_old_passwords)-5} más</li>' if len(self.users_with_old_passwords) > 5 else ''}
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="table-responsive mt-4">
            <table id="usersTable" class="table table-striped table-bordered" style="width:100%">
                <thead class="table-dark">
                    <tr>
                        <th>Usuario</th>
                        <th>MFA</th>
                        <th>Claves Acceso</th>
                        <th>Último Uso</th>
                        <th>Política Personalizada</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>

        <div class="commands-section mt-4">
            <h4><i class="bi bi-terminal-fill"></i> Comandos útiles</h4>
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Actualizar política de contraseñas</h5>
                    <code>aws iam update-account-password-policy --minimum-password-length 12 \\
    --require-symbols --require-numbers --require-uppercase-characters \\
    --require-lowercase-characters --max-password-age 90 \\
    --password-reuse-prevention 3</code>
                    
                    <h5 class="card-title mt-3">Habilitar MFA para un usuario</h5>
                    <code>aws iam create-virtual-mfa-device --virtual-mfa-device-name NombreDispositivo \\
    --outfile QRCode.png --bootstrap-mfa</code>
                    
                    <h5 class="card-title mt-3">Forzar cambio de contraseña</h5>
                    <code>aws iam update-login-profile --user-name USUARIO --password-reset-required</code>
                </div>
            </div>
        </div>

        <footer class="mt-5 text-center text-muted">
            <p>Reporte generado por <a href="https://github.com/R3LI4NT/AWSecure" target="__blank" style="text-decoration:none;">AWSecure</a> - Herramienta de Auditoría de Seguridad AWS</p>
        </footer>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js"></script>
    <script>
        $(document).ready(function() {{
            $('#usersTable').DataTable({{
                "language": {{
                    "url": "//cdn.datatables.net/plug-ins/1.11.5/i18n/Spanish.json"
                }},
                "order": [[1, "desc"], [3, "asc"]]
            }});
        }});
    </script>
</body>
</html>
        """
        
        # Guardar el reporte en un archivo
        os.makedirs("reports", exist_ok=True)
        filename = f"aws_password_policy_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join("reports", filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        print(colored(f"[+] Reporte HTML generado correctamente: {filepath}", 'green'))
        print(colored("[+] Abra el archivo en su navegador para ver el reporte interactivo", 'yellow'))