from datetime import datetime  # Importación faltante
import os
from termcolor import colored
from tabulate import tabulate
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError

class MFAChecker:
    def __init__(self, session):
        self.sesion = session
        self.mfa_results = []

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
                estado_mfa_raw = "HABILITADO" if dispositivos_mfa else "NO HABILITADO"
                
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
                
                # Guardar datos para posible reporte HTML
                self.mfa_results.append({
                    "usuario": nombre_usuario,
                    "mfa_activo": estado_mfa_raw,
                    "ultimo_acceso": ultimo_acceso,
                    "acceso_clave": acceso_clave,
                    "dispositivos_mfa": dispositivos_mfa
                })
                
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
            
            # Preguntar si generar reporte HTML
            self.preguntar_generar_reporte()
            
        except ClientError as e:
            print(colored(f"[-] Error al obtener usuarios IAM: {str(e)}", 'red'))

    def preguntar_generar_reporte(self):
        respuesta = input(colored("\n[?] ¿Desea generar un reporte HTML interactivo de estos resultados? (s/n): ", 'yellow'))
        if respuesta.lower() == 's':
            self.generar_reporte_html()

    def generar_reporte_html(self):
        print(colored("\n[*] Generando reporte HTML interactivo...", 'blue'))
        
        # Estadísticas para el reporte
        total_usuarios = len(self.mfa_results)
        usuarios_con_mfa = sum(1 for u in self.mfa_results if u['mfa_activo'] == "HABILITADO")
        usuarios_sin_mfa = total_usuarios - usuarios_con_mfa
        porcentaje_mfa = (usuarios_con_mfa / total_usuarios * 100) if total_usuarios > 0 else 0
        
        # Generar filas de la tabla
        filas_tabla = ""
        for usuario in self.mfa_results:
            color_fila = "success" if usuario['mfa_activo'] == "HABILITADO" else "danger"
            filas_tabla += f"""
            <tr class="{color_fila}">
                <td>{usuario['usuario']}</td>
                <td>{usuario['mfa_activo']}</td>
                <td>{usuario['ultimo_acceso']}</td>
                <td>{usuario['acceso_clave']}</td>
            </tr>
            """
        
        # Plantilla HTML completa
        html_template = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad AWS - Estado MFA</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
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
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header text-center">
            <h1>Reporte de Seguridad AWS</h1>
            <h2>Estado de Autenticación Multifactor (MFA)</h2>
            <p class="mb-0">Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="summary-card card-positive">
                    <h5>Usuarios con MFA habilitado</h5>
                    <h3>{usuarios_con_mfa} / {total_usuarios}</h3>
                </div>
            </div>
            <div class="col-md-6">
                <div class="summary-card card-negative">
                    <h5>Usuarios sin MFA</h5>
                    <h3>{usuarios_sin_mfa} / {total_usuarios}</h3>
                </div>
            </div>
        </div>

        <div class="risk-description">
            <h4><i class="bi bi-exclamation-triangle-fill"></i> Riesgo de Seguridad</h4>
            <p>La autenticación multifactor (MFA) agrega una capa adicional de protección además del nombre de usuario y la contraseña. 
            Los usuarios sin MFA habilitado están en mayor riesgo de compromiso si sus credenciales son filtradas o robadas.</p>
        </div>

        <div class="recommendations">
            <h4><i class="bi bi-check-circle-fill"></i> Recomendaciones</h4>
            <ul>
                <li>Habilitar MFA para todos los usuarios IAM, especialmente aquellos con privilegios.</li>
                <li>Implementar políticas que requieran MFA para operaciones sensibles.</li>
                <li>Considerar el uso de dispositivos MFA físicos para usuarios con acceso a recursos críticos.</li>
                <li>Revisar y rotar regularmente las claves de acceso.</li>
            </ul>
        </div>

        <div class="table-responsive">
            <table id="resultsTable" class="table table-striped table-bordered" style="width:100%">
                <thead class="table-dark">
                    <tr>
                        <th>Usuario</th>
                        <th>MFA Activo</th>
                        <th>Último Acceso</th>
                        <th>Acceso Clave</th>
                    </tr>
                </thead>
                <tbody>
                    {filas_tabla}
                </tbody>
            </table>
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
            $('#resultsTable').DataTable({{
                "language": {{
                    "url": "//cdn.datatables.net/plug-ins/1.11.5/i18n/Spanish.json"
                }},
                "order": [[1, "asc"]]
            }});
        }});
    </script>
</body>
</html>
            """
        
        # Guardar el reporte en un archivo
        os.makedirs("reports", exist_ok=True)

        nombre_archivo = f"aws_mfa_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        ruta_archivo = os.path.join("reports", nombre_archivo)

        with open(ruta_archivo, 'w') as f:
            f.write(html_template)

        print(colored(f"[+] Reporte HTML generado correctamente: {ruta_archivo}", 'green'))
        print(colored("[+] Abra el archivo en su navegador para ver el reporte interactivo", 'yellow'))
