import boto3
from termcolor import colored
from botocore.exceptions import ClientError
from tabulate import tabulate
from datetime import datetime
import os

class CloudTrailLogsChecker:
    def __init__(self, session):
        self.sesion = session
        self.cloudtrail = self.sesion.client('cloudtrail')
        self.trails_data = []
        self.problematic_trails = []
        
    def validacion_logs(self):
        print(colored("\n[*] Validando configuración de CloudTrail...", 'blue'))
        
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            
            if not trails:
                print(colored("[!] No se encontraron trails de CloudTrail configurados", 'red'))
                return
            
            print(colored(f"[+] Encontrados {len(trails)} trails de CloudTrail", 'green'))
            print(colored("[+] Analizando configuración de cada trail...", 'cyan'))
            
            # Procesar cada trail
            for trail in trails:
                trail_name = trail['Name']
                region = trail.get('HomeRegion', 'N/A')
                
                # Obtener estado del trail
                trail_status = self.cloudtrail.get_trail_status(Name=trail_name)
                
                # Verificar validación de logs
                log_validation = trail.get('LogFileValidationEnabled', False)
                
                # Verificar si es multi-región
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                
                # Verificar integración con CloudWatch
                cw_logs = trail.get('CloudWatchLogsLogGroupArn', 'No configurado')
                
                # Verificar S3 bucket
                s3_bucket = trail.get('S3BucketName', 'N/A')
                
                # Almacenar datos
                trail_info = {
                    'name': trail_name,
                    'region': region,
                    'log_validation': log_validation,
                    'is_multi_region': is_multi_region,
                    's3_bucket': s3_bucket,
                    'is_logging': trail_status.get('IsLogging', False),
                    'cloudwatch_logs': cw_logs != 'No configurado',
                    'latest_delivery_error': trail_status.get('LatestDeliveryError', 'N/A'),
                    'latest_notification_error': trail_status.get('LatestNotificationError', 'N/A')
                }
                
                self.trails_data.append(trail_info)
                
                # Identificar trails problemáticos
                if not log_validation or not is_multi_region or not trail_info['is_logging']:
                    self.problematic_trails.append(trail_info)
            
            # Mostrar resumen inicial
            self.mostrar_resumen_inicial()
            
            # Generar reporte detallado
            self.generar_reporte_logs()
            
            # Preguntar si generar reporte HTML
            self.preguntar_generar_reporte()
            
        except ClientError as e:
            print(colored(f"[-] Error al verificar CloudTrail: {str(e)}", 'red'))
    
    def mostrar_resumen_inicial(self):
        total_trails = len(self.trails_data)
        trails_with_validation = sum(1 for t in self.trails_data if t['log_validation'])
        trails_multi_region = sum(1 for t in self.trails_data if t['is_multi_region'])
        trails_active = sum(1 for t in self.trails_data if t['is_logging'])
        trails_with_cw = sum(1 for t in self.trails_data if t['cloudwatch_logs'])
        
        print(colored("\n" + "="*80, 'blue'))
        print(colored("RESUMEN DE CONFIGURACIÓN DE CLOUDTRAIL", 'blue', attrs=['bold']))
        print(colored("="*80, 'blue'))
        
        print(colored("\n[+] Estadísticas generales:", 'yellow'))
        print(colored(f"• Total de trails: {total_trails}", 'cyan'))
        print(colored(f"• Trails con validación de logs: {trails_with_validation}/{total_trails} "
              f"({trails_with_validation/total_trails*100:.1f}%)", 
              'green' if trails_with_validation == total_trails else 'red'))
        print(colored(f"• Trails multi-región: {trails_multi_region}/{total_trails} "
              f"({trails_multi_region/total_trails*100:.1f}%)", 
              'green' if trails_multi_region == total_trails else 'yellow'))
        print(colored(f"• Trails activos: {trails_active}/{total_trails}", 
              'green' if trails_active == total_trails else 'red'))
        print(colored(f"• Trails con CloudWatch Logs: {trails_with_cw}/{total_trails}", 
              'green' if trails_with_cw == total_trails else 'yellow'))
        
        if self.problematic_trails:
            print(colored("\n[!] Trails con problemas de configuración:", 'red'))
            for trail in self.problematic_trails:
                issues = []
                if not trail['log_validation']:
                    issues.append("validación de logs deshabilitada")
                if not trail['is_multi_region']:
                    issues.append("no es multi-región")
                if not trail['is_logging']:
                    issues.append("registro inactivo")
                
                print(colored(f"  - {trail['name']} ({', '.join(issues)})", 'yellow'))
    
    def generar_reporte_logs(self):
        # Preparar datos para la tabla
        table_data = []
        headers = [
            "Nombre del Trail",
            "Región",
            "Validación Logs",
            "Multi-Región",
            "Bucket S3",
            "Estado",
            "CloudWatch Logs",
            "Errores"
        ]
        
        for trail in self.trails_data:
            errors = []
            if trail['latest_delivery_error'] != 'N/A':
                errors.append("delivery")
            if trail['latest_notification_error'] != 'N/A':
                errors.append("notification")
            
            table_data.append([
                trail['name'],
                trail['region'],
                colored("HABILITADA", 'green') if trail['log_validation'] else colored("DESHABILITADA", 'red'),
                colored("SÍ", 'green') if trail['is_multi_region'] else colored("NO", 'yellow'),
                trail['s3_bucket'],
                colored("ACTIVO", 'green') if trail['is_logging'] else colored("INACTIVO", 'red'),
                colored("SÍ", 'green') if trail['cloudwatch_logs'] else colored("NO", 'yellow'),
                ", ".join(errors) if errors else "Ninguno"
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
        self.mostrar_recomendaciones()
    
    def mostrar_recomendaciones(self):
        print(colored("\n[!] RECOMENDACIONES DE SEGURIDAD:", 'red', attrs=['bold']))
        
        if any(not trail['log_validation'] for trail in self.trails_data):
            print(colored("1. Habilitar validación de archivos de log en todos los trails:", 'yellow'))
            print(colored("   La validación de logs permite detectar si los archivos han sido modificados", 'yellow'))
            print(colored("   Comando para habilitar:", 'green'))
            print(colored("   aws cloudtrail update-trail --name NOMBRE_TRAIL --enable-log-file-validation", 'green'))
        
        if any(not trail['is_multi_region'] for trail in self.trails_data):
            print(colored("\n2. Configurar trails multi-región para cobertura completa:", 'yellow'))
            print(colored("   Los trails multi-región capturan eventos en todas las regiones AWS", 'yellow'))
            print(colored("   Comando para habilitar:", 'green'))
            print(colored("   aws cloudtrail update-trail --name NOMBRE_TRAIL --is-multi-region-trail", 'green'))
        
        if any(not trail['is_logging'] for trail in self.trails_data):
            print(colored("\n3. Activar trails que están actualmente inactivos:", 'yellow'))
            print(colored("   Un trail inactivo no registra ningún evento", 'yellow'))
            print(colored("   Comando para activar:", 'green'))
            print(colored("   aws cloudtrail start-logging --name NOMBRE_TRAIL", 'green'))
        
        if any(not trail['cloudwatch_logs'] for trail in self.trails_data):
            print(colored("\n4. Habilitar integración con CloudWatch Logs:", 'yellow'))
            print(colored("   CloudWatch Logs permite alertas en tiempo real y mayor retención", 'yellow'))
            print(colored("   Comando para configurar:", 'green'))
            print(colored("   aws cloudtrail update-trail --name NOMBRE_TRAIL \\", 'green'))
            print(colored("   --cloud-watch-logs-log-group-arn ARN_GRUPO_LOG \\", 'green'))
            print(colored("   --cloud-watch-logs-role-arn ARN_ROL", 'green'))
        
        print(colored("\n5. Configurar alertas para errores de entrega:", 'yellow'))
        print(colored("   Monitorear errores en la entrega de logs a S3 o CloudWatch", 'yellow'))
        print(colored("   Puede usar CloudWatch Alarms o Amazon EventBridge", 'green'))
    
    def preguntar_generar_reporte(self):
        respuesta = input(colored("\n[?] ¿Desea generar un reporte HTML interactivo de estos resultados? (s/n): ", 'yellow'))
        if respuesta.lower() == 's':
            self.generarHTMLReport()
    
    def generarHTMLReport(self):
        print(colored("\n[*] Generando reporte HTML interactivo...", 'blue'))
        
        if not self.trails_data:
            print(colored("[!] No hay datos para generar el reporte", 'yellow'))
            return
        
        # Estadísticas para el reporte
        total_trails = len(self.trails_data)
        trails_with_validation = sum(1 for t in self.trails_data if t['log_validation'])
        trails_multi_region = sum(1 for t in self.trails_data if t['is_multi_region'])
        trails_active = sum(1 for t in self.trails_data if t['is_logging'])
        trails_with_cw = sum(1 for t in self.trails_data if t['cloudwatch_logs'])
        
        # Preparar datos para la tabla
        table_rows = ""
        for trail in self.trails_data:
            errors = []
            if trail['latest_delivery_error'] != 'N/A':
                errors.append("delivery")
            if trail['latest_notification_error'] != 'N/A':
                errors.append("notification")
            
            table_rows += f"""
            <tr>
                <td>{trail['name']}</td>
                <td>{trail['region']}</td>
                <td class="{ 'text-success' if trail['log_validation'] else 'text-danger' }">
                    {'SÍ' if trail['log_validation'] else 'NO'}
                </td>
                <td class="{ 'text-success' if trail['is_multi_region'] else 'text-warning' }">
                    {'SÍ' if trail['is_multi_region'] else 'NO'}
                </td>
                <td>{trail['s3_bucket']}</td>
                <td class="{ 'text-success' if trail['is_logging'] else 'text-danger' }">
                    {'ACTIVO' if trail['is_logging'] else 'INACTIVO'}
                </td>
                <td class="{ 'text-success' if trail['cloudwatch_logs'] else 'text-warning' }">
                    {'SÍ' if trail['cloudwatch_logs'] else 'NO'}
                </td>
                <td>{', '.join(errors) if errors else 'Ninguno'}</td>
            </tr>
            """
        
        # Preparar lista de trails problemáticos
        problematic_trails_list = ""
        for trail in sorted(self.problematic_trails, key=lambda x: x['name'])[:10]:
            issues = []
            if not trail['log_validation']:
                issues.append("Validación logs")
            if not trail['is_multi_region']:
                issues.append("No multi-región")
            if not trail['is_logging']:
                issues.append("Inactivo")
            if not trail['cloudwatch_logs']:
                issues.append("Sin CloudWatch")
            
            problematic_trails_list += f"""
            <li class="list-group-item d-flex justify-content-between align-items-center">
                {trail['name']} ({trail['region']})
                <div>
                    {''.join([f'<span class="badge bg-danger rounded-pill me-1">{issue}</span>' for issue in issues])}
                </div>
            </li>
            """
        
        # Plantilla HTML
        html_template = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad AWS - Validación de Logs CloudTrail</title>
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
        .validation-badge {{
            background-color: #dc3545;
        }}
        .region-badge {{
            background-color: #fd7e14;
        }}
        .commands-card {{
            background-color: #e2e3e5;
            border-left: 5px solid #6c757d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header text-center">
            <h1>Reporte de Seguridad AWS</h1>
            <h2>Validación de Logs CloudTrail</h2>
            <p class="mb-0">Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="row">
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if trails_with_validation == total_trails else 'card-negative' }">
                    <h5>Validación de Logs</h5>
                    <h3>{trails_with_validation}/{total_trails}</h3>
                    <p class="mb-0">{trails_with_validation/total_trails*100:.1f}% de cobertura</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if trails_multi_region == total_trails else 'card-warning' }">
                    <h5>Multi-Región</h5>
                    <h3>{trails_multi_region}/{total_trails}</h3>
                    <p class="mb-0">{trails_multi_region/total_trails*100:.1f}% de cobertura</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if trails_active == total_trails else 'card-negative' }">
                    <h5>Trails Activos</h5>
                    <h3>{trails_active}/{total_trails}</h3>
                    <p class="mb-0">{trails_active/total_trails*100:.1f}% activos</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if trails_with_cw == total_trails else 'card-warning' }">
                    <h5>CloudWatch Logs</h5>
                    <h3>{trails_with_cw}/{total_trails}</h3>
                    <p class="mb-0">{trails_with_cw/total_trails*100:.1f}% integrados</p>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="risk-description">
                    <h4><i class="bi bi-exclamation-triangle-fill"></i> Riesgos de Seguridad</h4>
                    <ul>
                        <li>Sin validación de logs, no se puede detectar modificaciones en los archivos</li>
                        <li>Trails no multi-región no capturan eventos en todas las regiones</li>
                        <li>Trails inactivos no registran ningún evento de actividad</li>
                        <li>Falta de integración con CloudWatch limita capacidades de monitoreo</li>
                        <li>Errores de entrega pueden indicar problemas en la recolección de logs</li>
                    </ul>
                </div>
            </div>
            <div class="col-md-6">
                <div class="recommendations">
                    <h4><i class="bi bi-check-circle-fill"></i> Recomendaciones</h4>
                    <ul class="list-group">
                        <li class="list-group-item">Habilitar validación de logs en todos los trails</li>
                        <li class="list-group-item">Configurar trails como multi-región</li>
                        <li class="list-group-item">Activar trails inactivos</li>
                        <li class="list-group-item">Integrar con CloudWatch Logs</li>
                        <li class="list-group-item">Monitorear errores de entrega</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <i class="bi bi-shield-exclamation"></i> Trails con Problemas de Configuración ({len(self.problematic_trails)})
                    </div>
                    <div class="card-body">
                        <ul class="list-group">
                            {problematic_trails_list}
                            {f'<li class="list-group-item text-center">... y {len(self.problematic_trails)-10} más</li>' if len(self.problematic_trails) > 10 else ''}
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="table-responsive mt-4">
            <table id="trailsTable" class="table table-striped table-bordered" style="width:100%">
                <thead class="table-dark">
                    <tr>
                        <th>Nombre del Trail</th>
                        <th>Región</th>
                        <th>Validación Logs</th>
                        <th>Multi-Región</th>
                        <th>Bucket S3</th>
                        <th>Estado</th>
                        <th>CloudWatch Logs</th>
                        <th>Errores</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>

        <div class="commands-section mt-4">
            <h4><i class="bi bi-terminal-fill"></i> Comandos útiles</h4>
            <div class="card commands-card">
                <div class="card-body">
                    <h5 class="card-title">Habilitar validación de logs</h5>
                    <code>aws cloudtrail update-trail --name NOMBRE_TRAIL --enable-log-file-validation</code>
                    
                    <h5 class="card-title mt-3">Configurar trail multi-región</h5>
                    <code>aws cloudtrail update-trail --name NOMBRE_TRAIL --is-multi-region-trail</code>
                    
                    <h5 class="card-title mt-3">Activar logging para un trail</h5>
                    <code>aws cloudtrail start-logging --name NOMBRE_TRAIL</code>
                    
                    <h5 class="card-title mt-3">Integrar con CloudWatch Logs</h5>
                    <code>aws cloudtrail update-trail --name NOMBRE_TRAIL \\
    --cloud-watch-logs-log-group-arn ARN_GRUPO_LOG \\
    --cloud-watch-logs-role-arn ARN_ROL</code>
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
            $('#trailsTable').DataTable({{
                "language": {{
                    "url": "//cdn.datatables.net/plug-ins/1.11.5/i18n/Spanish.json"
                }},
                "order": [[2, "asc"], [3, "desc"]],
                "columnDefs": [
                    {{ "orderable": false, "targets": [7] }}
                ]
            }});
        }});
    </script>
</body>
</html>
        """
        
        # Guardar el reporte en un archivo
        os.makedirs("reports", exist_ok=True)
        filename = f"aws_cloudtrail_logs_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join("reports", filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        print(colored(f"[+] Reporte HTML generado correctamente: {filepath}", 'green'))
        print(colored("[+] Abra el archivo en su navegador para ver el reporte interactivo", 'yellow'))