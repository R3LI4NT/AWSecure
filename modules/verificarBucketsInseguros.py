import boto3
from termcolor import colored
from botocore.exceptions import ClientError
from tabulate import tabulate
from datetime import datetime
import os

class BucketSecurityChecker:
    def __init__(self, session):
        self.sesion = session
        self.s3 = self.sesion.client('s3')
        self.buckets_data = []
        self.insecure_buckets = []
        
    def verificar_buckets_inseguros(self):
        print(colored("\n[*] Buscando buckets S3 con configuraciones inseguras...", 'blue'))
        
        try:
            buckets = self.s3.list_buckets()['Buckets']
            
            if not buckets:
                print(colored("[!] No se encontraron buckets S3 en esta cuenta", 'yellow'))
                return
            
            print(colored(f"[+] Encontrados [{len(buckets)}] buckets S3", 'green'))
            print(colored("[+] Analizando configuración de seguridad de cada bucket...", 'cyan'))
            
            for bucket in buckets:
                nombre_bucket = bucket['Name']
                bucket_info = {
                    'name': nombre_bucket,
                    'creation_date': bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S'),
                    'http_enabled': False,
                    'public_access': False,
                    'encryption': False,
                    'versioning': False,
                    'logging': False,
                    'policy_errors': []
                }
                
                try:
                    # Verificar si HTTP está habilitado
                    try:
                        policy = self.s3.get_bucket_policy(Bucket=nombre_bucket)['Policy']
                        if '"aws:SecureTransport":"false"' in policy:
                            bucket_info['http_enabled'] = True
                            self.insecure_buckets.append(bucket_info)
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                            bucket_info['policy_errors'].append(f"Error política: {str(e)}")
                    
                    # Verificar acceso público
                    try:
                        public_access = self.s3.get_public_access_block(Bucket=nombre_bucket)
                        block_all = public_access['PublicAccessBlockConfiguration']
                        bucket_info['public_access'] = not (
                            block_all['BlockPublicAcls'] and 
                            block_all['IgnorePublicAcls'] and 
                            block_all['BlockPublicPolicy'] and 
                            block_all['RestrictPublicBuckets']
                        )
                        if bucket_info['public_access']:
                            self.insecure_buckets.append(bucket_info)
                    except ClientError as e:
                        bucket_info['policy_errors'].append(f"Error acceso público: {str(e)}")
                    
                    # Verificar encriptación
                    try:
                        encryption = self.s3.get_bucket_encryption(Bucket=nombre_bucket)
                        bucket_info['encryption'] = True
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                            bucket_info['encryption'] = False
                            self.insecure_buckets.append(bucket_info)
                        else:
                            bucket_info['policy_errors'].append(f"Error encriptación: {str(e)}")
                    
                    # Verificar versionado
                    try:
                        versioning = self.s3.get_bucket_versioning(Bucket=nombre_bucket)
                        bucket_info['versioning'] = versioning.get('Status', '').lower() == 'enabled'
                    except ClientError as e:
                        bucket_info['policy_errors'].append(f"Error versionado: {str(e)}")
                    
                    # Verificar logging
                    try:
                        logging = self.s3.get_bucket_logging(Bucket=nombre_bucket)
                        bucket_info['logging'] = 'LoggingEnabled' in logging
                    except ClientError as e:
                        bucket_info['policy_errors'].append(f"Error logging: {str(e)}")
                    
                except ClientError as e:
                    print(colored(f"  [-] Error al analizar bucket {nombre_bucket}: {str(e)}", 'red'))
                
                self.buckets_data.append(bucket_info)
            
            # Mostrar resumen inicial
            self.mostrar_resumen_inicial()
            
            # Generar reporte detallado
            self.generar_reporte_buckets()
            
            # Preguntar si generar reporte HTML
            self.preguntar_generar_reporte()
            
        except ClientError as e:
            print(colored(f"[-] Error al verificar buckets S3: {str(e)}", 'red'))
    
    def mostrar_resumen_inicial(self):
        total_buckets = len(self.buckets_data)
        http_enabled = sum(1 for b in self.buckets_data if b['http_enabled'])
        public_access = sum(1 for b in self.buckets_data if b['public_access'])
        no_encryption = sum(1 for b in self.buckets_data if not b['encryption'])
        no_versioning = sum(1 for b in self.buckets_data if not b['versioning'])
        no_logging = sum(1 for b in self.buckets_data if not b['logging'])
        
        print(colored("\n" + "="*80, 'blue'))
        print(colored("RESUMEN DE SEGURIDAD DE BUCKETS S3", 'blue', attrs=['bold']))
        print(colored("="*80, 'blue'))
        
        print(colored("\n[+] Estadísticas generales:", 'yellow'))
        print(colored(f"• Total de buckets: {total_buckets}", 'cyan'))
        print(colored(f"• Buckets con HTTP habilitado: {http_enabled}/{total_buckets} "
              f"({http_enabled/total_buckets*100:.1f}%)", 
              'green' if http_enabled == 0 else 'red'))
        print(colored(f"• Buckets con posible acceso público: {public_access}/{total_buckets} "
              f"({public_access/total_buckets*100:.1f}%)", 
              'green' if public_access == 0 else 'red'))
        print(colored(f"• Buckets sin encriptación: {no_encryption}/{total_buckets}", 
              'green' if no_encryption == 0 else 'red'))
        print(colored(f"• Buckets sin versionado: {no_versioning}/{total_buckets}", 
              'green' if no_versioning == 0 else 'yellow'))
        print(colored(f"• Buckets sin logging: {no_logging}/{total_buckets}", 
              'green' if no_logging == 0 else 'yellow'))
        
        if self.insecure_buckets:
            print(colored("\n[!] Buckets con problemas de seguridad:", 'red'))
            for bucket in self.insecure_buckets[:10]:  # Mostrar solo los primeros 10 para no saturar
                issues = []
                if bucket['http_enabled']:
                    issues.append("HTTP habilitado")
                if bucket['public_access']:
                    issues.append("Acceso público")
                if not bucket['encryption']:
                    issues.append("Sin encriptación")
                
                print(colored(f"  - {bucket['name']} ({', '.join(issues)})", 'yellow'))
    
    def generar_reporte_buckets(self):
        # Preparar datos para la tabla
        table_data = []
        headers = [
            "Nombre del Bucket",
            "Fecha Creación",
            "HTTP Habilitado",
            "Acceso Público",
            "Encriptación",
            "Versionado",
            "Logging",
            "Errores"
        ]
        
        for bucket in self.buckets_data:
            table_data.append([
                bucket['name'],
                bucket['creation_date'],
                colored("SÍ", 'red') if bucket['http_enabled'] else colored("NO", 'green'),
                colored("SÍ", 'red') if bucket['public_access'] else colored("NO", 'green'),
                colored("NO", 'red') if not bucket['encryption'] else colored("SÍ", 'green'),
                colored("NO", 'yellow') if not bucket['versioning'] else colored("SÍ", 'green'),
                colored("NO", 'yellow') if not bucket['logging'] else colored("SÍ", 'green'),
                ", ".join(bucket['policy_errors']) if bucket['policy_errors'] else "Ninguno"
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
        
        if any(b['http_enabled'] for b in self.buckets_data):
            print(colored("1. Deshabilitar HTTP en todos los buckets:", 'yellow'))
            print(colored("   El tráfico HTTP no es seguro y puede exponer datos sensibles", 'yellow'))
            print(colored("   Actualice la política del bucket para requerir HTTPS:", 'green'))
            print(colored('''   {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": ["arn:aws:s3:::NOMBRE_BUCKET", "arn:aws:s3:::NOMBRE_BUCKET/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
                }]
            }''', 'green'))
        
        if any(b['public_access'] for b in self.buckets_data):
            print(colored("\n2. Restringir acceso público a los buckets:", 'yellow'))
            print(colored("   Los buckets públicos pueden exponer datos sensibles", 'yellow'))
            print(colored("   Habilite el bloqueo de acceso público:", 'green'))
            print(colored("   aws s3api put-public-access-block --bucket NOMBRE_BUCKET \\", 'green'))
            print(colored("   --public-access-block-configuration \\", 'green'))
            print(colored('''   '{
                "BlockPublicAcls": true,
                "IgnorePublicAcls": true,
                "BlockPublicPolicy": true,
                "RestrictPublicBuckets": true
            }' ''', 'green'))
        
        if any(not b['encryption'] for b in self.buckets_data):
            print(colored("\n3. Habilitar encriptación en todos los buckets:", 'yellow'))
            print(colored("   La encriptación protege los datos en caso de acceso no autorizado", 'yellow'))
            print(colored("   Habilite la encriptación SSE-S3 (simplificada):", 'green'))
            print(colored("   aws s3api put-bucket-encryption --bucket NOMBRE_BUCKET \\", 'green'))
            print(colored('''   --server-side-encryption-configuration '{
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }' ''', 'green'))
        
        if any(not b['versioning'] for b in self.buckets_data):
            print(colored("\n4. Habilitar versionado en buckets importantes:", 'yellow'))
            print(colored("   El versionado permite recuperar versiones anteriores de objetos", 'yellow'))
            print(colored("   Habilite el versionado:", 'green'))
            print(colored("   aws s3api put-bucket-versioning --bucket NOMBRE_BUCKET \\", 'green'))
            print(colored('''   --versioning-configuration '{
                "Status": "Enabled"
            }' ''', 'green'))
        
        if any(not b['logging'] for b in self.buckets_data):
            print(colored("\n5. Habilitar logging de acceso:", 'yellow'))
            print(colored("   El logging permite auditar quién accede a los datos", 'yellow'))
            print(colored("   Habilite el logging:", 'green'))
            print(colored("   aws s3api put-bucket-logging --bucket NOMBRE_BUCKET \\", 'green'))
            print(colored('''   --bucket-logging-status '{
                "LoggingEnabled": {
                    "TargetBucket": "BUCKET_LOGS",
                    "TargetPrefix": "logs/NOMBRE_BUCKET/"
                }
            }' ''', 'green'))
    
    def preguntar_generar_reporte(self):
        respuesta = input(colored("\n[?] ¿Desea generar un reporte HTML interactivo de estos resultados? (s/n): ", 'yellow'))
        if respuesta.lower() == 's':
            self.generarHTMLReport()
    
    def generarHTMLReport(self):
        print(colored("\n[*] Generando reporte HTML interactivo...", 'blue'))
        
        if not self.buckets_data:
            print(colored("[!] No hay datos para generar el reporte", 'yellow'))
            return
        
        # Estadísticas para el reporte
        total_buckets = len(self.buckets_data)
        http_enabled = sum(1 for b in self.buckets_data if b['http_enabled'])
        public_access = sum(1 for b in self.buckets_data if b['public_access'])
        no_encryption = sum(1 for b in self.buckets_data if not b['encryption'])
        no_versioning = sum(1 for b in self.buckets_data if not b['versioning'])
        no_logging = sum(1 for b in self.buckets_data if not b['logging'])
        
        # Preparar datos para la tabla
        table_rows = ""
        for bucket in self.buckets_data:
            table_rows += f"""
            <tr>
                <td>{bucket['name']}</td>
                <td>{bucket['creation_date']}</td>
                <td class="{ 'text-danger' if bucket['http_enabled'] else 'text-success' }">
                    {'SÍ' if bucket['http_enabled'] else 'NO'}
                </td>
                <td class="{ 'text-danger' if bucket['public_access'] else 'text-success' }">
                    {'SÍ' if bucket['public_access'] else 'NO'}
                </td>
                <td class="{ 'text-danger' if not bucket['encryption'] else 'text-success' }">
                    {'NO' if not bucket['encryption'] else 'SÍ'}
                </td>
                <td class="{ 'text-warning' if not bucket['versioning'] else 'text-success' }">
                    {'NO' if not bucket['versioning'] else 'SÍ'}
                </td>
                <td class="{ 'text-warning' if not bucket['logging'] else 'text-success' }">
                    {'NO' if not bucket['logging'] else 'SÍ'}
                </td>
                <td>{', '.join(bucket['policy_errors']) if bucket['policy_errors'] else 'Ninguno'}</td>
            </tr>
            """
        
        # Preparar lista de buckets problemáticos
        insecure_buckets_list = ""
        for bucket in sorted(self.insecure_buckets, key=lambda x: x['name'])[:10]:
            issues = []
            if bucket['http_enabled']:
                issues.append("HTTP habilitado")
            if bucket['public_access']:
                issues.append("Acceso público")
            if not bucket['encryption']:
                issues.append("Sin encriptación")
            if not bucket['versioning']:
                issues.append("Sin versionado")
            if not bucket['logging']:
                issues.append("Sin logging")
            
            insecure_buckets_list += f"""
            <li class="list-group-item d-flex justify-content-between align-items-center">
                {bucket['name']}
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
    <title>Reporte de Seguridad AWS - Buckets S3</title>
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
            <h2>Configuración de Buckets S3</h2>
            <p class="mb-0">Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="row">
            <div class="col-md-2">
                <div class="summary-card { 'card-positive' if http_enabled == 0 else 'card-negative' }">
                    <h5>HTTP Habilitado</h5>
                    <h3>{http_enabled}/{total_buckets}</h3>
                    <p class="mb-0">{http_enabled/total_buckets*100:.1f}%</p>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card { 'card-positive' if public_access == 0 else 'card-negative' }">
                    <h5>Acceso Público</h5>
                    <h3>{public_access}/{total_buckets}</h3>
                    <p class="mb-0">{public_access/total_buckets*100:.1f}%</p>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card { 'card-positive' if no_encryption == 0 else 'card-negative' }">
                    <h5>Sin Encriptación</h5>
                    <h3>{no_encryption}/{total_buckets}</h3>
                    <p class="mb-0">{no_encryption/total_buckets*100:.1f}%</p>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card { 'card-positive' if no_versioning == 0 else 'card-warning' }">
                    <h5>Sin Versionado</h5>
                    <h3>{no_versioning}/{total_buckets}</h3>
                    <p class="mb-0">{no_versioning/total_buckets*100:.1f}%</p>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card { 'card-positive' if no_logging == 0 else 'card-warning' }">
                    <h5>Sin Logging</h5>
                    <h3>{no_logging}/{total_buckets}</h3>
                    <p class="mb-0">{no_logging/total_buckets*100:.1f}%</p>
                </div>
            </div>
            <div class="col-md-2">
                <div class="summary-card card-neutral">
                    <h5>Total Buckets</h5>
                    <h3>{total_buckets}</h3>
                    <p class="mb-0">100%</p>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="risk-description">
                    <h4><i class="bi bi-exclamation-triangle-fill"></i> Riesgos de Seguridad</h4>
                    <ul>
                        <li>HTTP habilitado permite tráfico no cifrado que puede ser interceptado</li>
                        <li>Acceso público puede exponer datos sensibles a internet</li>
                        <li>Falta de encriptación hace que los datos sean vulnerables si son accedidos</li>
                        <li>Sin versionado no se pueden recuperar versiones anteriores de objetos</li>
                        <li>Sin logging no se puede auditar quién accede a los datos</li>
                    </ul>
                </div>
            </div>
            <div class="col-md-6">
                <div class="recommendations">
                    <h4><i class="bi bi-check-circle-fill"></i> Recomendaciones</h4>
                    <ul class="list-group">
                        <li class="list-group-item">Forzar HTTPS en todos los buckets</li>
                        <li class="list-group-item">Bloquear acceso público no intencional</li>
                        <li class="list-group-item">Habilitar encriptación SSE-S3 o SSE-KMS</li>
                        <li class="list-group-item">Activar versionado en buckets importantes</li>
                        <li class="list-group-item">Configurar logging de acceso</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <i class="bi bi-shield-exclamation"></i> Buckets con Problemas de Seguridad ({len(self.insecure_buckets)})
                    </div>
                    <div class="card-body">
                        <ul class="list-group">
                            {insecure_buckets_list}
                            {f'<li class="list-group-item text-center">... y {len(self.insecure_buckets)-10} más</li>' if len(self.insecure_buckets) > 10 else ''}
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="table-responsive mt-4">
            <table id="bucketsTable" class="table table-striped table-bordered" style="width:100%">
                <thead class="table-dark">
                    <tr>
                        <th>Nombre del Bucket</th>
                        <th>Fecha Creación</th>
                        <th>HTTP Habilitado</th>
                        <th>Acceso Público</th>
                        <th>Encriptación</th>
                        <th>Versionado</th>
                        <th>Logging</th>
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
                    <h5 class="card-title">Forzar HTTPS en un bucket</h5>
                    <code>aws s3api put-bucket-policy --bucket NOMBRE_BUCKET --policy '{{<br>
    "Version": "2012-10-17",<br>
    "Statement": [{{<br>
        "Effect": "Deny",<br>
        "Principal": "*",<br>
        "Action": "s3:*",<br>
        "Resource": ["arn:aws:s3:::NOMBRE_BUCKET", "arn:aws:s3:::NOMBRE_BUCKET/*"],<br>
        "Condition": {{"Bool": {{"aws:SecureTransport": "false"}}}}<br>
    }}]<br>
}}'</code>
                    
                    <h5 class="card-title mt-3">Bloquear acceso público</h5>
                    <code>aws s3api put-public-access-block --bucket NOMBRE_BUCKET \<br>
--public-access-block-configuration \<br>
'{{<br>
    "BlockPublicAcls": true,<br>
    "IgnorePublicAcls": true,<br>
    "BlockPublicPolicy": true,<br>
    "RestrictPublicBuckets": true<br>
}}'</code>
                    
                    <h5 class="card-title mt-3">Habilitar encriptación</h5>
                    <code>aws s3api put-bucket-encryption --bucket NOMBRE_BUCKET \<br>
--server-side-encryption-configuration '{{<br>
    "Rules": [{{<br>
        "ApplyServerSideEncryptionByDefault": {{<br>
            "SSEAlgorithm": "AES256"<br>
        }}<br>
    }}]<br>
}}'</code>
                    
                    <h5 class="card-title mt-3">Activar versionado</h5>
                    <code>aws s3api put-bucket-versioning --bucket NOMBRE_BUCKET \<br>
--versioning-configuration '{{<br>
    "Status": "Enabled"<br>
}}'</code>
                    
                    <h5 class="card-title mt-3">Configurar logging</h5>
                    <code>aws s3api put-bucket-logging --bucket NOMBRE_BUCKET \<br>
--bucket-logging-status '{{<br>
    "LoggingEnabled": {{<br>
        "TargetBucket": "BUCKET_LOGS",<br>
        "TargetPrefix": "logs/NOMBRE_BUCKET/"<br>
    }}<br>
}}'</code>
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
            $('#bucketsTable').DataTable({{
                "language": {{
                    "url": "//cdn.datatables.net/plug-ins/1.11.5/i18n/Spanish.json"
                }},
                "order": [[2, "desc"], [3, "desc"]],
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
        filename = f"aws_insecure_buckets_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join("reports", filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        print(colored(f"[+] Reporte HTML generado correctamente: {filepath}", 'green'))
        print(colored("[+] Abra el archivo en su navegador para ver el reporte interactivo", 'yellow'))