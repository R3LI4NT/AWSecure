import boto3
from termcolor import colored
from botocore.exceptions import ClientError
from tabulate import tabulate
from datetime import datetime
import os
import json

class RolePolicyChecker:
    def __init__(self, session):
        self.sesion = session
        self.iam = self.sesion.client('iam')
        self.risky_policies = []
        self.all_policies = []
        
    def verificar_politicas_riesgosas(self):
        print(colored("\n[*] Buscando políticas IAM permisivas...", 'blue'))
        
        try:
            # Obtener todas las políticas
            politicas = []
            for ambito in ['AWS', 'Local']:
                paginador = self.iam.get_paginator('list_policies')
                for pagina in paginador.paginate(Scope=ambito):
                    politicas.extend(pagina['Policies'])
            
            if not politicas:
                print(colored("[!] No se encontraron políticas IAM en esta cuenta", 'yellow'))
                return
            
            print(colored(f"[+] Encontradas [{len(politicas)}] políticas IAM", 'green'))
            print(colored("[+] Analizando permisos de cada política...", 'cyan'))
            
            # Procesar cada política
            for politica in politicas:
                policy_info = {
                    'name': politica['PolicyName'],
                    'arn': politica['Arn'],
                    'type': 'AWS Managed' if politica['Arn'].startswith('arn:aws:iam::aws:policy') else 'Custom',
                    'attached_to': [],
                    'risky_permissions': [],
                    'document': None
                }
                
                try:
                    # Obtener versión de la política
                    version_politica = self.iam.get_policy_version(
                        PolicyArn=politica['Arn'],
                        VersionId=politica['DefaultVersionId']
                    )['PolicyVersion']
                    
                    policy_info['document'] = version_politica['Document']
                    
                    # Verificar permisos riesgosos
                    risky_perms = self._analizar_politica(version_politica['Document'])
                    if risky_perms:
                        policy_info['risky_permissions'] = risky_perms
                        self.risky_policies.append(policy_info)
                    
                    # Obtener entidades adjuntas
                    policy_info['attached_to'] = self._obtener_entidades_adjuntas(politica['Arn'])
                    
                except ClientError as e:
                    print(colored(f"  [-] Error al analizar política {politica['PolicyName']}: {str(e)}", 'red'))
                    continue
                
                self.all_policies.append(policy_info)
            
            # Mostrar resumen inicial
            self.mostrar_resumen_inicial()
            
            # Generar reporte detallado
            self.generar_reporte_politicas()
            
            # Preguntar si generar reporte HTML
            self.preguntar_generar_reporte()
            
        except ClientError as e:
            print(colored(f"[-] Error al verificar políticas IAM: {str(e)}", 'red'))
    
    def _analizar_politica(self, documento_politica):
        if isinstance(documento_politica, str):
            try:
                documento_politica = json.loads(documento_politica)
            except json.JSONDecodeError:
                return []
        
        if not isinstance(documento_politica, dict):
            return []
        
        declaraciones = documento_politica.get('Statement', [])
        if isinstance(declaraciones, dict):
            declaraciones = [declaraciones]
        
        risky_perms = []
        
        for declaracion in declaraciones:
            if declaracion.get('Effect') == 'Allow':
                acciones = declaracion.get('Action', [])
                if isinstance(acciones, str):
                    acciones = [acciones]
                
                recursos = declaracion.get('Resource', [])
                if isinstance(recursos, str):
                    recursos = [recursos]
                
                # Detectar permisos riesgosos
                if '*' in recursos:
                    for accion in acciones:
                        if any(perm in accion.lower() for perm in [
                            'passrole', '*', 'iam:*', 'sts:assumerole', 
                            'sts:assumerolewithsaml', 'sts:assumerolewithwebidentity'
                        ]):
                            risky_perms.append({
                                'action': accion,
                                'resource': declaracion.get('Resource'),
                                'condition': declaracion.get('Condition')
                            })
        
        return risky_perms
    
    def _obtener_entidades_adjuntas(self, arn_politica):
        entidades = []
        
        try:
            paginador = self.iam.get_paginator('list_entities_for_policy')
            
            # Obtener usuarios adjuntos
            for pagina in paginador.paginate(PolicyArn=arn_politica, EntityFilter='User'):
                entidades.extend([f"user:{u['UserName']}" for u in pagina.get('PolicyUsers', [])])
            
            # Obtener grupos adjuntos
            for pagina in paginador.paginate(PolicyArn=arn_politica, EntityFilter='Group'):
                entidades.extend([f"group:{g['GroupName']}" for g in pagina.get('PolicyGroups', [])])
            
            # Obtener roles adjuntos
            for pagina in paginador.paginate(PolicyArn=arn_politica, EntityFilter='Role'):
                entidades.extend([f"role:{r['RoleName']}" for r in pagina.get('PolicyRoles', [])])
                
        except ClientError as e:
            print(colored(f"  [-] Error al obtener entidades adjuntas: {str(e)}", 'red'))
        
        return entidades
    
    def mostrar_resumen_inicial(self):
        total_policies = len(self.all_policies)
        risky_policies = len(self.risky_policies)
        attached_risky = sum(1 for p in self.risky_policies if p['attached_to'])
        
        print(colored("\n" + "="*80, 'blue'))
        print(colored("RESUMEN DE POLÍTICAS IAM RIESGOSAS", 'blue', attrs=['bold']))
        print(colored("="*80, 'blue'))
        
        print(colored("\n[+] Estadísticas generales:", 'yellow'))
        print(colored(f"• Total de políticas analizadas: {total_policies}", 'cyan'))
        print(colored(f"• Políticas con permisos riesgosos: {risky_policies}/{total_policies} "
              f"({risky_policies/total_policies*100:.1f}%)", 
              'green' if risky_policies == 0 else 'red'))
        print(colored(f"• Políticas riesgosas adjuntas a entidades: {attached_risky}/{risky_policies}", 
              'green' if attached_risky == 0 else 'red'))
        
        if self.risky_policies:
            print(colored("\n[!] Políticas con permisos riesgosos encontradas:", 'red'))
            for policy in self.risky_policies[:5]:  # Mostrar solo las primeras 5 para no saturar
                print(colored(f"  - {policy['name']} ({policy['type']})", 'yellow'))
                for perm in policy['risky_permissions'][:3]:  # Mostrar solo los primeros 3 permisos
                    print(colored(f"    → Permite: {perm['action']} en {perm['resource']}", 'red'))
                if policy['attached_to']:
                    print(colored(f"    Adjunta a: {', '.join(policy['attached_to'][:3])}" + 
                          ("..." if len(policy['attached_to']) > 3 else ""), 'yellow'))
    
    def generar_reporte_politicas(self):
        # Preparar datos para la tabla
        table_data = []
        headers = [
            "Nombre de Política",
            "Tipo",
            "Permisos Riesgosos",
            "Adjunta a",
            "Entidades"
        ]
        
        for policy in self.risky_policies:
            perms = "\n".join([f"{p['action']} ({p['resource']})" for p in policy['risky_permissions'][:3]])
            if len(policy['risky_permissions']) > 3:
                perms += "\n..."
                
            attached = "\n".join(policy['attached_to'][:3])
            if len(policy['attached_to']) > 3:
                attached += "\n..."
            
            table_data.append([
                policy['name'],
                policy['type'],
                colored(perms, 'red'),
                colored("SÍ", 'red') if policy['attached_to'] else colored("NO", 'green'),
                colored(attached, 'yellow') if policy['attached_to'] else "Ninguna"
            ])
        
        # Mostrar tabla
        print("\n" + colored(tabulate(
            table_data,
            headers=headers,
            tablefmt="grid",
            stralign="left",
        ), 'white'))
        
        # Mostrar recomendaciones
        self.mostrar_recomendaciones()
    
    def mostrar_recomendaciones(self):
        print(colored("\n[!] RECOMENDACIONES DE SEGURIDAD:", 'red', attrs=['bold']))
        
        if self.risky_policies:
            print(colored("1. Restringir políticas con permisos demasiado amplios:", 'yellow'))
            print(colored("   Las políticas que permiten '*' en Resource son especialmente peligrosas", 'yellow'))
            print(colored("   Ejemplo de política segura para iam:PassRole:", 'green'))
            print(colored('''   {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::*:role/specific-role"
                }]
            }''', 'green'))
            
            print(colored("\n2. Revisar y eliminar políticas no necesarias:", 'yellow'))
            print(colored("   Elimine políticas personalizadas que ya no se usen", 'yellow'))
            print(colored("   Comando para eliminar política:", 'green'))
            print(colored("   aws iam delete-policy --policy-arn ARN_POLITICA", 'green'))
            
            print(colored("\n3. Implementar el principio de mínimo privilegio:", 'yellow'))
            print(colored("   Asigne solo los permisos necesarios para cada rol/usuario", 'yellow'))
            
            print(colored("\n4. Usar condiciones en las políticas:", 'yellow'))
            print(colored("   Agregue condiciones para restringir aún más los permisos", 'yellow'))
            print(colored("   Ejemplo con condición:", 'green'))
            print(colored('''   {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::*:role/specific-role",
                    "Condition": {
                        "IpAddress": {"aws:SourceIp": ["192.0.2.0/24"]}
                    }
                }]
            }''', 'green'))
        
        print(colored("\n5. Monitorear cambios en políticas con AWS Config:", 'yellow'))
        print(colored("   Configure AWS Config para alertar sobre cambios en políticas IAM", 'yellow'))
    
    def preguntar_generar_reporte(self):
        respuesta = input(colored("\n[?] ¿Desea generar un reporte HTML interactivo de estos resultados? (s/n): ", 'yellow'))
        if respuesta.lower() == 's':
            self.generarHTMLReport()
    
    def generarHTMLReport(self):
        print(colored("\n[*] Generando reporte HTML interactivo...", 'blue'))
        
        if not self.all_policies:
            print(colored("[!] No hay datos para generar el reporte", 'yellow'))
            return
        
        # Estadísticas para el reporte
        total_policies = len(self.all_policies)
        risky_policies = len(self.risky_policies)
        attached_risky = sum(1 for p in self.risky_policies if p['attached_to'])
        aws_managed_risky = sum(1 for p in self.risky_policies if p['type'] == 'AWS Managed')
        custom_risky = sum(1 for p in self.risky_policies if p['type'] == 'Custom')
        
        # Preparar datos para la tabla
        table_rows = ""
        for policy in self.risky_policies:
            perms = "<ul>" + "".join([f"<li>{p['action']} (<code>{p['resource']}</code>)</li>" 
                                    for p in policy['risky_permissions'][:3]]) + "</ul>"
            if len(policy['risky_permissions']) > 3:
                perms += "<em>y más...</em>"
                
            attached = "<ul>" + "".join([f"<li>{e}</li>" for e in policy['attached_to'][:3]]) + "</ul>"
            if len(policy['attached_to']) > 3:
                attached += "<em>y más...</em>"
            
            table_rows += f"""
            <tr>
                <td>{policy['name']}</td>
                <td>{policy['type']}</td>
                <td class="text-danger">{perms}</td>
                <td class="{ 'text-danger' if policy['attached_to'] else 'text-success' }">
                    {'SÍ' if policy['attached_to'] else 'NO'}
                </td>
                <td>{attached if policy['attached_to'] else 'Ninguna'}</td>
            </tr>
            """
        
        # Preparar lista de políticas problemáticas
        risky_policies_list = ""
        for policy in sorted(self.risky_policies, key=lambda x: x['name'])[:10]:
            issues = []
            for perm in policy['risky_permissions'][:3]:
                issues.append(f"{perm['action']} en {perm['resource']}")
            
            risky_policies_list += f"""
            <li class="list-group-item d-flex justify-content-between align-items-center">
                {policy['name']} ({policy['type']})
                <div>
                    {''.join([f'<span class="badge bg-danger rounded-pill me-1">{issue}</span>' for issue in issues])}
                    {f'<span class="badge bg-warning rounded-pill">Adjunta</span>' if policy['attached_to'] else ''}
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
    <title>Reporte de Seguridad AWS - Políticas IAM Riesgosas</title>
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
        ul, ol {{
            padding-left: 20px;
            margin-bottom: 0;
        }}
        code {{
            color: #d63384;
            word-wrap: break-word;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header text-center">
            <h1>Reporte de Seguridad AWS</h1>
            <h2>Políticas IAM Riesgosas</h2>
            <p class="mb-0">Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="row">
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if risky_policies == 0 else 'card-negative' }">
                    <h5>Políticas Riesgosas</h5>
                    <h3>{risky_policies}/{total_policies}</h3>
                    <p class="mb-0">{risky_policies/total_policies*100:.1f}%</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if attached_risky == 0 else 'card-negative' }">
                    <h5>Adjuntas a Entidades</h5>
                    <h3>{attached_risky}/{risky_policies}</h3>
                    <p class="mb-0">{attached_risky/risky_policies*100:.1f}%</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if aws_managed_risky == 0 else 'card-warning' }">
                    <h5>Políticas AWS</h5>
                    <h3>{aws_managed_risky}</h3>
                    <p class="mb-0">Administradas por AWS</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card { 'card-positive' if custom_risky == 0 else 'card-negative' }">
                    <h5>Políticas Personalizadas</h5>
                    <h3>{custom_risky}</h3>
                    <p class="mb-0">Creadas en la cuenta</p>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="risk-description">
                    <h4><i class="bi bi-exclamation-triangle-fill"></i> Riesgos de Seguridad</h4>
                    <ul>
                        <li>Políticas con permisos demasiado amplios pueden permitir escalamiento de privilegios</li>
                        <li>Permisos como <code>iam:PassRole</code> o <code>sts:AssumeRole</code> en recursos <code>*</code> son especialmente peligrosos</li>
                        <li>Políticas adjuntas a entidades activas aumentan el riesgo</li>
                        <li>Políticas personalizadas suelen ser más riesgosas que las administradas por AWS</li>
                        <li>Falta de condiciones permite uso desde cualquier contexto</li>
                    </ul>
                </div>
            </div>
            <div class="col-md-6">
                <div class="recommendations">
                    <h4><i class="bi bi-check-circle-fill"></i> Recomendaciones</h4>
                    <ul class="list-group">
                        <li class="list-group-item">Aplicar principio de mínimo privilegio</li>
                        <li class="list-group-item">Restringir permisos a recursos específicos</li>
                        <li class="list-group-item">Eliminar políticas no utilizadas</li>
                        <li class="list-group-item">Agregar condiciones a políticas existentes</li>
                        <li class="list-group-item">Revisar políticas adjuntas a entidades activas primero</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <i class="bi bi-shield-exclamation"></i> Políticas con Permisos Riesgosos ({len(self.risky_policies)})
                    </div>
                    <div class="card-body">
                        <ul class="list-group">
                            {risky_policies_list}
                            {f'<li class="list-group-item text-center">... y {len(self.risky_policies)-10} más</li>' if len(self.risky_policies) > 10 else ''}
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="table-responsive mt-4">
            <table id="policiesTable" class="table table-striped table-bordered" style="width:100%">
                <thead class="table-dark">
                    <tr>
                        <th>Nombre de Política</th>
                        <th>Tipo</th>
                        <th>Permisos Riesgosos</th>
                        <th>Adjunta</th>
                        <th>Entidades</th>
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
                    <h5 class="card-title">Ver entidades adjuntas a una política</h5>
                    <code>aws iam list-entities-for-policy --policy-arn ARN_POLITICA</code>
                    
                    <h5 class="card-title mt-3">Eliminar política</h5>
                    <code>aws iam delete-policy --policy-arn ARN_POLITICA</code>
                    
                    <h5 class="card-title mt-3">Crear política con permisos restringidos</h5>
                    <code>aws iam create-policy --policy-name NOMBRE_POLITICA \<br>
--policy-document file://politica-segura.json</code>
                    
                    <h5 class="card-title mt-3">Ejemplo de política segura (politica-segura.json)</h5>
                    <pre><code>{{
    "Version": "2012-10-17",
    "Statement": [
        {{
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::*:role/specific-role",
            "Condition": {{
                "IpAddress": {{"aws:SourceIp": ["192.0.2.0/24"]}},
                "StringEquals": {{"iam:PassedToService": "ec2.amazonaws.com"}}
            }}
        }}
    ]
}}</code></pre>
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
            $('#policiesTable').DataTable({{
                "language": {{
                    "url": "//cdn.datatables.net/plug-ins/1.11.5/i18n/Spanish.json"
                }},
                "order": [[3, "desc"], [1, "asc"]],
                "columnDefs": [
                    {{ "orderable": false, "targets": [2, 4] }}
                ]
            }});
        }});
    </script>
</body>
</html>
        """
        
        # Guardar el reporte en un archivo
        os.makedirs("reports", exist_ok=True)
        filename = f"aws_risky_policies_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join("reports", filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        print(colored(f"[+] Reporte HTML generado correctamente: {filepath}", 'green'))
        print(colored("[+] Abra el archivo en su navegador para ver el reporte interactivo", 'yellow'))