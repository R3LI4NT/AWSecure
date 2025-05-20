import boto3
from termcolor import colored
from botocore.exceptions import ClientError
from tabulate import tabulate
from datetime import datetime
import os

class SnapshotChecker:
    def __init__(self, session):
        self.sesion = session
        self.regiones = []
        self.snapshots_no_cifrados = []
        self.snapshots_results = []
        
    def obtener_regiones(self):
        ec2 = self.sesion.client('ec2')
        self.regiones = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        print(colored(f"[+] Regiones AWS disponibles: {', '.join(self.regiones)}", 'green'))
        return self.regiones

    def buscar_snapshots_no_cifrados(self):
        print(colored("\n[*] Buscando snapshots EBS no cifrados...", 'blue'))
        
        self.snapshots_no_cifrados = []
        self.snapshots_results = []
        
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
                        
                        # Guardar datos para el reporte HTML
                        self.snapshots_results.append({
                            "snapshot_id": snap['SnapshotId'],
                            "region": region,
                            "tamaño": snap['VolumeSize'],
                            "fecha_creacion": snap['StartTime'].strftime('%Y-%m-%d %H:%M:%S'),
                            "descripcion": snap.get('Description', 'N/A'),
                            "encrypted": False
                        })
                    
                    # Mostrar tabla regional
                    print("\n" + colored(tabulate(
                        datos_tabla,
                        headers=encabezados,
                        tablefmt="grid",
                        stralign="left",
                        numalign="center"
                    ), 'white'))
                    
                    self.snapshots_no_cifrados.extend(datos_tabla)
                else:
                    print(colored(f"[+] No se encontraron snapshots no cifrados en {region}", 'green'))
                    
            except ClientError as e:
                print(colored(f"[-] Error al obtener snapshots en {region}: {str(e)}", 'red'))
        
        return self.snapshots_no_cifrados

    def generar_reporte_snapshots(self):
        if not self.snapshots_no_cifrados:
            print(colored("\n[+] No se encontraron snapshots no cifrados en ninguna región", 'green'))
            return

        print(colored("\n" + "="*80, 'red'))
        print(colored("RESUMEN GLOBAL DE SNAPSHOTS NO CIFRADOS", 'red', attrs=['bold']))
        print(colored("="*80, 'red'))
        
        # Estadísticas
        tamaño_total = sum(float(fila[2]) for fila in self.snapshots_no_cifrados)
        regiones_afectadas = len(set(fila[1] for fila in self.snapshots_no_cifrados))
        mas_antiguo = min(fila[3] for fila in self.snapshots_no_cifrados)
        
        print(colored(f"\n• Snapshots no cifrados totales: {len(self.snapshots_no_cifrados)}", 'yellow'))
        print(colored(f"• Regiones afectadas: {regiones_afectadas}", 'yellow'))
        print(colored(f"• Espacio total en riesgo: {tamaño_total} GB", 'yellow'))
        print(colored(f"• Snapshot más antiguo: {mas_antiguo}", 'yellow'))
        
        # Mostrar tabla 
        self.snapshots_no_cifrados.sort(key=lambda x: x[3], reverse=True)
        
        encabezados = ["Snapshot ID", "Región", "Tamaño (GB)", "Fecha creación", "Descripción"]
        print("\n" + colored(tabulate(
            self.snapshots_no_cifrados,
            headers=encabezados,
            tablefmt="grid",
            stralign="left",
            numalign="center"
        ), 'cyan'))
        
        # Preguntar si generar reporte HTML
        self.preguntar_generar_reporte()
        
        # Recomendación de acción
        self.mostrar_recomendaciones()

    def preguntar_generar_reporte(self):
        respuesta = input(colored("\n[?] ¿Desea generar un reporte HTML interactivo de estos resultados? (s/n): ", 'yellow'))
        if respuesta.lower() == 's':
            self.generar_reporte_html()

    def generar_reporte_html(self):
        print(colored("\n[*] Generando reporte HTML interactivo...", 'blue'))
        
        if not self.snapshots_results:
            print(colored("[!] No hay datos de snapshots para generar el reporte", 'yellow'))
            return
        
        # Estadísticas para el reporte
        total_snapshots = len(self.snapshots_results)
        tamaño_total = sum(s['tamaño'] for s in self.snapshots_results)
        regiones_afectadas = len(set(s['region'] for s in self.snapshots_results))
        snapshots_antiguos = sorted(self.snapshots_results, key=lambda x: x['fecha_creacion'])[:5]
        
        # Generar filas de la tabla
        filas_tabla = ""
        for snap in self.snapshots_results:
            filas_tabla += f"""
            <tr class="{'table-danger' if not snap['encrypted'] else 'table-success'}">
                <td>{snap['snapshot_id']}</td>
                <td>{snap['region']}</td>
                <td>{snap['tamaño']} GB</td>
                <td>{snap['fecha_creacion']}</td>
                <td>{snap['descripcion'][:100] + '...' if len(snap['descripcion']) > 100 else snap['descripcion']}</td>
            </tr>
            """
        
        # Generar lista de snapshots antiguos
        lista_antiguos = ""
        for snap in snapshots_antiguos:
            lista_antiguos += f"""
            <li class="list-group-item d-flex justify-content-between align-items-center">
                {snap['snapshot_id']}
                <span class="badge bg-secondary rounded-pill">{snap['fecha_creacion']}</span>
            </li>
            """
        
        # Plantilla HTML completa
        html_template = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad AWS - Snapshots EBS</title>
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
        .list-group-item {{
            transition: all 0.3s;
        }}
        .list-group-item:hover {{
            background-color: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header text-center">
            <h1>Reporte de Seguridad AWS</h1>
            <h2>Snapshots EBS no cifrados</h2>
            <p class="mb-0">Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="row">
            <div class="col-md-4">
                <div class="summary-card card-negative">
                    <h5>Snapshots no cifrados</h5>
                    <h3>{total_snapshots}</h3>
                </div>
            </div>
            <div class="col-md-4">
                <div class="summary-card card-neutral">
                    <h5>Espacio total en riesgo</h5>
                    <h3>{tamaño_total} GB</h3>
                </div>
            </div>
            <div class="col-md-4">
                <div class="summary-card card-neutral">
                    <h5>Regiones afectadas</h5>
                    <h3>{regiones_afectadas}</h3>
                </div>
            </div>
        </div>

        <div class="risk-description">
            <h4><i class="bi bi-exclamation-triangle-fill"></i> Riesgo de Seguridad</h4>
            <p>Los snapshots EBS no cifrados representan un riesgo significativo para la seguridad de los datos. 
            Si estos snapshots son accedidos por actores malintencionados, la información confidencial podría 
            ser comprometida. El cifrado de snapshots es esencial para cumplir con estándares de seguridad 
            y regulaciones de protección de datos.</p>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="recommendations">
                    <h4><i class="bi bi-check-circle-fill"></i> Recomendaciones</h4>
                    <ul class="list-group">
                        <li class="list-group-item">Cifrar snapshots existentes usando 'aws ec2 copy-snapshot --encrypted'</li>
                        <li class="list-group-item">Habilitar cifrado predeterminado para EBS</li>
                        <li class="list-group-item">Implementar políticas que restrinjan la creación de snapshots no cifrados</li>
                        <li class="list-group-item">Monitorear regularmente snapshots no cifrados</li>
                        <li class="list-group-item">Eliminar snapshots antiguos que ya no sean necesarios</li>
                    </ul>
                </div>
            </div>
            <div class="col-md-6">
                <div class="oldest-snapshots">
                    <h4><i class="bi bi-clock-history"></i> Snapshots más antiguos</h4>
                    <ul class="list-group">
                        {lista_antiguos}
                    </ul>
                </div>
            </div>
        </div>

        <div class="table-responsive mt-4">
            <table id="resultsTable" class="table table-striped table-bordered" style="width:100%">
                <thead class="table-dark">
                    <tr>
                        <th>Snapshot ID</th>
                        <th>Región</th>
                        <th>Tamaño (GB)</th>
                        <th>Fecha creación</th>
                        <th>Descripción</th>
                    </tr>
                </thead>
                <tbody>
                    {filas_tabla}
                </tbody>
            </table>
        </div>

        <div class="commands-section mt-4">
            <h4><i class="bi bi-terminal-fill"></i> Comandos útiles</h4>
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Cifrar un snapshot existente</h5>
                    <code>aws ec2 copy-snapshot --source-region &lt;region&gt; --source-snapshot-id &lt;snapshot-id&gt; --region &lt;region-destino&gt; --encrypted --description "Snapshot cifrado"</code>
                    
                    <h5 class="card-title mt-3">Habilitar cifrado predeterminado</h5>
                    <code>aws ec2 enable-ebs-encryption-by-default --region &lt;region&gt;</code>
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
            $('#resultsTable').DataTable({{
                "language": {{
                    "url": "//cdn.datatables.net/plug-ins/1.11.5/i18n/Spanish.json"
                }},
                "order": [[3, "asc"]]
            }});
        }});
    </script>
</body>
</html>
        """
        
        # Guardar el reporte en un archivo
        os.makedirs("reports", exist_ok=True)

        nombre_archivo = f"aws_snapshots_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        ruta_archivo = os.path.join("reports", nombre_archivo)

        with open(ruta_archivo, 'w') as f:
            f.write(html_template)

        print(colored(f"[+] Reporte HTML generado correctamente: {ruta_archivo}", 'green'))
        print(colored("[+] Abra el archivo en su navegador para ver el reporte interactivo", 'yellow'))

    def mostrar_recomendaciones(self):
        print(colored("\n[!] RECOMENDACIÓN DE SEGURIDAD:", 'red', attrs=['bold']))
        print(colored("1. Cifrar snapshots existentes usando 'aws ec2 copy-snapshot --encrypted'", 'yellow'))
        print(colored("2. Habilitar cifrado predeterminado con 'aws ec2 enable-ebs-encryption-by-default'", 'yellow'))
        print(colored("3. Eliminar snapshots no cifrados originales después de verificar las copias cifradas", 'yellow'))
        print(colored("\nComandos útiles:", 'green'))
        print(colored("  # Para cifrar un snapshot existente:", 'green'))
        print(colored("  aws ec2 copy-snapshot --source-region <region> --source-snapshot-id <snapshot-id> \\", 'green'))
        print(colored("    --region <region-destino> --encrypted --description \"Snapshot cifrado\"", 'green'))
        print(colored("\n  # Para habilitar cifrado predeterminado:", 'green'))
        print(colored("  aws ec2 enable-ebs-encryption-by-default --region <region>", 'green'))

    def verificar_snapshots_no_cifrados(self):
        self.obtener_regiones()
        self.buscar_snapshots_no_cifrados()
        self.generar_reporte_snapshots()