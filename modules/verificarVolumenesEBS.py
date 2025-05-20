import boto3
from termcolor import colored
from botocore.exceptions import ClientError
from tabulate import tabulate
from datetime import datetime
import os

class VolumeChecker:
    def __init__(self, session):
        self.sesion = session
        self.regiones = []
        self.volumenes_no_cifrados = []
        self.volumes_results = []
        
    def obtener_regiones(self):
        ec2 = self.sesion.client('ec2')
        self.regiones = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        print(colored(f"[+] Regiones AWS disponibles: {', '.join(self.regiones)}", 'green'))
        return self.regiones

    def buscar_volumenes_no_cifrados(self):
        print(colored("\n[*] Buscando volúmenes EBS no cifrados...", 'blue'))
        
        self.volumenes_no_cifrados = []
        self.volumes_results = []
        
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
                        
                        # Guardar datos para el reporte HTML
                        self.volumes_results.append({
                            "volume_id": vol['VolumeId'],
                            "region": region,
                            "tamaño": vol['Size'],
                            "tipo": vol['VolumeType'],
                            "estado": vol['State'],
                            "instancia_adjunta": instancia_adjunta,
                            "az": vol['AvailabilityZone'],
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
                    
                    self.volumenes_no_cifrados.extend(datos_tabla)
                else:
                    print(colored(f"[+] No se encontraron volúmenes no cifrados en {region}", 'green'))
                    
            except ClientError as e:
                print(colored(f"[-] Error al obtener volúmenes en {region}: {str(e)}", 'red'))
        
        return self.volumenes_no_cifrados

    def generar_reporte_volumenes(self):
        if not self.volumenes_no_cifrados:
            print(colored("\n[+] No se encontraron volúmenes no cifrados en ninguna región", 'green'))
            return

        print(colored("\n" + "="*80, 'red'))
        print(colored("RESUMEN GLOBAL DE VOLÚMENES NO CIFRADOS", 'red', attrs=['bold']))
        print(colored("="*80, 'red'))
        
        # Estadísticas
        tamaño_total = sum(float(fila[2]) for fila in self.volumenes_no_cifrados)
        regiones_afectadas = len(set(fila[1] for fila in self.volumenes_no_cifrados))
        volumenes_adjuntos = sum(1 for fila in self.volumenes_no_cifrados if fila[5] != "Ninguna")
        
        print(colored(f"\n• Volúmenes no cifrados totales: {len(self.volumenes_no_cifrados)}", 'yellow'))
        print(colored(f"• Regiones afectadas: {regiones_afectadas}", 'yellow'))
        print(colored(f"• Espacio total en riesgo: {tamaño_total} GB", 'yellow'))
        print(colored(f"• Volúmenes adjuntos a instancias: {volumenes_adjuntos}", 'yellow'))
        
        # Mostrar tabla 
        self.volumenes_no_cifrados.sort(key=lambda x: float(x[2]), reverse=True)
        
        encabezados = ["Volume ID", "Región", "Tamaño (GB)", "Tipo", "Estado", "Instancia Adjunta", "AZ"]
        print("\n" + colored(tabulate(
            self.volumenes_no_cifrados,
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
        
        if not self.volumes_results:
            print(colored("[!] No hay datos de volúmenes para generar el reporte", 'yellow'))
            return
        
        # Estadísticas para el reporte
        total_volumes = len(self.volumes_results)
        tamaño_total = sum(v['tamaño'] for v in self.volumes_results)
        regiones_afectadas = len(set(v['region'] for v in self.volumes_results))
        volumes_adjuntos = sum(1 for v in self.volumes_results if v['instancia_adjunta'] != "Ninguna")
        volumes_grandes = sorted(self.volumes_results, key=lambda x: x['tamaño'], reverse=True)[:5]
        
        # Generar filas de la tabla
        filas_tabla = ""
        for vol in self.volumes_results:
            filas_tabla += f"""
            <tr class="{'table-danger' if not vol['encrypted'] else 'table-success'}">
                <td>{vol['volume_id']}</td>
                <td>{vol['region']}</td>
                <td>{vol['tamaño']} GB</td>
                <td>{vol['tipo']}</td>
                <td>{vol['estado']}</td>
                <td>{vol['instancia_adjunta']}</td>
                <td>{vol['az']}</td>
            </tr>
            """
        
        # Generar lista de volúmenes más grandes
        lista_grandes = ""
        for vol in volumes_grandes:
            lista_grandes += f"""
            <li class="list-group-item d-flex justify-content-between align-items-center">
                {vol['volume_id']}
                <span class="badge bg-secondary rounded-pill">{vol['tamaño']} GB</span>
            </li>
            """
        
        # Plantilla HTML completa
        html_template = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad AWS - Volúmenes EBS</title>
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
            <h2>Volúmenes EBS no cifrados</h2>
            <p class="mb-0">Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="row">
            <div class="col-md-3">
                <div class="summary-card card-negative">
                    <h5>Volúmenes no cifrados</h5>
                    <h3>{total_volumes}</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card card-neutral">
                    <h5>Espacio total en riesgo</h5>
                    <h3>{tamaño_total} GB</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card card-neutral">
                    <h5>Regiones afectadas</h5>
                    <h3>{regiones_afectadas}</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-card {'card-negative' if volumes_adjuntos > 0 else 'card-positive'}">
                    <h5>Adjuntos a instancias</h5>
                    <h3>{volumes_adjuntos}</h3>
                </div>
            </div>
        </div>

        <div class="risk-description">
            <h4><i class="bi bi-exclamation-triangle-fill"></i> Riesgo de Seguridad</h4>
            <p>Los volúmenes EBS no cifrados representan un riesgo significativo para la seguridad de los datos. 
            Si estos volúmenes son accedidos por actores malintencionados, la información confidencial podría 
            ser comprometida. El cifrado de volúmenes es esencial para cumplir con estándares de seguridad 
            y regulaciones de protección de datos, especialmente para volúmenes adjuntos a instancias en ejecución.</p>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="recommendations">
                    <h4><i class="bi bi-check-circle-fill"></i> Recomendaciones</h4>
                    <ul class="list-group">
                        <li class="list-group-item">Habilitar cifrado predeterminado para EBS en todas las regiones</li>
                        <li class="list-group-item">Para volúmenes no adjuntos: crear copias cifradas y eliminar los originales</li>
                        <li class="list-group-item">Para volúmenes adjuntos: seguir el proceso de migración a volúmenes cifrados</li>
                        <li class="list-group-item">Implementar políticas que restrinjan la creación de volúmenes no cifrados</li>
                        <li class="list-group-item">Monitorear regularmente volúmenes no cifrados</li>
                    </ul>
                </div>
            </div>
            <div class="col-md-6">
                <div class="largest-volumes">
                    <h4><i class="bi bi-hdd-stack"></i> Volúmenes más grandes</h4>
                    <ul class="list-group">
                        {lista_grandes}
                    </ul>
                </div>
            </div>
        </div>

        <div class="table-responsive mt-4">
            <table id="resultsTable" class="table table-striped table-bordered" style="width:100%">
                <thead class="table-dark">
                    <tr>
                        <th>Volume ID</th>
                        <th>Región</th>
                        <th>Tamaño (GB)</th>
                        <th>Tipo</th>
                        <th>Estado</th>
                        <th>Instancia Adjunta</th>
                        <th>Zona de Disponibilidad</th>
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
                    <h5 class="card-title">Habilitar cifrado predeterminado</h5>
                    <code>aws ec2 enable-ebs-encryption-by-default --region &lt;region&gt;</code>
                    
                    <h5 class="card-title mt-3">Migrar volumen adjunto a cifrado</h5>
                    <code># 1. Crear snapshot del volumen<br>
                    aws ec2 create-snapshot --volume-id &lt;volume-id&gt; --region &lt;region&gt; --description "Snapshot para migración a cifrado"<br><br>
                    # 2. Crear volumen cifrado del snapshot<br>
                    aws ec2 create-volume --snapshot-id &lt;snapshot-id&gt; --availability-zone &lt;az&gt; --encrypted --region &lt;region&gt;<br><br>
                    # 3. Detener instancia, desacoplar volumen antiguo, acoplar nuevo volumen cifrado</code>
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
                "order": [[2, "desc"]]
            }});
        }});
    </script>
</body>
</html>
        """
        
        # Guardar el reporte en un archivo
        os.makedirs("reports", exist_ok=True)

        nombre_archivo = f"aws_volumes_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        ruta_archivo = os.path.join("reports", nombre_archivo)

        with open(ruta_archivo, 'w') as f:
            f.write(html_template)

        print(colored(f"[+] Reporte HTML generado correctamente: {ruta_archivo}", 'green'))
        print(colored("[+] Abra el archivo en su navegador para ver el reporte interactivo", 'yellow'))

    def mostrar_recomendaciones(self):
        print(colored("\n[!] RECOMENDACIÓN DE SEGURIDAD:", 'red', attrs=['bold']))
        print(colored("1. Cifrar volúmenes existentes creando copias cifradas", 'yellow'))
        print(colored("2. Habilitar cifrado predeterminado con 'aws ec2 enable-ebs-encryption-by-default'", 'yellow'))
        print(colored("3. Para volúmenes adjuntos:", 'yellow'))
        print(colored("   a. Crear snapshot cifrado", 'yellow'))
        print(colored("   b. Crear volumen cifrado del snapshot", 'yellow'))
        print(colored("   c. Detener instancia, desacoplar volumen antiguo", 'yellow'))
        print(colored("   d. Acoplar volumen cifrado y reiniciar instancia", 'yellow'))
        print(colored("\nComandos útiles:", 'green'))
        print(colored("  # Para habilitar cifrado predeterminado:", 'green'))
        print(colored("  aws ec2 enable-ebs-encryption-by-default --region <region>", 'green'))
        print(colored("\n  # Para cifrar un volumen no adjunto:", 'green'))
        print(colored("  aws ec2 create-snapshot --volume-id <volume-id> --region <region>", 'green'))
        print(colored("  aws ec2 create-volume --snapshot-id <snapshot-id> --availability-zone <az> --encrypted --region <region>", 'green'))

    def verificar_volumenes_no_cifrados(self):
        self.obtener_regiones()
        self.buscar_volumenes_no_cifrados()
        self.generar_reporte_volumenes()