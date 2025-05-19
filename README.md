<p align="center">
  <img src="https://github.com/R3LI4NT/AWSecure/blob/main/img/AWSecure.png" alt="Purge Logo" Logo" />
</p>

<p align="center">
    <a href="https://python.org">
    <img src="https://img.shields.io/badge/Python-3-green.svg">
  </a>
    <img src="https://img.shields.io/badge/Release-1.0-blue.svg">
  </a>
    <img src="https://img.shields.io/badge/Public-%F0%9F%94%91-red.svg">
  </a>
</p>

AWSecure es una herramienta de seguridad de código abierto desarrollada en Python, diseñada para analizar y auditar entornos de infraestructura en Amazon Web Services (AWS). Su objetivo principal es facilitar la identificación de configuraciones inseguras y posibles vulnerabilidades en cuentas y servicios de AWS.

Tenga en cuenta que esta es la primera versión del proyecto. Planeo incorporar nuevas funcionalidades de auditoría, generar reportes de los análisis en formato PDF y reorganizar el código para estructurarlo de manera modular.

<h1 align="center"></h1>

</br>

#### ~ Instalación

- [x] Tested on: Kali Linux

> [!IMPORTANT]
> Antes de ejecutar la herramienta, asegúrate de configurar las credenciales de AWS en la CLI. Estas se almacenan en la ruta: `~/.aws/credentials`.

```
• git clone https://github.com/R3LI4NT/AWSecure
• cd AWSecure
• python3 -m venv myenv && source myenv/bin/activate
• pip3 install -r requirements.txt
```

> Instalar AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

<h1 align="center"></h1>

</br>

#### ~ Algunos ejemplos de uso

- [x] Banner 
![1](https://github.com/user-attachments/assets/cd066931-919c-4654-9b94-583efeef76b2)

<h1 align="center"></h1>

- [x] Comprobante de MFA 
![2](https://github.com/user-attachments/assets/0b32ad31-a383-414a-b4b9-f2ea339525b3)
![3](https://github.com/user-attachments/assets/b44cf2a9-355d-49cf-ba13-4472bcf789fa)

<h1 align="center"></h1>

- [x] Comprobante de validación de archivos 
![4](https://github.com/user-attachments/assets/cf049ca5-702c-441d-9975-1180a61b181b)

<h1 align="center"></h1>

- [x] Comprobante de Snapshots sin cifrar 
![5](https://github.com/user-attachments/assets/885b5759-c057-4904-a73f-af3b28695b43)

</br>

<h1 align="center"></h1>

En caso de querer contribuir con el proyecto, por favor, contactarme al siguiente correo. Se darán créditos por ello.

<img src="https://img.shields.io/badge/r3li4nt.contact@keemail.me-D14836?style=for-the-badge&logo=gmail&logoColor=white" />

¡Gracias!

<h1 align="center"></h1>

### Importante

**`ES:`** No me hago responsable del mal uso que se le pueda dar a esta herramienta, úselo para Pentesting o fines educativos.

**`EN:`**  I am not responsible for the misuse that may be given to this tool, use it for Pentesting or educational purposes.

#R3LI4NT
