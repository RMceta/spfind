
# spfind 

`spfind.py` es una herramienta de escaneo de red escrita en Python que permite identificar:

- Dirección IP y MAC
- Fabricante (OUI)
- Sistema operativo (estimado por TTL)
- Puertos abiertos y sus servicios
- Guardar resultados en `.txt` o `.json`

## 📦 Instalación

```bash
git clone https://github.com/RMceta/spfind.git
cd spfind
pip install -r requirements.txt
```

## 🚀 Uso 

```bash
sudo python3 spfind.py <IP> [opciones]
```
⚠️ Usar siempre como superusuario

### Opciones disponibles:

- `-p` o `--ports`  
  Permite especificar los puertos a escanear.  
  Puedes usar un solo número (`-p 5000`) para escanear desde el puerto 1 hasta el 5000,  
  o un rango personalizado (`-p 20-10000`) para escanear desde el puerto 20 hasta el 10000.  
  Si no se especifica esta opción, el escaneo por defecto se realiza desde el **puerto 1 hasta el 1000**.  
   >⚠️Nota: Escanear rangos más amplios puede aumentar significativamente el tiempo de análisis.


- `-g` o `--guardar`  
  Guarda los resultados del escaneo en un archivo.  
  Puedes elegir entre los formatos `txt` o `json` (`-g txt` o `-g json`).  
  El archivo se guarda automáticamente con el nombre:
  - `scan_result.txt` para texto plano
  - `scan_result.json` para formato estructurado


**Ejemplos:**

```bash
sudo python3 spfind.py 192.168.1.1
```
```bash
sudo python3 spfind.py 192.168.1.1 -p 5000
```
```bash
sudo python3 spfind.py 192.168.1.1 -p 20-10000
```
```bash
sudo python3 spfind.py 192.168.1.1 -g txt
```
```bash
sudo python3 spfind.py 192.168.1.1 -p 100-200 -g json
```

## 🛠 Requisitos

- Python 3.7 o superior
- Sistema operativo: Windows, Linux(Recomendado), macOS 
- Permisos de superusuario para operaciones ARP

