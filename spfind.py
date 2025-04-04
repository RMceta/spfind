import socket
import threading
import sys
import re
import requests
import subprocess
import json
import argparse
from scapy.all import ARP, Ether, srp

CIAN = "\033[1;36m"
BLANCO = "\033[1;37m"
AMARILLO = "\033[1;33m"

# ----------------------------- Funciones ----------------------------- #

def get_mac_address(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc if result else None

def get_vendor_by_mac(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return response.text.strip() if response.status_code == 200 else "Desconocido"
    except:
        return "Desconocido"

def detect_os(host):
    try:
        output = subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()
        ttl_match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        if not ttl_match:
            return "Desconocido"
        ttl = int(ttl_match.group(1))
        return "Linux" if ttl <= 64 else "Windows" if ttl <= 128 else "Desconocido"
    except:
        return "Desconocido"

def scan_ports(host, port_range, num_threads=100):
    open_ports = []
    lock = threading.Lock()

    def scan_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((host, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Desconocido"
                with lock:
                    open_ports.append((port, service))
                    print(f"Puerto {port}: {service}")

    threads = []
    for port in range(port_range[0], port_range[1] + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
        if len(threads) >= num_threads:
            for t in threads:
                t.join()
            threads.clear()
    for t in threads:
        t.join()

    return open_ports

# ----------------------------- Principal ----------------------------- #

def scan_info(host, port_range=(1, 1000), guardar=None):
    print("\n")
    print("------------------------------------------------")
    print(f"{CIAN}[*] Dirección IP:{BLANCO} {host}")

    result_data = {"host": host}

    mac_address = get_mac_address(host)
    vendor = get_vendor_by_mac(mac_address) if mac_address else "Desconocido"
    print(f"{CIAN}[*] Dirección MAC:{BLANCO} {mac_address or 'Desconocida'} {CIAN}[*] OUI:{BLANCO} {vendor}")
    result_data["mac"] = mac_address or "Desconocida"
    result_data["vendor"] = vendor

    os = detect_os(host)
    print(f"{CIAN}[*] Sistema operativo:{BLANCO} {os}")
    result_data["sistema_operativo"] = os

    print("\n------------------------------------------------")
    print(f"{CIAN}[*] Puertos abiertos:{BLANCO}\n")
    open_ports = scan_ports(host, port_range)
    result_data["puertos_abiertos"] = [{"puerto": p, "servicio": s} for p, s in open_ports]

    print("\n------------------------------------------------")
    print(f"{AMARILLO}[!] Escaneo finalizado{BLANCO}\n")

    if guardar:
        guardar_resultado(result_data, guardar)

def guardar_resultado(data, formato):
    nombre_archivo = f"scan_result.{formato}"
    try:
        if formato == "txt":
            with open(nombre_archivo, "w") as f:
                for key, val in data.items():
                    if isinstance(val, list):
                        f.write(f"\n{key.upper()}:\n")
                        for item in val:
                            f.write(json.dumps(item, indent=2) + "\n")
                    else:
                        f.write(f"{key}: {val}\n")
        elif formato == "json":
            with open(nombre_archivo, "w") as f:
                json.dump(data, f, indent=2)
        print(f"\n{CIAN}[✓] Resultado guardado en {BLANCO}{nombre_archivo}")
    except Exception as e:
        print(f"{AMARILLO}Error al guardar resultados:{BLANCO} {e}")

# ----------------------------- CLI ----------------------------- #

def parse_args():
    parser = argparse.ArgumentParser(description="Escáner de red y puertos")
    parser.add_argument("host", help="Dirección IP o dominio del objetivo")
    parser.add_argument("-p", "--puertos", help="Rango de puertos, ej: 80 o 20-1000")
    parser.add_argument("-g", "--guardar", choices=["txt", "json"], help="Guardar resultado como .txt o .json")
    return parser.parse_args()

def interpretar_rango(rango):
    if not rango:
        return (1, 1000)
    if "-" in rango:
        inicio, fin = rango.split("-")
        return (int(inicio), int(fin))
    else:
        return (1, int(rango))

def main():
    args = parse_args()

    host = args.host
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host) and not re.match(r"^[\w.-]+$", host):
        print("Introduce una IP o dominio válido")
        return

    port_range = interpretar_rango(args.puertos)
    scan_info(host, port_range, args.guardar)

if __name__ == "__main__":
    main()
