import nmap
import time

def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')  # Utiliser -sn pour un scan ping simple

    devices = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            devices.append({'ip': host, 'hostname': nm[host].hostname()})

    return devices

def detailed_scan(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-O -sV')  # Appliquer -O et -sV pour un scan détaillé
        details = {'ip': ip, 'os': None, 'services': []}

        # Vérifier si l'IP est dans les résultats du scan
        if ip not in nm.all_hosts():
            print(f"Aucun résultat pour l'IP : {ip}")
            return details  # Retourne des détails vides si aucun résultat n'est trouvé

        # Récupérer les informations sur le système d'exploitation (OS)
        if 'osmatch' in nm[ip]:
            details['os'] = nm[ip]['osmatch'][0]['name'] if nm[ip]['osmatch'] else 'Unknown'

        # Vérifier la présence de services TCP ouverts
        if 'tcp' in nm[ip]:
            for port in nm[ip]['tcp']:
                service = nm[ip]['tcp'][port]
                details['services'].append({
                    'port': port,
                    'name': service['name'],
                    'version': service.get('version', 'Unknown')
                })

        return details
    except Exception as e:
        print(f"Erreur lors du scan de {ip} : {e}")
        return {'ip': ip, 'os': 'Erreur', 'services': []}

# Scanner le réseau local pour obtenir les appareils connectés
devices = scan_network("192.168.1.0/24")
ip_list = [device['ip'] for device in devices]  # Liste des IPs

print("Appareils connectés détectés :")
for device in devices:
    print(f"IP: {device['ip']}, Hostname: {device['hostname']}")

# Demander si l'utilisateur souhaite effectuer un scan approfondi
user_input = input("\nVoulez-vous effectuer un scan approfondi ? Ce scan peut prendre un certain temps. Appuyez sur 'O' pour valider ou une autre touche pour annuler : ").strip().lower()

if user_input == 'o':
    print("\nDémarrage du scan approfondi...\n")
    for ip in ip_list:
        details = detailed_scan(ip)
        print(f"IP : {details['ip']}")
        print(f"OS : {details['os']}")
        print("Services :")
        for service in details['services']:
            print(f" - Port : {service['port']}, Service : {service['name']}, Version : {service['version']}")
        print("\n" + "-"*30 + "\n")
        time.sleep(2)  # Ajouter un petit délai pour éviter de surcharger le réseau
else:
    print("Scan approfondi annulé.")
