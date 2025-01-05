import os
import subprocess
import time
from stem import Signal
from stem.control import Controller
import scapy.all as scapy
import shutil
import json

class PrivacyTool:
    def __init__(self):
        self.tor_control_port = 9051
        self.tor_password = 'your_password_here'

    def banner(self):
        banner_text = """
       

 __ \  _)                               _)                       |     _ \  _)   _|  |   
 |   |  |  __ `__ \    _ \  __ \    __|  |   _ \   __ \    _` |  |    |   |  |  |    __| 
 |   |  |  |   |   |   __/  |   | \__ \  |  (   |  |   |  (   |  |    __ <   |  __|  |   
____/  _| _|  _|  _| \___| _|  _| ____/ _| \___/  _|  _| \__,_| _|   _| \_\ _| _|   \__| 
                                                                                         
    -------------------------------------------------
        -root0emir
    -------------------------------------------------



        """
        print(banner_text)

    def connect_to_tor(self):
        """Connect to Tor and change identity"""
        try:
            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate(password=self.tor_password)
                controller.signal(Signal.NEWNYM)  
                print("[INFO] Tor bağlantısı başarılı ve kimlik değiştirildi.")
                self.check_tor_connection()
        except Exception as e:
            print(f"[ERROR] Tor bağlantısı başarısız: {e}")

    def manual_change_identity(self):
        """Manual option to change Tor identity"""
        try:
            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate(password=self.tor_password)
                controller.signal(Signal.NEWNYM)
                print("[INFO] Tor kimliği başarıyla değiştirildi.")
                self.check_tor_connection()
        except Exception as e:
            print(f"[ERROR] Tor kimliği değiştirme sırasında bir hata oluştu: {e}")

    def check_tor_connection(self):
        """Check if Tor connection is active"""
        try:
            response = subprocess.check_output([
                'curl', '--socks5-hostname', '127.0.0.1:9050', 'https://check.torproject.org'
            ], stderr=subprocess.DEVNULL).decode()
            if "Congratulations" in response:
                print("[INFO] Tor ağına başarıyla bağlısınız. IP adresiniz gizlendi. Tüm trafik Tor ağına yönlendiriliyor.")
            else:
                print("[WARNING] Tor ağına bağlı değilsiniz. Bağlantınızı kontrol edin.")
        except Exception as e:
            print(f"[ERROR] Tor bağlantısı kontrol edilemiyor: {e}")

    def clear_traces(self):
        """Clear traces from the system"""
        try:
            components_cleared = []
            os.system('rm -rf /tmp/*')
            components_cleared.append("Geçici dosyalar")

            os.system('sudo systemctl restart network-manager')
            components_cleared.append("Ağ durumu sıfırlandı")

            shutil.rmtree(os.path.expanduser('~/.cache'), ignore_errors=True)
            components_cleared.append("Önbellek dosyaları")

            print("[INFO] İzler başarıyla temizlendi:")
            for component in components_cleared:
                print(f"  - {component}")
        except Exception as e:
            print(f"[ERROR] İzler temizlenirken bir hata oluştu: {e}")

    def reset_dns_settings(self):
        """Reset DNS settings to secure defaults"""
        try:
            resolv_conf_path = "/etc/resolv.conf"
            with open(resolv_conf_path, "w") as f:
                f.write("nameserver 1.1.1.1\n")
                f.write("nameserver 8.8.8.8\n")
            print("[INFO] DNS ayarları sıfırlandı ve güvenli DNS sunucuları eklendi.")
        except Exception as e:
            print(f"[ERROR] DNS ayarları sıfırlanırken bir hata oluştu: {e}")

    def analyze_traffic(self):
        """Analyze network traffic"""
        try:
            print("[INFO] Ağ trafiği analizi başlatıldı. (CTRL+C ile durdurabilirsiniz)")
            scapy.sniff(prn=self.process_packet, store=False, filter="ip")
        except KeyboardInterrupt:
            print("[INFO] Ağ trafiği analizi durduruldu.")
        except Exception as e:
            print(f"[ERROR] Trafik analizi sırasında bir hata oluştu: {e}")

    @staticmethod
    def process_packet(packet):
        """Process a single network packet"""
        try:
            packet_data = {}
            if packet.haslayer(scapy.IP):
                packet_data['src'] = packet[scapy.IP].src
                packet_data['dst'] = packet[scapy.IP].dst
                packet_data['proto'] = packet[scapy.IP].proto
                print(json.dumps(packet_data, indent=2))

            if packet.haslayer(scapy.TCP):
                packet_data['tcp_ports'] = {
                    'src_port': packet[scapy.TCP].sport,
                    'dst_port': packet[scapy.TCP].dport
                }
                print(json.dumps(packet_data, indent=2))
        except Exception as e:
            print(f"[ERROR] Paket işlenemedi: {e}")

    def protect_against_arp(self):
        """Protect against ARP spoofing"""
        try:
            print("[INFO] ARP koruması başlatıldı.")
            while True:
                arp_requests = scapy.sniff(filter="arp", timeout=5, store=False)
                for packet in arp_requests:
                    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 1:  # ARP request
                        attacker_ip = packet[scapy.ARP].psrc
                        attacker_mac = packet[scapy.ARP].hwsrc
                        print(f"[WARNING] ARP isteği tespit edildi: IP = {attacker_ip}, MAC = {attacker_mac}")
        except KeyboardInterrupt:
            print("[INFO] ARP koruması durduruldu.")
        except Exception as e:
            print(f"[ERROR] ARP koruması sırasında bir hata oluştu: {e}")

    def analyze_tor_traffic(self):
        """Analyze traffic passing through Tor proxy"""
        try:
            print("[INFO] Tor ağı üzerinden geçen trafik analiz ediliyor...")
            scapy.sniff(prn=self.process_packet, store=False, filter="tcp port 9050")
        except KeyboardInterrupt:
            print("[INFO] Tor trafik analizi durduruldu.")
        except Exception as e:
            print(f"[ERROR] Tor trafik analizi sırasında bir hata oluştu: {e}")

# Kullanım
if __name__ == "__main__":
    if os.name != 'posix':
        print("[ERROR] Bu araç yalnızca Linux tabanlı işletim sistemlerinde çalışır.")
        exit(1)

    tool = PrivacyTool()
    tool.banner()

    while True:
        print("\n[1] Tor Ağına Bağlan")
        print("[2] Tor Bağlantısını Kontrol Et")
        print("[3] İzleri Temizle")
        print("[4] DNS Ayarlarını Sıfırla")
        print("[5] Ağ Trafiğini Analiz Et")
        print("[6] ARP Korumasını Başlat")
        print("[7] Tor Trafiğini Analiz Et")
        print("[8] Tor Kimlik Değiştirme ")
        print("[0] Çıkış")

        try:
            choice = input("Başlatılıyor...")
            if choice == "1":
                tool.connect_to_tor()
            elif choice == "2":
                tool.check_tor_connection()
            elif choice == "3":
                tool.clear_traces()
            elif choice == "4":
                tool.reset_dns_settings()
            elif choice == "5":
                tool.analyze_traffic()
            elif choice == "6":
                tool.protect_against_arp()
            elif choice == "7":
                tool.analyze_tor_traffic()
            elif choice == "8":
                tool.manual_change_identity()
            elif choice == "0":
                print("[INFO] Çıkış yapılıyor.")
                break
            else:
                print("[ERROR] Geçersiz seçim. Lütfen tekrar deneyin.")
        except KeyboardInterrupt:
            print("\n[INFO] Çıkış yapılıyor.")
            break
