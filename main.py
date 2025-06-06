import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import threading
import socket
import time
import os
import subprocess
import platform
from cryptography.fernet import Fernet
import scapy.all as scapy
import ctypes
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import time
import base64
import os
import json
import hashlib

# Ana pencere sınıfı
class NetworkApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Güvenli Dosya Transfer ve Ağ Analizi Sistemi")
        self.geometry("800x600")
        
        # Ana menü çerçevesi
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Başlık etiketi
        ttk.Label(self.main_frame, text="Güvenli Dosya Transfer ve Ağ Analizi Sistemi", 
                 font=("Arial", 16, "bold")).pack(pady=20)
        
        # Butonlar için çerçeve
        buttons_frame = ttk.Frame(self.main_frame)
        buttons_frame.pack(pady=20)
        
        # Ana menü butonları
        ttk.Button(buttons_frame, text="Sunucu (Dosya Alımı)", 
                  command=self.open_server, width=25).grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(buttons_frame, text="İstemci (Dosya Gönderimi)", 
                  command=self.open_client, width=25).grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(buttons_frame, text="iPerf Testi", 
                  command=self.open_iperf, width=25).grid(row=1, column=0, padx=10, pady=10)
        ttk.Button(buttons_frame, text="Wireshark Yakalama", 
                  command=self.open_wireshark, width=25).grid(row=1, column=1, padx=10, pady=10)
        ttk.Button(buttons_frame, text="MITM Simülasyonu", 
                  command=self.open_mitm, width=25).grid(row=2, column=0, padx=10, pady=10)
        ttk.Button(buttons_frame, text="Paket Enjeksiyonu", 
                  command=self.open_injection, width=25).grid(row=2, column=1, padx=10, pady=10)
        ttk.Button(buttons_frame, text="Güvenlik Protokolü Karşılaştırması", 
                  command=self.open_security_comparison, width=25).grid(row=3, column=0, columnspan=2, padx=10, pady=10)
        
        # Alt bilgi
        ttk.Label(self.main_frame, text="© 2025 Ağ Güvenliği Projesi", 
                 font=("Arial", 8)).pack(side="bottom", pady=10)
        
        # Alt çerçeveleri tanımla (pencereler arası geçiş için)
        self.frames = {}
        
    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def back_to_main(self):
        self.clear_main_frame()
        self.__init__()
    
    def open_server(self):
        self.clear_main_frame()
        ServerFrame(self.main_frame, self.back_to_main)
    
    def open_client(self):
        self.clear_main_frame()
        ClientFrame(self.main_frame, self.back_to_main)
    
    def open_iperf(self):
        self.clear_main_frame()
        IPerfFrame(self.main_frame, self.back_to_main)
    
    def open_wireshark(self):
        self.clear_main_frame()
        WiresharkFrame(self.main_frame, self.back_to_main)
    
    def open_mitm(self):
        self.clear_main_frame()
        MITMFrame(self.main_frame, self.back_to_main)
    
    def open_injection(self):
        self.clear_main_frame()
        InjectionFrame(self.main_frame, self.back_to_main)
    
    def open_security_comparison(self):
        self.clear_main_frame()
        SecurityComparisonFrame(self.main_frame, self.back_to_main)

# Sunucu çerçevesi
class ServerFrame:
    def __init__(self, parent, back_callback):
        self.parent = parent
        self.back_callback = back_callback
        
        # Başlık
        ttk.Label(parent, text="Sunucu (Dosya Alımı)", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Kontrol çerçevesi
        control_frame = ttk.Frame(parent)
        control_frame.pack(pady=10, fill="x")
        
        # Protokol durumu
        status_frame = ttk.LabelFrame(control_frame, text="Protokol Durumu")
        status_frame.pack(side="left", padx=10, fill="y")
        
        self.tcp_status = ttk.Label(status_frame, text="TCP: Bekleniyor")
        self.tcp_status.pack(anchor="w", padx=10, pady=5)
        
        self.udp_status = ttk.Label(status_frame, text="UDP: Bekleniyor")
        self.udp_status.pack(anchor="w", padx=10, pady=5)
        
        # Şifreleme anahtar girişi
        key_frame = ttk.LabelFrame(control_frame, text="Şifreleme")
        key_frame.pack(side="left", padx=10, fill="both", expand=True)
        
        ttk.Label(key_frame, text="Şifreleme Anahtarı:").pack(anchor="w", padx=10, pady=5)
        self.key_entry = ttk.Entry(key_frame, width=40)
        self.key_entry.pack(padx=10, pady=5, fill="x")
        
        # Butonlar
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Sunucuyu Başlat", command=self.start_server)
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Durdur", command=self.stop_server, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        # Şifre çözme butonu ekleyin (başlangıçta devre dışı)
        self.decrypt_btn = ttk.Button(btn_frame, text="Şifreyi Çöz", 
                                      command=self.decrypt_data_ui, state="disabled")
        self.decrypt_btn.pack(side="left", padx=5)
        
        # Ana menü butonu
        ttk.Button(btn_frame, text="Ana Menüye Dön", command=back_callback).pack(side="left", padx=5)
        
        # Alınan veriyi saklayacak değişken
        self.received_encrypted_data = None
        
        # İlerleme çubuğu
        progress_frame = ttk.LabelFrame(parent, text="Dosya Alım Durumu")
        progress_frame.pack(pady=10, fill="x", padx=10)
        
        self.progress = ttk.Progressbar(progress_frame, length=100, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=10)
        
        self.status_label = ttk.Label(progress_frame, text="Hazır")
        self.status_label.pack(anchor="w", padx=10, pady=5)
        
        # Log penceresi
        log_frame = ttk.LabelFrame(parent, text="Sunucu Logu")
        log_frame.pack(pady=10, fill="both", expand=True, padx=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Sunucu değişkenleri
        self.server_running = False
        self.stop_event = threading.Event()
        self.received_data = {"tcp": b"", "udp": b""}
        self.connections_active = {"tcp": False, "udp": False}
        self.total_bytes = 0
        self.active_protocol = None

    def log(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def update_status(self, message):
        self.status_label.config(text=message)
    
    def start_server(self):
        '''self.server_running = True
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress["value"] = 0
        self.log("Sunucu başlatılıyor...")
        
        # Sunucu thread'ini başlat
        self.server_thread = threading.Thread(target=self.server_function)
        self.server_thread.daemon = True
        self.server_thread.start()'''
        self.server_running = True
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress["value"] = 0
        
        # Önceki verilerle ilgili tüm değişkenleri temizle
        self.received_data = {"tcp": b"", "udp": b""}
        self.connections_active = {"tcp": False, "udp": False}
        self.total_bytes = 0
        self.active_protocol = None
        self.received_encrypted_data = None
        
        self.log("Sunucu başlatılıyor...")
        
        # Sunucu thread'ini başlat
        self.server_thread = threading.Thread(target=self.server_function)
        self.server_thread.daemon = True
        self.server_thread.start()
    
    def stop_server(self):
        self.log("Sunucu durduruluyor...")
        self.stop_event.set()
        self.server_running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.update_status("Durduruldu")
    
    def server_function(self):
        self.log("TCP ve UDP modunda eşzamanlı dinleme başlatılıyor...")
        
        # TCP ve UDP thread'lerini oluştur
        tcp_thread = threading.Thread(target=self.tcp_listener)
        udp_thread = threading.Thread(target=self.udp_listener)
        
        tcp_thread.daemon = True
        udp_thread.daemon = True
        
        tcp_thread.start()
        udp_thread.start()
        
        # Her iki thread tamamlanana kadar bekle
        tcp_thread.join()
        udp_thread.join()
        
        # Hangi protokolün veri aldığını kontrol et
        if len(self.received_data["tcp"]) > 0:
            self.active_protocol = "tcp"
            data = self.received_data["tcp"]
        elif len(self.received_data["udp"]) > 0:
            self.active_protocol = "udp"
            data = self.received_data["udp"]
        else:
            self.log("Hiçbir protokolden veri alınamadı!")
            self.update_status("Veri alınamadı")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            return
        
        self.log(f"{self.active_protocol.upper()} protokolü ile veri alındı, toplam: {len(data)} bayt")
        self.log("Şifreleme anahtarını girip 'Şifreyi Çöz' butonuna basın.")
        
        # Şifrelenmiş veriyi sakla ve şifre çözme butonunu etkinleştir
        self.received_encrypted_data = data
        self.decrypt_btn.config(state="normal")
        self.update_status("Şifre bekleniyor...")
        
        # Durdur butonunu devre dışı bırak
        self.stop_btn.config(state="disabled")
    
    def decrypt_data_ui(self):
        """Kullanıcının girdiği anahtarla veriyi çözen UI fonksiyonu"""
        if self.received_encrypted_data is None:
            self.log("Henüz veri alınmadı!")
            return
            
        key = self.key_entry.get().encode()
        if not key:
            self.log("Şifreleme anahtarı girilmedi!")
            self.update_status("Anahtar eksik")
            return
        
        try:
            self.log("Dosya şifresi çözülüyor...")
            self.update_status("Şifre çözülüyor...")
            decrypted_data = self.decrypt_data(key, self.received_encrypted_data)
            self.log("Dosya şifresi çözüldü.")
            
            with open('received_file.txt', 'wb') as f:
                f.write(decrypted_data)
            self.log("Dosya başarıyla alındı ve kaydedildi: received_file.txt")
            self.update_status("Tamamlandı")
            
            # İşlem tamamlandı, butonları resetle
            self.decrypt_btn.config(state="disabled")
            self.start_btn.config(state="normal")
            self.received_encrypted_data = None
            self.received_data = {"tcp": b"", "udp": b""}
            
        except Exception as e:
            self.log(f"Şifre çözme hatası: {e}")
            self.update_status("Şifreleme hatası")
            # Hata durumunda kullanıcının tekrar denemesine izin ver
            self.decrypt_btn.config(state="normal")
    
    def tcp_listener(self):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.bind(('0.0.0.0', 5001))
        tcp_socket.settimeout(1.0)
        tcp_socket.listen(1)
        self.log("TCP dinleniyor (port 5001)...")
        self.tcp_status.config(text="TCP: Dinleniyor")
        
        try:
            while not self.stop_event.is_set():
                try:
                    conn, addr = tcp_socket.accept()
                    self.log(f"TCP bağlantısı kuruldu: {addr}")
                    self.tcp_status.config(text=f"TCP: Bağlandı ({addr[0]})")
                    self.connections_active["tcp"] = True
                    
                    # Kimlik doğrulama
                    token = conn.recv(1024).decode()
                    if token != "secret_token_123":
                        self.log("TCP kimlik doğrulama başarısız!")
                        conn.close()
                        self.connections_active["tcp"] = False
                        self.tcp_status.config(text="TCP: Kimlik doğrulama hatası")
                        continue
                    self.log("TCP kimlik doğrulama başarılı!")
                    
                    # Veri alımı
                    self.total_bytes = 0
                    while not self.stop_event.is_set():
                        packet = conn.recv(1028)
                        if not packet or packet == b"END":
                            break
                        if len(packet) >= 4:
                            data_size = len(packet)-4
                            self.log(f"TCP parça alındı: {data_size} bayt")
                            self.total_bytes += data_size
                            self.received_data["tcp"] += packet[4:]
                            conn.send(b"1")  # ACK gönder
                            # İlerleme çubuğunu güncelle (100 KB max varsayalım)
                            self.progress["value"] = min(100, (self.total_bytes / (100*1024)) * 100)
                            self.update_status(f"Alınıyor: {self.total_bytes} bayt")
                        else:
                            self.log("Hatalı TCP paketi alındı!")
                    
                    self.log("TCP veri alımı tamamlandı")
                    self.tcp_status.config(text="TCP: Tamamlandı")
                    conn.close()
                    self.connections_active["tcp"] = False
                    self.stop_event.set()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f"TCP hata: {e}")
                    self.tcp_status.config(text=f"TCP: Hata ({str(e)[:20]})")
                    self.connections_active["tcp"] = False
                    
        finally:
            tcp_socket.close()
            self.tcp_status.config(text="TCP: Kapalı")
    
    def udp_listener(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind(('0.0.0.0', 5001))
        udp_socket.settimeout(1.0)
        self.log("UDP dinleniyor (port 5001)...")
        self.udp_status.config(text="UDP: Dinleniyor")
        
        try:
            received_packets = {}
            first_packet = True
            client_addr = None
            
            while not self.stop_event.is_set():
                try:
                    packet, addr = udp_socket.recvfrom(1028)
                    
                    if first_packet:
                        first_packet = False
                        client_addr = addr
                        self.connections_active["udp"] = True
                        self.udp_status.config(text=f"UDP: Bağlandı ({addr[0]})")
                        
                        # İlk paket kimlik doğrulama
                        try:
                            token = packet.decode()
                            if token != "secret_token_123":
                                self.log(f"UDP kimlik doğrulama başarısız! ({addr})")
                                self.connections_active["udp"] = False
                                self.udp_status.config(text="UDP: Kimlik doğrulama hatası")
                                continue
                            self.log(f"UDP kimlik doğrulama başarılı! ({addr})")
                        except:
                            # Belki ilk paket kimlik doğrulama değil, veri paketidir
                            if len(packet) >= 4:
                                seq = int.from_bytes(packet[:4], byteorder='big')
                                self.log(f"UDP parça {seq} alındı: {len(packet)-4} bayt")
                                received_packets[seq] = packet[4:]
                                self.total_bytes += len(packet)-4
                                self.progress["value"] = min(100, (self.total_bytes / (100*1024)) * 100)
                                self.update_status(f"Alınıyor: {self.total_bytes} bayt")
                            
                        continue
                    
                    # Bu noktadan sonra gelen paketler veri paketidir
                    if packet == b"END":
                        # Tüm paketleri sıralı birleştir
                        for seq in sorted(received_packets.keys()):
                            self.received_data["udp"] += received_packets[seq]
                        self.log("UDP veri alımı tamamlandı")
                        self.udp_status.config(text="UDP: Tamamlandı")
                        self.connections_active["udp"] = False
                        self.stop_event.set()
                        break
                    
                    if len(packet) >= 4:
                        seq = int.from_bytes(packet[:4], byteorder='big')
                        data_size = len(packet)-4
                        self.log(f"UDP parça {seq} alındı: {data_size} bayt")
                        received_packets[seq] = packet[4:]
                        self.total_bytes += data_size
                        self.progress["value"] = min(100, (self.total_bytes / (100*1024)) * 100)
                        self.update_status(f"Alınıyor: {self.total_bytes} bayt")
                    else:
                        self.log("Hatalı UDP paketi alındı!")
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f"UDP hata: {e}")
                    self.udp_status.config(text=f"UDP: Hata ({str(e)[:20]})")
                    self.connections_active["udp"] = False
                    
        finally:
            udp_socket.close()
            self.udp_status.config(text="UDP: Kapalı")
    
    def decrypt_data(self, key, data):
        fernet = Fernet(key)
        return fernet.decrypt(data)

# İstemci çerçevesi
class ClientFrame:
    def __init__(self, parent, back_callback):
        self.parent = parent
        self.back_callback = back_callback
        
        # Başlık
        ttk.Label(parent, text="İstemci (Dosya Gönderimi)", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Ayarlar çerçevesi
        settings_frame = ttk.LabelFrame(parent, text="Bağlantı Ayarları")
        settings_frame.pack(pady=10, fill="x", padx=10)
        
        # Protokol seçimi
        ttk.Label(settings_frame, text="Protokol:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.protocol_var = tk.StringVar(value="t")
        ttk.Radiobutton(settings_frame, text="TCP", variable=self.protocol_var, value="t").grid(
            row=0, column=1, padx=10, pady=5, sticky="w")
        ttk.Radiobutton(settings_frame, text="UDP", variable=self.protocol_var, value="u").grid(
            row=0, column=2, padx=10, pady=5, sticky="w")
        
        # Sunucu IP
        ttk.Label(settings_frame, text="Sunucu IP:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.server_ip = ttk.Entry(settings_frame, width=30)
        self.server_ip.insert(0, "127.0.0.1")
        self.server_ip.grid(row=1, column=1, columnspan=2, padx=10, pady=5, sticky="we")
        
        # Dosya seçimi
        ttk.Label(settings_frame, text="Dosya:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.file_path = ttk.Entry(settings_frame, width=30)
        self.file_path.insert(0, "file_to_send.txt")
        self.file_path.grid(row=2, column=1, padx=10, pady=5, sticky="we")
        ttk.Button(settings_frame, text="Gözat", command=self.browse_file).grid(
            row=2, column=2, padx=10, pady=5)
        
        # Butonlar
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Dosya Gönder", command=self.start_client)
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="İptal", command=self.stop_client, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        ttk.Button(btn_frame, text="Ana Menüye Dön", command=back_callback).pack(side="left", padx=5)
        
        # İlerleme çubuğu
        progress_frame = ttk.LabelFrame(parent, text="Dosya Gönderim Durumu")
        progress_frame.pack(pady=10, fill="x", padx=10)
        
        self.progress = ttk.Progressbar(progress_frame, length=100, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=10)
        
        self.status_label = ttk.Label(progress_frame, text="Hazır")
        self.status_label.pack(anchor="w", padx=10, pady=5)
        
        # RTT ve performans ölçümleri için çerçeve
        perf_frame = ttk.LabelFrame(parent, text="Performans Metrikleri")
        perf_frame.pack(pady=10, fill="x", padx=10)
        
        self.rtt_label = ttk.Label(perf_frame, text="RTT: - ms")
        self.rtt_label.pack(side="left", padx=10, pady=5)
        
        self.speed_label = ttk.Label(perf_frame, text="Hız: - KB/s")
        self.speed_label.pack(side="left", padx=10, pady=5)
        
        self.total_sent_label = ttk.Label(perf_frame, text="Gönderilen: 0 bayt")
        self.total_sent_label.pack(side="left", padx=10, pady=5)
        
        # Log penceresi
        log_frame = ttk.LabelFrame(parent, text="İstemci Logu")
        log_frame.pack(pady=10, fill="both", expand=True, padx=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # İstemci değişkenleri
        self.client_running = False
        self.stop_client_flag = False
        self.encryption_key = None
        self.total_bytes = 0
        self.avg_rtt = 0
        self.start_time = 0
    
    def log(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def update_status(self, message):
        self.status_label.config(text=message)
    
    def browse_file(self):
        filename = filedialog.askopenfilename(title="Gönderilecek dosyayı seç")
        if filename:
            self.file_path.delete(0, tk.END)
            self.file_path.insert(0, filename)
    
    def start_client(self):
        self.client_running = True
        self.stop_client_flag = False
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress["value"] = 0
        
        # İstemci thread'ini başlat
        self.client_thread = threading.Thread(target=self.client_function)
        self.client_thread.daemon = True
        self.client_thread.start()
    
    def stop_client(self):
        self.log("İstemci durduruluyor...")
        self.stop_client_flag = True
        self.update_status("İptal edildi")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
    
    def client_function(self):
        is_tcp = self.protocol_var.get() == 't'
        protocol_name = "TCP" if is_tcp else "UDP"
        self.log(f"{protocol_name} protokolü seçildi")
        
        server_ip = self.server_ip.get()
        if not server_ip:
            self.log("Sunucu IP adresi girilmedi!")
            self.update_status("IP adresi eksik")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            return
        
        file_path = self.file_path.get()
        if not os.path.exists(file_path):
            self.log(f"Dosya bulunamadı: {file_path}")
            self.update_status("Dosya bulunamadı")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            return
        
        # Soket oluştur
        if is_tcp:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)
        else:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bağlantı
        try:
            self.log(f"Sunucuya bağlanılıyor: {server_ip}:5001")
            if is_tcp:
                client_socket.connect((server_ip, 5001))
            self.log("Bağlantı kuruldu")
            
            # Kimlik doğrulama
            try:
                auth_token = "secret_token_123".encode()
                if is_tcp:
                    client_socket.send(auth_token)
                else:
                    client_socket.sendto(auth_token, (server_ip, 5001))
                self.log("Kimlik doğrulama token'ı gönderildi")
            except Exception as e:
                self.log(f"Token gönderme hatası: {e}")
                client_socket.close()
                self.update_status("Kimlik doğrulama hatası")
                self.start_btn.config(state="normal")
                self.stop_btn.config(state="disabled")
                return
            
            # Şifreleme anahtarı oluştur
            self.encryption_key = self.generate_key()
            key_str = self.encryption_key.decode()
            self.log(f"Şifreleme anahtarı oluşturuldu: {key_str}")
            
            # Dosyayı oku ve şifrele
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                    file_size = len(data)
                    self.log(f"Dosya okundu: {file_size} bayt")
                    
                    encrypted_data = self.encrypt_data(self.encryption_key, data)
                    self.log(f"Dosya şifrelendi: {len(encrypted_data)} bayt")
                    
                    # Dosyayı parçalara ayır ve gönder
                    chunk_size = 1024
                    total_chunks = (len(encrypted_data) + chunk_size - 1) // chunk_size
                    self.total_bytes = 0
                    self.avg_rtt = 0
                    rtt_count = 0
                    self.start_time = time.time()
                    
                    for i in range(0, len(encrypted_data), chunk_size):
                        if self.stop_client_flag:
                            break
                            
                        chunk = encrypted_data[i:i+chunk_size]
                        seq = i // chunk_size
                        header = seq.to_bytes(4, byteorder='big')
                        
                        # İlerleme çubuğunu güncelle
                        progress_pct = (seq + 1) / total_chunks * 100
                        self.progress["value"] = progress_pct
                        
                        if is_tcp:
                            # TCP: ACK ve retransmission ile gönder
                            retries = 3
                            while retries > 0 and not self.stop_client_flag:
                                try:
                                    start_time = time.time()
                                    client_socket.send(header + chunk)
                                    ack = client_socket.recv(1)
                                    rtt = time.time() - start_time
                                    
                                    self.avg_rtt = (self.avg_rtt * rtt_count + rtt) / (rtt_count + 1)
                                    rtt_count += 1
                                    
                                    self.total_bytes += len(chunk)
                                    elapsed = time.time() - self.start_time
                                    speed = self.total_bytes / elapsed / 1024  # KB/s
                                    
                                    # Metrikleri güncelle
                                    self.rtt_label.config(text=f"RTT: {rtt*1000:.2f} ms")
                                    self.speed_label.config(text=f"Hız: {speed:.2f} KB/s")
                                    self.total_sent_label.config(text=f"Gönderilen: {self.total_bytes} bayt")
                                    
                                    self.log(f"Parça {seq}/{total_chunks-1} gönderildi, RTT: {rtt*1000:.2f} ms")
                                    self.update_status(f"Gönderiliyor: {progress_pct:.1f}%")
                                    
                                    if rtt > 0.1:  # Dinamik sıkışıklık kontrolü
                                        time.sleep(0.01)
                                    break
                                except socket.timeout:
                                    retries -= 1
                                    self.log(f"Parça {seq} tekrar deneme: {retries}")
                                except Exception as e:
                                    self.log(f"Gönderme hatası: {e}")
                                    retries -= 1
                            
                            if retries == 0:
                                self.log(f"Parça {seq} gönderimi başarısız!")
                                self.update_status("Gönderim hatası")
                                break
                        else:
                            # UDP: ACK olmadan gönder
                            try:
                                client_socket.sendto(header + chunk, (server_ip, 5001))
                                self.total_bytes += len(chunk)
                                
                                elapsed = time.time() - self.start_time
                                speed = self.total_bytes / elapsed / 1024  # KB/s
                                
                                self.speed_label.config(text=f"Hız: {speed:.2f} KB/s")
                                self.total_sent_label.config(text=f"Gönderilen: {self.total_bytes} bayt")
                                
                                self.log(f"Parça {seq}/{total_chunks-1} gönderildi (UDP)")
                                self.update_status(f"Gönderiliyor: {progress_pct:.1f}%")
                                time.sleep(0.01)  # UDP için küçük gecikme
                            except Exception as e:
                                self.log(f"UDP gönderme hatası: {e}")
                    
                    # Gönderimi tamamla
                    if not self.stop_client_flag:
                        if is_tcp:
                            client_socket.send(b"END")
                        else:
                            client_socket.sendto(b"END", (server_ip, 5001))
                        
                        self.log("Dosya gönderimi tamamlandı")
                        self.update_status("Tamamlandı")
                        self.progress["value"] = 100
                        
                        # Özel IP paketi gönder
                        try:
                            self.send_custom_packet(server_ip)
                        except Exception as e:
                            self.log(f"Özel IP paketi gönderme hatası: {e}")
                
            except FileNotFoundError:
                self.log(f"Dosya bulunamadı: {file_path}")
                self.update_status("Dosya bulunamadı")
            except Exception as e:
                self.log(f"Dosya işleme hatası: {e}")
                self.update_status("Dosya hatası")
        
        except Exception as e:
            self.log(f"Bağlantı hatası: {e}")
            self.update_status("Bağlantı hatası")
        
        finally:
            client_socket.close()
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
    
    def generate_key(self):
        return Fernet.generate_key()
    
    def encrypt_data(self, key, data):
        fernet = Fernet(key)
        return fernet.encrypt(data)
    
    def send_custom_packet(self, destination_ip):
        if not self.is_admin():
            self.log("Bu işlem için yönetici hakları gerekli!")
            return
            
        try:
            pkt = scapy.IP(dst=destination_ip, ttl=50)
            pkt.chksum = self.calculate_checksum(bytes(pkt)[:20])
            pkt = pkt / scapy.TCP(dport=80, flags="S")
            scapy.send(pkt, verbose=False)
            self.log(f"Özel IP paketi gönderildi (TTL=50, Checksum={pkt.chksum})")
        except Exception as e:
            self.log(f"Özel paket gönderme hatası: {e}")
    
    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def calculate_checksum(self, data):
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
            checksum += word
            checksum = (checksum >> 16) + (checksum & 0xffff)
        return ~checksum & 0xffff

# iPerf çerçevesi
class IPerfFrame:
    def __init__(self, parent, back_callback):
        self.parent = parent
        self.back_callback = back_callback
        
        # Başlık
        ttk.Label(parent, text="iPerf Testi", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Kontrol çerçevesi
        control_frame = ttk.Frame(parent)
        control_frame.pack(pady=10, fill="x")
        
        # Mod seçimi
        mode_frame = ttk.LabelFrame(control_frame, text="Test Modu")
        mode_frame.pack(side="left", padx=10, fill="y")
        
        self.mode_var = tk.StringVar(value="s")
        ttk.Radiobutton(mode_frame, text="Sunucu", variable=self.mode_var, value="s").pack(anchor="w", padx=10, pady=5)
        ttk.Radiobutton(mode_frame, text="İstemci", variable=self.mode_var, value="c", 
                        command=self.toggle_ip_entry).pack(anchor="w", padx=10, pady=5)
        
        # Sunucu IP girişi (istemci modu için)
        self.ip_frame = ttk.LabelFrame(control_frame, text="Sunucu IP")
        self.ip_frame.pack(side="left", padx=10, fill="both", expand=True)
        
        self.server_ip = ttk.Entry(self.ip_frame, width=30)
        self.server_ip.insert(0, "127.0.0.1")
        self.server_ip.pack(padx=10, pady=10, fill="x")
        self.server_ip.config(state="disabled")  # Başlangıçta devre dışı
        
        # Butonlar
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Testi Başlat", command=self.start_iperf)
        self.start_btn.pack(side="left", padx=5)
        
        ttk.Button(btn_frame, text="Ana Menüye Dön", command=back_callback).pack(side="left", padx=5)
        
        # Log penceresi
        log_frame = ttk.LabelFrame(parent, text="iPerf Logu")
        log_frame.pack(pady=10, fill="both", expand=True, padx=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Platform kontrolü
        self.check_platform()
    
    def log(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def toggle_ip_entry(self):
        if self.mode_var.get() == "c":
            self.server_ip.config(state="normal")
        else:
            self.server_ip.config(state="disabled")
    
    def check_platform(self):
        if platform.system() == "Windows":
            self.log("Windows ortamında iPerf3 yüklenmiş olmalı!")
            self.log("https://iperf.fr/iperf-download.php adresinden indirebilirsiniz.")
        else:
            self.log("Linux/Mac ortamı: brew veya apt ile kurulabilir.")
    
    def start_iperf(self):
        mode = self.mode_var.get()
        
        if mode == "s":
            # Sunucu modu
            self.log("iPerf sunucusu başlatılıyor...")
            self.start_btn.config(state="disabled")
            
            thread = threading.Thread(target=self.run_iperf_server)
            thread.daemon = True
            thread.start()
        else:
            # İstemci modu
            server_ip = self.server_ip.get()
            if not server_ip:
                self.log("Sunucu IP adresi girilmedi!")
                return
                
            self.log(f"iPerf istemcisi başlatılıyor, hedef: {server_ip}...")
            self.start_btn.config(state="disabled")
            
            thread = threading.Thread(target=lambda: self.run_iperf_client(server_ip))
            thread.daemon = True
            thread.start()
    
    def run_iperf_server(self):
        try:
            process = subprocess.Popen(
                ["iperf3", "-s"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            for line in iter(process.stdout.readline, ""):
                self.log(line.strip())
                
            process.stdout.close()
            process.wait()
            
        except Exception as e:
            self.log(f"Hata: {e}")
        finally:
            self.start_btn.config(state="normal")
    
    def run_iperf_client(self, server_ip):
        try:
            process = subprocess.Popen(
                ["iperf3", "-c", server_ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            for line in iter(process.stdout.readline, ""):
                self.log(line.strip())
                
            process.stdout.close()
            process.wait()
            
        except Exception as e:
            self.log(f"Hata: {e}")
        finally:
            self.start_btn.config(state="normal")

# Wireshark çerçevesi
class WiresharkFrame:
    def __init__(self, parent, back_callback):
        self.parent = parent
        self.back_callback = back_callback
        
        # Başlık
        ttk.Label(parent, text="Wireshark Yakalama", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Ağ arayüzleri listesi
        interfaces_frame = ttk.LabelFrame(parent, text="Ağ Arayüzleri")
        interfaces_frame.pack(pady=10, fill="x", padx=10)
        
        self.interfaces_listbox = tk.Listbox(interfaces_frame, height=5)
        self.interfaces_listbox.pack(fill="x", padx=10, pady=10)
        
        # Arayüzleri yenile butonu
        ttk.Button(interfaces_frame, text="Arayüzleri Yenile", command=self.refresh_interfaces).pack(
            pady=5, padx=10, anchor="e")
        
        # Kayıt ayarları
        settings_frame = ttk.LabelFrame(parent, text="Kayıt Ayarları")
        settings_frame.pack(pady=10, fill="x", padx=10)
        
        ttk.Label(settings_frame, text="Kayıt dosyası:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.filename = ttk.Entry(settings_frame, width=30)
        self.filename.insert(0, "capture.pcapng")
        self.filename.grid(row=0, column=1, padx=10, pady=5, sticky="we")
        
        # Butonlar
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Kayıt Başlat", command=self.start_capture)
        self.start_btn.pack(side="left", padx=5)
        
        ttk.Button(btn_frame, text="Ana Menüye Dön", command=back_callback).pack(side="left", padx=5)
        
        # Log penceresi
        log_frame = ttk.LabelFrame(parent, text="Wireshark Logu")
        log_frame.pack(pady=10, fill="both", expand=True, padx=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Arayüzleri yükle
        self.interface_map = {}
        self.refresh_interfaces()
    
    def log(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def refresh_interfaces(self):
        self.interfaces_listbox.delete(0, tk.END)
        self.interface_map = {}
        
        try:
            interfaces = self.list_interfaces()
            if not interfaces:
                self.log("Hiçbir ağ arayüzü bulunamadı!")
                return
                
            for idx, name in interfaces:
                self.interfaces_listbox.insert(tk.END, f"{idx}: {name}")
                self.interface_map[idx] = name
                
            self.log(f"{len(interfaces)} arayüz bulundu")
        except Exception as e:
            self.log(f"Arayüz listesini alma hatası: {e}")
    
    def list_interfaces(self):
        interfaces = []
        try:
            result = subprocess.run(
                ['tshark', '-D'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            lines = result.stdout.strip().split('\n')
            for line in lines:
                idx, name = line.split('.', 1)
                interfaces.append((idx.strip(), name.strip()))
        except Exception as e:
            self.log(f"Interface listelenemedi: {e}")
        return interfaces
    
    def start_capture(self):
        selected = self.interfaces_listbox.curselection()
        if not selected:
            self.log("Lütfen bir ağ arayüzü seçin!")
            return
            
        selected_idx = self.interfaces_listbox.get(selected[0]).split(":")[0]
        output_file = self.filename.get()
        
        if not output_file:
            self.log("Lütfen geçerli bir dosya adı girin!")
            return
        
        self.log(f"Interface {selected_idx} üzerinde kayıt başlatılıyor...")
        self.log(f"Kayıt dosyası: {output_file}")
        
        self.start_btn.config(state="disabled")
        
        # Kaydı ayrı bir thread'de başlat
        thread = threading.Thread(target=lambda: self.run_capture(selected_idx, output_file))
        thread.daemon = True
        thread.start()
    
    def run_capture(self, interface_idx, output_file):
        try:
            command = f'tshark -i {interface_idx} -w {output_file}'
            self.log(f"Komut çalıştırılıyor: {command}")
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            for line in iter(process.stdout.readline, ""):
                self.log(line.strip())
                
            process.stdout.close()
            process.wait()
            
        except Exception as e:
            self.log(f"Hata: {e}")
        finally:
            self.start_btn.config(state="normal")

# MITM çerçevesi
class MITMFrame:
    def __init__(self, parent, back_callback):
        self.parent = parent
        self.back_callback = back_callback
        
        # Başlık
        ttk.Label(parent, text="MITM Simülasyonu", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Hedef ayarları
        settings_frame = ttk.LabelFrame(parent, text="MITM Ayarları")
        settings_frame.pack(pady=10, fill="x", padx=10)
        
        ttk.Label(settings_frame, text="Hedef IP:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.target_ip = ttk.Entry(settings_frame, width=30)
        self.target_ip.grid(row=0, column=1, padx=10, pady=5, sticky="we")
        
        ttk.Label(settings_frame, text="Gateway IP:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.gateway_ip = ttk.Entry(settings_frame, width=30)
        self.gateway_ip.grid(row=1, column=1, padx=10, pady=5, sticky="we")
        
        # Butonlar
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Saldırıyı Başlat", command=self.start_mitm)
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Durdur", command=self.stop_mitm, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        ttk.Button(btn_frame, text="Ana Menüye Dön", command=back_callback).pack(side="left", padx=5)
        
        # Durum etiketi
        self.status_label = ttk.Label(parent, text="Hazır")
        self.status_label.pack(pady=5)
        
        # Log penceresi
        log_frame = ttk.LabelFrame(parent, text="MITM Logu")
        log_frame.pack(pady=10, fill="both", expand=True, padx=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # MITM değişkenleri
        self.mitm_running = False
        self.stop_mitm_flag = False
    
    def log(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def start_mitm(self):
        target_ip = self.target_ip.get()
        gateway_ip = self.gateway_ip.get()
        
        if not target_ip or not gateway_ip:
            self.log("Hedef IP ve Gateway IP adreslerini girin!")
            return
        
        if not self.is_admin():
            self.log("Bu işlem için yönetici hakları gerekli!")
            return
        
        self.mitm_running = True
        self.stop_mitm_flag = False
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        
        self.log("MITM saldırısı başlatılıyor...")
        self.status_label.config(text="MITM saldırısı aktif")
        
        # MITM thread'ini başlat
        self.mitm_thread = threading.Thread(target=lambda: self.run_mitm(target_ip, gateway_ip))
        self.mitm_thread.daemon = True
        self.mitm_thread.start()
    
    def stop_mitm(self):
        if not self.mitm_running:
            return
            
        self.log("Saldırı durduruluyor, ARP tablosu düzeltiliyor...")
        self.stop_mitm_flag = True
        self.status_label.config(text="Durduruluyor...")
    
    def run_mitm(self, target_ip, gateway_ip):
        try:
            while not self.stop_mitm_flag:
                self.spoof(target_ip, gateway_ip)
                self.spoof(gateway_ip, target_ip)
                self.log(f"ARP paketleri gönderildi: {target_ip} <-> {gateway_ip}")
                time.sleep(2)
                
        except Exception as e:
            self.log(f"MITM hatası: {e}")
        
        finally:
            # Saldırı bitti, ARP tablolarını düzelt
            try:
                self.log("ARP tablosu düzeltiliyor...")
                self.restore(target_ip, gateway_ip)
                self.restore(gateway_ip, target_ip)
                self.log("ARP tablosu düzeltildi")
            except Exception as e:
                self.log(f"ARP tablosu düzeltme hatası: {e}")
                
            self.mitm_running = False
            self.status_label.config(text="Hazır")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
    
    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def spoof(self, target_ip, spoof_ip):
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=scapy.getmacbyip(target_ip), psrc=spoof_ip)
        scapy.send(packet, verbose=False)
    
    def restore(self, destination_ip, source_ip):
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=scapy.getmacbyip(destination_ip),
                           psrc=source_ip, hwsrc=scapy.getmacbyip(source_ip))
        scapy.send(packet, count=4, verbose=False)

# Paket Enjeksiyonu çerçevesi
class InjectionFrame:
    def __init__(self, parent, back_callback):
        self.parent = parent
        self.back_callback = back_callback
        
        # Başlık
        ttk.Label(parent, text="Paket Enjeksiyonu", font=("Arial", 14, "bold")).pack(pady=10)
        
        # IP ayarları
        settings_frame = ttk.LabelFrame(parent, text="Paket Ayarları")
        settings_frame.pack(pady=10, fill="x", padx=10)
        
        ttk.Label(settings_frame, text="Hedef IP:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.target_ip = ttk.Entry(settings_frame, width=30)
        self.target_ip.grid(row=0, column=1, padx=10, pady=5, sticky="we")
        
        ttk.Label(settings_frame, text="TTL:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.ttl_var = tk.StringVar(value="50")
        ttk.Spinbox(settings_frame, from_=1, to=255, textvariable=self.ttl_var, width=10).grid(
            row=1, column=1, padx=10, pady=5, sticky="w")
        
        ttk.Label(settings_frame, text="Port:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.port_var = tk.StringVar(value="5001")
        ttk.Spinbox(settings_frame, from_=1, to=65535, textvariable=self.port_var, width=10).grid(
            row=2, column=1, padx=10, pady=5, sticky="w")
        
        ttk.Label(settings_frame, text="TCP Flags:").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.flags_var = tk.StringVar(value="S")
        ttk.Combobox(settings_frame, textvariable=self.flags_var, 
                     values=["S", "A", "F", "R", "P", "SA", "FA", "RA"]).grid(
            row=3, column=1, padx=10, pady=5, sticky="w")
        
        # Butonlar
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        
        self.inject_btn = ttk.Button(btn_frame, text="Paket Gönder", command=self.inject_packet)
        self.inject_btn.pack(side="left", padx=5)
        
        ttk.Button(btn_frame, text="Ana Menüye Dön", command=back_callback).pack(side="left", padx=5)
        
        # Log penceresi
        log_frame = ttk.LabelFrame(parent, text="Paket Logu")
        log_frame.pack(pady=10, fill="both", expand=True, padx=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
    
    def log(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def inject_packet(self):
        target_ip = self.target_ip.get()
        
        if not target_ip:
            self.log("Hedef IP adresini girin!")
            return
            
        if not self.is_admin():
            self.log("Bu işlem için yönetici hakları gerekli!")
            return
        
        try:
            ttl = int(self.ttl_var.get())
            port = int(self.port_var.get())
            flags = self.flags_var.get()
            
            self.log(f"Paket hazırlanıyor: {target_ip}:{port} (TTL={ttl}, Flags={flags})")
            
            # Paket gönderme işlemini başlat
            self.inject_btn.config(state="disabled")
            
            thread = threading.Thread(target=lambda: self.send_packet(target_ip, ttl, port, flags))
            thread.daemon = True
            thread.start()
            
        except ValueError:
            self.log("TTL ve Port değerleri sayı olmalıdır!")
    
    def send_packet(self, target_ip, ttl, port, flags):
        try:
            pkt = scapy.IP(dst=target_ip, ttl=ttl)
            pkt.chksum = self.calculate_checksum(bytes(pkt)[:20])
            pkt = pkt / scapy.TCP(dport=port, flags=flags)
            
            self.log(f"Paket gönderiliyor: IP={target_ip}, Port={port}, TTL={ttl}, Flags={flags}")
            
            # Paketi gönder
            scapy.send(pkt, verbose=False)
            self.log(f"Paket başarıyla gönderildi (Checksum={pkt.chksum})")
            
            # Yanıtı yakalamaya çalış
            try:
                self.log("Yanıt bekleniyor...")
                resp = scapy.sr1(pkt, timeout=2, verbose=False)
                
                if resp:
                    self.log(f"Yanıt alındı: {resp.summary()}")
                    if resp.haslayer(scapy.TCP):
                        tcp_flags = resp[scapy.TCP].flags
                        self.log(f"TCP Flags: {tcp_flags}")
                        
                        # IP Başlık bilgilerini göster
                        self.log(f"IP Header - TTL: {resp.ttl}, ID: {resp.id}")
                        if resp.flags:
                            self.log(f"IP Flags: {resp.flags}")
                else:
                    self.log("Yanıt alınamadı (timeout)")
            
            except Exception as e:
                self.log(f"Yanıt alınırken hata: {e}")
            
        except Exception as e:
            self.log(f"Paket gönderme hatası: {e}")
        
        finally:
            self.inject_btn.config(state="normal")

def is_admin(self):
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
        
def calculate_checksum(self, data):
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        checksum += word
        checksum = (checksum >> 16) + (checksum & 0xffff)
    return ~checksum & 0xffff

# Add this class after your other frame classes

class SecurityComparisonFrame:
    def __init__(self, parent, back_callback):
        self.parent = parent
        self.back_callback = back_callback
        
        # Başlık
        ttk.Label(parent, text="Güvenlik Protokolleri Karşılaştırması", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Test veri boyutu seçimi
        settings_frame = ttk.LabelFrame(parent, text="Test Ayarları")
        settings_frame.pack(pady=10, fill="x", padx=10)
        
        ttk.Label(settings_frame, text="Test Veri Boyutu (KB):").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.data_size_var = tk.StringVar(value="10")
        ttk.Spinbox(settings_frame, from_=1, to=1000, textvariable=self.data_size_var, width=10).grid(
            row=0, column=1, padx=10, pady=5, sticky="w")
        
        # Protokol seçimi için checkbuttons
        protocols_frame = ttk.LabelFrame(parent, text="Karşılaştırılacak Protokoller")
        protocols_frame.pack(pady=10, fill="x", padx=10)
        
        self.protocol_vars = {
            "Fernet (AES-128)": tk.BooleanVar(value=True),
            "AES-256": tk.BooleanVar(value=True),
            "RSA-2048": tk.BooleanVar(value=True),
            "3DES": tk.BooleanVar(value=True),
            "ChaCha20": tk.BooleanVar(value=True)
        }
        
        row = 0
        col = 0
        for protocol, var in self.protocol_vars.items():
            ttk.Checkbutton(protocols_frame, text=protocol, variable=var).grid(
                row=row, column=col, padx=10, pady=5, sticky="w")
            col += 1
            if col > 2:
                col = 0
                row += 1
        
        # Butonlar
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)
        
        self.run_btn = ttk.Button(btn_frame, text="Karşılaştırmayı Başlat", command=self.run_comparison)
        self.run_btn.pack(side="left", padx=5)
        
        ttk.Button(btn_frame, text="Ana Menüye Dön", command=back_callback).pack(side="left", padx=5)
        
        # Sonuçlar için tablar
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(pady=10, fill="both", expand=True, padx=10)
        
        # Performans sonuçları
        self.perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.perf_frame, text="Performans")
        
        # Güvenlik özellikleri
        self.security_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.security_frame, text="Güvenlik Özellikleri")
        
        # Güvenlik özellikleri tablosunu oluştur
        self.create_security_features_table()
        
        # Test sonuçları
        self.results = {}
    
    def create_security_features_table(self):
        """Güvenlik protokollerinin özelliklerini gösteren bir tablo oluşturur"""
        features = [
            "Algoritma Tipi", "Anahtar Uzunluğu", "Blok Boyutu", 
            "Şifreleme Modu", "Anahtar Değişimi", "Doğrulama", 
            "Veri Bütünlüğü", "Zayıf Noktalar", "Önerilen Kullanım"
        ]
        
        protocols = [
            "Fernet (AES-128)", "AES-256", "RSA-2048", "3DES", "ChaCha20"
        ]
        
        # Protocol details - educational information
        details = {
            "Fernet (AES-128)": [
                "Simetrik", "128-bit", "128-bit",
                "CBC + HMAC", "Gerekli", "HMAC-SHA256",
                "Yüksek", "Anahtar Dağıtımı", "Genel veri şifreleme"
            ],
            "AES-256": [
                "Simetrik", "256-bit", "128-bit",
                "Değişken (CBC, GCM)", "Gerekli", "GMAC (GCM modunda)",
                "Yüksek", "Anahtar Dağıtımı", "Yüksek güvenlikli veri"
            ],
            "RSA-2048": [
                "Asimetrik", "2048-bit", "Değişken",
                "PKCS#1", "Gerekmiyor", "Ayrı imzalama gerekli",
                "İmzayla yüksek", "Performans, Kuantum tehdidi", "Anahtar dağıtımı, İmzalama"
            ],
            "3DES": [
                "Simetrik", "168-bit", "64-bit",
                "CBC, ECB", "Gerekli", "Ayrı MAC gerekli",
                "Orta", "Sweet32 saldırısı, Yavaş", "Legacy sistemler"
            ],
            "ChaCha20": [
                "Simetrik", "256-bit", "Akış şifresi",
                "Poly1305 ile", "Gerekli", "Poly1305",
                "Yüksek", "Yeni, daha az analiz", "Mobil, düşük güç"
            ]
        }
        
        # Tablo oluştur
        for i, feature in enumerate(features):
            ttk.Label(self.security_frame, text=feature, font=("Arial", 10, "bold")).grid(
                row=i+1, column=0, padx=10, pady=5, sticky="w")
                
        for j, protocol in enumerate(protocols):
            ttk.Label(self.security_frame, text=protocol, font=("Arial", 10, "bold")).grid(
                row=0, column=j+1, padx=10, pady=5)
                
            for i, value in enumerate(details[protocol]):
                ttk.Label(self.security_frame, text=value).grid(
                    row=i+1, column=j+1, padx=10, pady=5)
    
    def run_comparison(self):
        """Güvenlik protokollerini karşılaştır ve sonuçları göster"""
        try:
            self.run_btn.config(state="disabled")
            
            # Test verisi oluştur
            try:
                data_size = int(self.data_size_var.get())
                if data_size <= 0 or data_size > 1000:
                    raise ValueError("Veri boyutu 1-1000 KB aralığında olmalıdır")
            except ValueError:
                tk.messagebox.showerror("Hata", "Geçerli bir veri boyutu girin (1-1000 KB)")
                self.run_btn.config(state="normal")
                return
                
            # Test verisini oluştur (random bytes)
            test_data = os.urandom(data_size * 1024)
            
            # Seçilen protokolleri al
            selected_protocols = [p for p, v in self.protocol_vars.items() if v.get()]
            
            if not selected_protocols:
                tk.messagebox.showerror("Hata", "En az bir protokol seçin")
                self.run_btn.config(state="normal")
                return
            
            # Sonuçları temizle
            for widget in self.perf_frame.winfo_children():
                widget.destroy()
                
            self.results = {}
            
            # Her protokol için şifreleme ve şifre çözme testleri yap
            for protocol in selected_protocols:
                enc_time, dec_time, enc_size = self.test_protocol(protocol, test_data)
                self.results[protocol] = {
                    "enc_time": enc_time,
                    "dec_time": dec_time,
                    "enc_size": enc_size,
                    "throughput_enc": (data_size / enc_time) if enc_time > 0 else 0,
                    "throughput_dec": (data_size / dec_time) if dec_time > 0 else 0,
                    "overhead": (enc_size / len(test_data)) if len(test_data) > 0 else 0
                }
            
            # Sonuçları görselleştir
            self.visualize_results()
            
        except Exception as e:
            tk.messagebox.showerror("Hata", f"Test sırasında hata oluştu: {e}")
        finally:
            self.run_btn.config(state="normal")
    
    def test_protocol(self, protocol, data):
        """Belirli bir protokol için şifreleme ve şifre çözme testleri yapar"""
        encrypted_data = None
        enc_time = 0
        dec_time = 0
        
        if protocol == "Fernet (AES-128)":
            # Fernet kullanarak şifreleme
            key = Fernet.generate_key()
            fernet = Fernet(key)
            
            start = time.time()
            encrypted_data = fernet.encrypt(data)
            enc_time = time.time() - start
            
            start = time.time()
            fernet.decrypt(encrypted_data)
            dec_time = time.time() - start
            
        elif protocol == "AES-256":
            # AES-256 kullanarak şifreleme
            key = os.urandom(32)  # 256-bit
            iv = os.urandom(16)   # 128-bit
            
            start = time.time()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Padding ekle (16 bayt'ın katı olması gerekiyor)
            padded_data = data + b'\0' * (16 - (len(data) % 16) if len(data) % 16 != 0 else 0)
            ct = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = iv + ct  # IV'yi şifreli veriyle birleştir
            enc_time = time.time() - start
            
            start = time.time()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decryptor.update(ct) + decryptor.finalize()
            dec_time = time.time() - start
            
        elif protocol == "RSA-2048":
            # RSA kullanarak şifreleme (büyük dosyaları parçalara ayırmak gerekir)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            
            # RSA performansı test etmek için sadece ilk 190 baytı şifreleyelim (maksimum blok boyutu)
            test_chunk = data[:190] if len(data) > 190 else data
            
            start = time.time()
            encrypted_data = public_key.encrypt(
                test_chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            enc_time = time.time() - start
            
            start = time.time()
            private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            dec_time = time.time() - start
            
            # Tam veri boyutu için tahmini süre hesapla
            if len(data) > 190:
                enc_time = enc_time * (len(data) / 190)
                dec_time = dec_time * (len(data) / 190)
                
            # Gerçek boyutu tahmin et
            encrypted_data = b'0' * int(len(data) * 1.5)  # RSA overhead'i yaklaşık %50
            
        elif protocol == "3DES":
            # 3DES kullanarak şifreleme
            key = os.urandom(24)  # 192-bit (168-bit etkin)
            iv = os.urandom(8)    # 64-bit
            
            start = time.time()
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Padding ekle (8 bayt'ın katı olması gerekiyor)
            padded_data = data + b'\0' * (8 - (len(data) % 8) if len(data) % 8 != 0 else 0)
            ct = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = iv + ct  # IV'yi şifreli veriyle birleştir
            enc_time = time.time() - start
            
            start = time.time()
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decryptor.update(ct) + decryptor.finalize()
            dec_time = time.time() - start
            
        elif protocol == "ChaCha20":
            # ChaCha20 kullanarak şifreleme
            key = os.urandom(32)  # 256-bit
            nonce = os.urandom(16)  # 128-bit
            
            start = time.time()
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            encrypted_data = nonce + encrypted_data  # Nonce'yi şifreli veriyle birleştir
            enc_time = time.time() - start
            
            start = time.time()
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
            decryptor = cipher.decryptor()
            decryptor.update(encrypted_data[16:]) + decryptor.finalize()
            dec_time = time.time() - start
        
        return enc_time, dec_time, len(encrypted_data) if encrypted_data else 0
    
    def visualize_results(self):
        """Test sonuçlarını görselleştir"""
        if not self.results:
            return
            
        # Matplotlib figure oluştur
        fig = plt.Figure(figsize=(10, 8), dpi=100)
        
        # Şifreleme hızı grafiği
        ax1 = fig.add_subplot(221)
        protocols = list(self.results.keys())
        enc_speeds = [r["throughput_enc"] for r in self.results.values()]
        ax1.bar(protocols, enc_speeds)
        ax1.set_title('Şifreleme Hızı (KB/s)')
        ax1.set_ylabel('KB/s')
        plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')
        
        # Şifre çözme hızı grafiği
        ax2 = fig.add_subplot(222)
        dec_speeds = [r["throughput_dec"] for r in self.results.values()]
        ax2.bar(protocols, dec_speeds)
        ax2.set_title('Şifre Çözme Hızı (KB/s)')
        ax2.set_ylabel('KB/s')
        plt.setp(ax2.get_xticklabels(), rotation=45, ha='right')
        
        # Şifreleme/Çözme süresi grafiği
        ax3 = fig.add_subplot(223)
        enc_times = [r["enc_time"] for r in self.results.values()]
        dec_times = [r["dec_time"] for r in self.results.values()]
        x = np.arange(len(protocols))
        width = 0.35
        ax3.bar(x - width/2, enc_times, width, label='Şifreleme')
        ax3.bar(x + width/2, dec_times, width, label='Şifre Çözme')
        ax3.set_title('İşlem Süresi (saniye)')
        ax3.set_ylabel('Saniye')
        ax3.set_xticks(x)
        ax3.set_xticklabels(protocols)
        ax3.legend()
        plt.setp(ax3.get_xticklabels(), rotation=45, ha='right')
        
        # Veri boyutu oranı
        ax4 = fig.add_subplot(224)
        overheads = [r["overhead"] for r in self.results.values()]
        ax4.bar(protocols, overheads)
        ax4.set_title('Boyut Oranı (Şifreli/Orijinal)')
        ax4.set_ylabel('Oran')
        plt.setp(ax4.get_xticklabels(), rotation=45, ha='right')
        
        fig.tight_layout()
        
        # Canvas oluştur ve frame'e ekle
        canvas = FigureCanvasTkAgg(fig, master=self.perf_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Özet tablosu ekle
        summary_frame = ttk.Frame(self.perf_frame)
        summary_frame.pack(fill="x", padx=10, pady=10)
        
        # Tablo başlıkları
        headers = ["Protokol", "Şifreleme Hızı (KB/s)", "Şifre Çözme Hızı (KB/s)", "Boyut Artışı (%)"]
        for i, header in enumerate(headers):
            ttk.Label(summary_frame, text=header, font=("Arial", 10, "bold")).grid(
                row=0, column=i, padx=10, pady=5, sticky="w")
        
        # Tablo verileri
        for i, (protocol, result) in enumerate(self.results.items()):
            ttk.Label(summary_frame, text=protocol).grid(row=i+1, column=0, padx=10, pady=2, sticky="w")
            ttk.Label(summary_frame, text=f"{result['throughput_enc']:.2f}").grid(row=i+1, column=1, padx=10, pady=2)
            ttk.Label(summary_frame, text=f"{result['throughput_dec']:.2f}").grid(row=i+1, column=2, padx=10, pady=2)
            ttk.Label(summary_frame, text=f"{(result['overhead']-1)*100:.1f}%").grid(row=i+1, column=3, padx=10, pady=2)


# Ana uygulamayı başlat
if __name__ == "__main__":
    app = NetworkApp()
    app.mainloop()