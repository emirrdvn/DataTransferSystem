# Advanced Secure File Transfer System

Bu proje, modern ağ güvenliği gereksinimlerini karşılayan kapsamlı bir dosya transfer çözümüdür. AES/RSA şifreleme, düşük seviye IP header manipülasyonu ve detaylı ağ performans analizi özelliklerini entegre eder.

## 🚀 Özellikler

- **Güvenli Dosya Transferi**: AES (Fernet) şifreleme ile güvenli dosya aktarımı
- **Çoklu Protokol Desteği**: TCP ve UDP protokolleri üzerinden hibrit çalışma
- **Ağ Performans Analizi**: iPerf3 entegrasyonu ile bant genişliği ve gecikme ölçümü
- **Paket Yakalama**: Wireshark (tshark) ile gerçek zamanlı paket analizi
- **Güvenlik Testi**: MITM (Man-in-the-Middle) saldırı simülasyonu
- **Dinamik Tıkanıklık Kontrolü**: RTT ölçümlerine dayalı adaptif kontrol
- **Kullanıcı Dostu GUI**: Tüm işlevler için grafik arayüz

## 📋 Sistem Gereksinimleri

- Python 3.7+
- iPerf3
- Wireshark/tshark
- Scapy kütüphanesi
- Cryptography kütüphanesi

### Gerekli Python Kütüphaneleri

```bash
pip install cryptography scapy tkinter
```

## ⚙️ Kurulum

1. **Projeyi klonlayın veya indirin**

2. **Gerekli bağımlılıkları yükleyin:**
   ```bash
   pip install -r requirements.txt
   ```

3. **iPerf3'ü yükleyin:**
   - **Ubuntu/Debian:** `sudo apt-get install iperf3`
   - **CentOS/RHEL:** `sudo yum install iperf3`
   - **Windows:** [iPerf3 resmi sitesinden](https://iperf.fr/iperf-download.php) indirin
   - **macOS:** `brew install iperf3`

4. **Wireshark/tshark'ı yükleyin:**
   - **Ubuntu/Debian:** `sudo apt-get install wireshark-common`
   - **CentOS/RHEL:** `sudo yum install wireshark`
   - **Windows:** [Wireshark resmi sitesinden](https://www.wireshark.org/download.html) indirin
   - **macOS:** `brew install wireshark`

## 🔧 Kullanım

### ⚠️ Önemli Not
**Bu uygulamayı yönetici (administrator/root) olarak çalıştırmayı unutmayın!** Düşük seviye ağ işlemleri ve paket manipülasyonu için yönetici yetkileri gereklidir.

### Ana Uygulama

```bash
# Linux/macOS
sudo python main.py

# Windows (Yönetici olarak çalıştırılan Command Prompt'ta)
python main.py
```

### Sistem Bileşenleri

#### 1. Sunucu (ServerFrame)
- Dosya alım işlevlerini yönetir
- TCP (Port 5001) ve UDP (Port 5002) protokollerini destekler
- Token tabanlı kimlik doğrulama
- Otomatik şifre çözme

#### 2. İstemci (ClientFrame)
- Dosya gönderim işlevlerini yönetir
- Dinamik protokol seçimi
- RTT ölçümü ve tıkanıklık kontrolü
- Otomatik şifreleme

#### 3. Performans Testi (iPerfFrame)
- Bant genişliği ölçümü
- Gecikme analizi
- İstemci ve sunucu modları

#### 4. Paket Analizi (WiresharkFrame)
- Ağ arayüzü seçimi
- Gerçek zamanlı paket yakalama
- Filtreleme seçenekleri

#### 5. Güvenlik Testi (MITMFrame)
- ARP spoofing simülasyonu
- MITM saldırı testi
- Otomatik ARP tablosu düzeltme

## 🔐 Güvenlik Özellikleri

### Şifreleme
- **AES (Fernet)**: Simetrik şifreleme
- **Rastgele Anahtar Üretimi**: Her transfer için benzersiz anahtar
- **SHA-256 Hash**: Veri bütünlüğü kontrolü

### Kimlik Doğrulama
- Token tabanlı doğrulama (`secret_token_123`)
- Yetkisiz erişim engelleme

### Güvenlik Testleri
- MITM saldırı simülasyonu
- ARP spoofing koruması
- Şifrelenmiş trafik analizi

## 📊 Performans Özellikleri

### TCP Avantajları
- Güvenilir veri transferi
- ACK mekanizması
- Hata düzeltme

### UDP Avantajları
- Yüksek hız
- Düşük gecikme
- Paket sıralama mekanizması

### Hibrit Yaklaşım
- Otomatik protokol seçimi
- Ağ koşullarına adaptasyon
- Optimal performans

## 🔧 Yapılandırma

### Varsayılan Ayarlar
- **TCP Port**: 5001
- **UDP Port**: 5002
- **Kimlik Doğrulama Token**: `secret_token_123`
- **Chunk Boyutu**: 1024 bytes
- **RTT Eşiği**: 100ms

### Özelleştirme
Ayarları değiştirmek için ilgili sınıflardaki port numaralarını ve token değerlerini düzenleyebilirsiniz.

## 🚧 Bilinen Kısıtlamalar

- **Tek Kullanıcı**: Çoklu istemci desteği bulunmaz
- **Platform Bağımlılığı**: Bazı özellikler root/admin yetkisi gerektirir
- **UDP Güvenilirlik**: Paket kaybında yeniden gönderim yok
- **Temel GUI**: Kullanıcı arayüzü geliştirilebilir

## 🔮 Gelecek Geliştirmeler

- RSA asimetrik şifreleme
- Çoklu istemci desteği
- Gelişmiş saldırı simülasyonları
- SQLite veritabanı entegrasyonu
- Gelişmiş GUI tasarımı

## 📝 Kullanım Örnekleri

### Basit Dosya Transferi
1. Sunucu modülünü başlatın
2. TCP veya UDP dinlemeyi etkinleştirin
3. İstemci modülünde dosya seçin
4. Transfer protokolünü seçin
5. Gönder butonuna tıklayın

### Performans Testi
1. iPerf modülünü açın
2. Sunucu IP adresini girin
3. Test tipini seçin (bant genişliği/gecikme)
4. Testi başlatın

### Güvenlik Testi
1. MITM modülünü açın
2. Hedef IP ve Gateway IP girin
3. Saldırıyı başlatın
4. Trafik yakalama sonuçlarını analiz edin

## 🤝 Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'inizi push edin (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun

## 📄 Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Ticari kullanım için uygun değildir.

## ⚠️ Sorumluluk Reddi

Bu yazılım yalnızca eğitim ve araştırma amaçlıdır. Kötü niyetli kullanım yasaktır. Geliştiriciler herhangi bir kötüye kullanımından sorumlu değildir.

## 📞 İletişim

Proje ile ilgili sorularınız için GitHub Issues bölümünü kullanabilirsiniz.

---

**Not**: Bu sistem test ortamında kullanılmak üzere tasarlanmıştır. Üretim ortamında kullanmadan önce kapsamlı güvenlik testleri yapılmalıdır.
