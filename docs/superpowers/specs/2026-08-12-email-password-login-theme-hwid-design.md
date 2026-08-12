# E-posta/Parola Girişi, Tema ve HWID Diyaloğu Tasarımı

## Amaç

License Client girişini yalnızca e-posta ve paroladan oluşan sade bir akışa dönüştürmek, kullanıcının StarLoader lisansını backend tarafında otomatik seçmek, ilk doğrulanan cihazı mevcut güvenli cihaz akışıyla otomatik kaydetmek ve giriş ekranından yalnızca hash'lenmiş HWID bilgisini gösteren bir diyaloğa erişim sağlamaktır. Adwaita Dark tema kaynağının her Qt executable içinde güvenilir biçimde yüklenmesi de bu değişikliğin parçasıdır.

## Kararlar ve Kapsam

- Bir kullanıcı, bir ürün için yalnızca bir lisansa sahip olabilir. Bu kural PostgreSQL'de `(user_id, product)` unique constraint'iyle uygulanır.
- Login ekranı lisans anahtarı veya cihaz kimliği istemez.
- Açık lisans anahtarı login API'sine gönderilmez. `license_hmac` mevcut yönetim ve veri modeli uyumluluğu için korunur.
- Backend, doğrulanmış kullanıcının yapılandırılmış StarLoader ürününe ait tek lisansını bulur ve durum/süre kontrollerini uygular.
- İlk cihaz kaydı için yeni bir kullanıcı adımı eklenmez. Mevcut `/v1/device/verify` akışı eşleşmeyen cihazı limit uygunsa otomatik oluşturur.
- HWID diyaloğu ham donanım seri numaralarını göstermez; login sırasında kullanılan aynı `HardwareIdentity::finalFingerprint` değerini gösterir.
- Bağımsız `hwid-obtainer` tanılama executable'ı korunur. License Client bu aracı açmaz veya onun ayrıntılı UI'ını gömmez.
- Admin paneli, lisans yenileme UX'i ve cihaz reset/recovery akışı kapsam dışındadır.

## Login Arayüzü

`license-client/ui/LoginWindow.ui` şu görünür öğeleri içerir:

1. Logo, başlık ve kısa açıklama.
2. E-posta alanı.
3. Parola alanı.
4. Giriş düğmesi.
5. Kullanıcı dostu durum ve destek kodu etiketleri.
6. Kartın altında tıklanabilir `HWID'yi görüntüle` etiketi.

`licenseKeyLineEdit` ve `deviceIdLineEdit` kaldırılır. Tab sırası yalnızca e-posta, parola, giriş düğmesi ve HWID bağlantısını kapsar. Kimlik doğrulama devam ederken e-posta, parola ve giriş düğmesi devre dışı bırakılır. HWID bağlantısı modal diyalog açıkken ikinci kez çalıştırılamaz.

## Tema Yükleme

Tema dosyası `shared/theme/theme.qrc` içinden gelir. `DeviceIdentityShared` statik kitaplık olduğu için resource object'inin linker tarafından atılmaması garanti edilmelidir. `ThemeManager` tema kaynağını `Q_INIT_RESOURCE(theme)` ile süreç başına bir kez başlatır ve ardından `:/theme/AdwaitaDark.qss` içeriğini uygulama stylesheet'i olarak yükler.

Tema yüklenemezse uygulama sessizce teması yok saymaz. Geliştirme/test ortamında boş stylesheet test hatasıdır; runtime'da tanı koymayı kolaylaştıran bir Qt warning üretilir. License Client, HWID diyaloğu ve HWID Obtainer aynı global stylesheet'i miras alır. UI dosyalarına ikinci bir büyük inline stylesheet eklenmez.

## API ve Backend Lisans Seçimi

`POST /v1/auth/login` istek gövdesi:

```json
{
  "email": "person@example.com",
  "password": "secret",
  "device_fingerprint": "UPPERCASE_SHA256_HEX"
}
```

`license_key` artık kabul edilmez; JSON decoder bilinmeyen alanları reddetmeye devam eder. Login servisi şu sırayı izler:

1. E-postayı normalize eder ve kullanıcıyı bulur.
2. Parolayı mevcut sabit-zaman yaklaşımını koruyarak doğrular.
3. Repository üzerinden `(user_id, configured_product)` ile tek lisansı bulur.
4. Lisans yoksa `LICENSE_NOT_FOUND`, revoked ise `LICENSE_REVOKED`, süresi dolmuşsa `LICENSE_EXPIRED` döndürür.
5. Geçerli lisansın ID'siyle pending session ve challenge oluşturur.

Repository arayüzü açık lisans anahtarı HMAC'iyle lookup yapmak yerine kullanıcı ve ürünle lookup yapar. Yeni migration mevcut veride aynı kullanıcı+ürün için birden fazla lisans varsa constraint eklemeyi reddeder; veri sessizce seçilmez veya silinmez. Admin `create-license` komutu duplicate kullanıcı+ürün girişini anlaşılır bir hatayla reddeder. Yenileme, ileride mevcut lisans kaydının güncellenmesiyle yapılmalıdır.

## Cihaz Kaydı ve Doğrulama

İstemci login öncesinde mevcut `SystemHardwareCollector` ile donanım sinyallerini toplar, final fingerprint'i üretir ve TPM anahtarını hazırlar. Login challenge alındıktan sonra mevcut TPM imza akışı değişmeden devam eder.

`/v1/device/verify` davranışı korunur:

- Kayıtlı cihaz yeterli skorla eşleşirse `last_seen_at` ve korunan sinyaller güncellenir.
- Eşleşme yoksa ve aktif cihaz sayısı `max_devices` değerinin altındaysa cihaz otomatik oluşturulur.
- Limit doluysa `DEVICE_LIMIT_REACHED`, revoked TPM cihazıysa `DEVICE_REVOKED` döner.

Bu nedenle ilk girişte ayrıca “HWID kaydet” düğmesi veya endpoint'i bulunmaz.

## HWID Diyaloğu

Login kartının altındaki bağlantı `license-client/ui/HwidDialog.ui` ile tanımlanan modal pencereyi açar. Diyalog başlangıçta `HWID hesaplanıyor…` durumu gösterir ve donanım toplamayı UI thread'i dışında gerçekleştirir. Başarı halinde yalnızca büyük harfli final fingerprint görünür; kopyala ve kapat işlemleri kullanılabilir. Ham SMBIOS, disk, BIOS, MachineGuid veya TPM public key değerleri gösterilmez.

Diyalog, giriş akışıyla aynı `IHardwareCollector` uygulamasını kullanır; `QSysInfo::machineUniqueId()` tabanlı mevcut alternatif HWID algoritması kaldırılır. Böylece kullanıcıya gösterilen değer ile sunucuya gönderilen fingerprint farklılaşamaz. Toplama başarısızsa teknik ayrıntı sızdırmayan bir mesaj gösterilir ve kopyalama kapalı kalır. Diyalog kapanırken devam eden future güvenli biçimde tamamlanır veya sonucu yok sayılır.

## Güvenlik ve Hata Davranışı

- Parola, ham donanım sinyalleri, TPM private key ve session token loglanmaz.
- Lisansın istemci tarafından bilinmesine gerek kalmaz; lisans sahipliği backend'de authenticated user ve product üzerinden belirlenir.
- Kullanıcının devre dışı olması veya lisansın geçersiz olması mevcut dış hata semantiğini korur.
- Çoklu lisans verisi bir tanesini rastgele seçmez; migration/admin işlemi açık hata verir.
- HWID diyaloğu yalnızca tek yönlü fingerprint gösterir ve ham sinyalleri dışarı çıkarmaz.

## Test Stratejisi

### C++/Qt

- `ThemeManager::themeStyleSheet()` boş değildir ve beklenen Login/HWID selector'larını içerir.
- `ThemeManager::applyTheme()` global stylesheet'i uygular.
- Login UI testi `licenseKeyLineEdit` ve `deviceIdLineEdit` bulunmadığını; e-posta, parola, giriş ve HWID bağlantısının bulunduğunu doğrular.
- `AuthManager::login(email, password)` API isteğine fingerprint ekler ve lisans anahtarı taşımaz.
- HWID diyaloğu fake collector ile verilen final fingerprint'i gösterir, ham alanları göstermez ve kopyalama davranışını korur.
- Collector hatası diyalogda güvenli hata durumuna dönüşür.

### Go

- Login HTTP testi `license_key` olmadan başarılı parse ve servis çağrısını doğrular; eski `license_key` alanını unknown field olarak reddeder.
- Login servis testleri kullanıcı+ürün lisans lookup'ını, lisans yok/revoked/expired durumlarını ve geçerli challenge üretimini kapsar.
- Store/integration testleri `(user_id, product)` tek lisans constraint'ini ve lookup'ı doğrular.
- Mevcut ilk cihaz oluşturma, cihaz eşleştirme, cihaz limiti ve revoked cihaz testleri korunur.
- Blackbox smoke testi yeni üç alanlı login sözleşmesini kullanır.

## Tamamlanma Ölçütleri

- Login penceresinde yalnızca e-posta ve parola giriş alanları görünür.
- Kullanıcı lisans anahtarı girmeden geçerli tek StarLoader lisansıyla login olabilir.
- İlk cihaz kullanıcı etkileşimi olmadan kaydedilir; sonraki girişte eşleştirilir.
- HWID bağlantısı aynı final fingerprint'i gösteren temalı diyaloğu açar.
- Adwaita Dark stylesheet her iki Qt executable'da boş olmayan biçimde yüklenir.
- C++ derlemesi, CTest paketi, Go testleri ve ilgili PostgreSQL entegrasyon testleri başarılıdır.
