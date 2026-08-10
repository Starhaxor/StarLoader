# Login, HWID Obtainer ve Go Backend Tasarımı

## Amaç

Windows 10/11 üzerinde çalışan iki ayrı Qt 6 uygulaması ve bunları destekleyen Go/PostgreSQL lisans servisi oluşturulacaktır. HWID Obtainer cihaz kimliği sinyallerini toplar ve tanılama çıktısı üretir. License Client kullanıcı, lisans ve TPM tabanlı cihaz doğrulamasını tamamlamadan uygulamayı açmaz.

İlk sürüm çalışan çekirdek sistemi hedefler. Admin web paneli, Redis, offline grace period, refresh token ve sertifika pinning bu sürümün kapsamı dışındadır.

## Teknik Sınırlar

- İstemciler Windows 10/11, Qt 6 Widgets ve C++20 kullanır.
- Production doğrulaması TPM 2.0 olmadan kapalı biçimde başarısız olur; yazılım anahtarına düşülmez.
- Backend Go ile yazılır ve PostgreSQL kullanır.
- Yerel PostgreSQL Docker Compose ile başlatılır.
- Tüm production API trafiği HTTPS arkasında çalıştırılmak üzere tasarlanır. Yerel geliştirme HTTP kullanabilir.
- Parolalar Argon2id ile özetlenir.
- Lisans anahtarları ve donanım sinyalleri sunucuya ait ayrı HMAC-SHA256 anahtarlarıyla korunur.
- Oturum token'ları Ed25519 ile imzalanır ve kısa ömürlüdür.
- Request ID ile `users`, `licenses`, `devices`, `auth_sessions` ve `device_challenges` birincil anahtarları UUIDv7 kullanır; veritabanı başka UUID sürümlerini reddeder.

## Depo Yapısı ve Bileşenler

### `shared`

Her iki Qt uygulamasının kullandığı statik C++ kitaplığıdır. Windows kayıt defterinden MachineGuid, raw SMBIOS tablosundan sistem UUID/anakart/BIOS bilgisi ve sistem diskinin seri numarasını toplar. TPM üzerinde kalıcı ECDSA P-256 anahtarı oluşturur, public key'i dışa aktarır ve challenge imzalar. Bütün alanları ortak bir algoritmayla normalize edip SHA-256 fingerprint üretir.

### `hwid-obtainer`

Bağımsız Qt 6 tanılama uygulamasıdır. SMBIOS UUID, anakart seri numarası, BIOS seri numarası, sistem disk seri numarası, MachineGuid, TPM public key hash ve final fingerprint alanlarını gösterir. Toplama işlemi UI thread'ini bloklamaz. Yenileme, fingerprint kopyalama, JSON dışa aktarma ve yerel TPM imza doğrulama işlemleri sunar.

### `license-client`

Email, parola ve lisans anahtarını alan Qt 6 login uygulamasıdır. Ortak kitaplıkla cihaz kimliğini toplar, login challenge'ını alır, challenge'ı TPM ile imzalar ve cihaz doğrulama çağrısını yapar. Backend token'ının Ed25519 imzası ile issuer, audience, product, expiration, license ve device claim'lerini doğrulamadan authenticated durumuna geçmez.

### `backend`

Tek Go binary'si HTTP API ve yönetim alt komutlarını içerir. Katmanlar HTTP taşıma, uygulama servisleri, güvenlik yardımcıları ve PostgreSQL repository sınırlarıyla ayrılır. API, kullanıcı/lisans doğrulama, challenge üretme-tüketme, ECDSA cihaz kanıtı, aktivasyon, cihaz eşleştirme ve oturum token'ı üretimini gerçekleştirir.

Yönetim komutları:

- `server admin create-user`: email ve güvenli biçimde alınan parola ile kullanıcı oluşturur.
- `server admin create-license`: kullanıcı, ürün, süre ve cihaz limiti için kriptografik rastgele lisans üretir. Açık anahtar yalnızca bir kez stdout'a yazılır.

### `deploy`, `backend/migrations` ve `server-contract`

`deploy` yerel PostgreSQL Docker Compose tanımını ve örnek ortam ayarlarını içerir. `backend/migrations` Go binary'sine gömülen sürümlü SQL migration'larını, `server-contract` ise Qt/Go arasında paylaşılan API sözleşmesini içerir.

## Donanım Kimliği

Toplanan alanlar:

- TPM public key ve SHA-256 özeti
- SMBIOS System UUID
- Motherboard Serial
- BIOS Serial
- Windows'un kurulu olduğu fiziksel sistem diskinin seri numarası
- Windows MachineGuid
- CPU mimarisi ve host adı yalnızca tanılama amacıyla

Metin alanları trim edilir, büyük harfe çevrilir; boşluk, `-`, `{` ve `}` karakterleri kaldırılır. Fingerprint girdisi alanların sabit sırada `|` ile ayrılmasıyla oluşturulur ve SHA-256 özeti büyük harfli hexadecimal olarak döndürülür. Aynı normalizasyon kodu her iki istemcide ortak kitaplıktan gelir.

TPM anahtarı Microsoft Platform Crypto Provider içinde `StarLoader.DeviceIdentity.v1` adıyla kalıcı ECDSA P-256 anahtarıdır. Private key dışa aktarılmaz. Challenge önce SHA-256 ile özetlenir, ardından TPM anahtarıyla imzalanır.

## Login ve Cihaz Doğrulama Akışı

1. İstemci donanım sinyallerini toplar ve TPM anahtarını hazırlar.
2. İstemci `POST /v1/auth/login` çağrısına email, parola, lisans anahtarı ve fingerprint gönderir.
3. Backend IP başına dakikada en fazla beş giriş denemesi uygular; kullanıcı, parola, durum, lisans, ürün ve süreyi doğrular.
4. Backend 32 kriptografik rastgele bayttan oluşan ve iki dakika geçerli bir challenge ile geçici session oluşturur. Veritabanında challenge'ın kendisi değil SHA-256 özeti tutulur.
5. İstemci challenge'ı TPM anahtarıyla imzalar ve `POST /v1/device/verify` çağrısına session ID, imza, TPM public key ve donanım alanlarını gönderir.
6. Backend session başına dakikada on doğrulama denemesi uygular. Transaction içinde session ve challenge'ı kilitler; süresini, kullanılmamış olmasını ve ECDSA imzasını doğrular.
7. Backend donanım değerlerini ayrı hardware pepper ile HMAC-SHA256 özetleyerek karşılaştırır. Ham seri numaraları kalıcı olarak saklanmaz.
8. Lisansa bağlı aktif cihaz yoksa ve limit uygunsa cihaz kaydı oluşturulur. Kayıt varsa cihaz skoru hesaplanır.
9. Doğrulama başarılı olduğunda challenge aynı transaction içinde tüketilir ve cihazın `last_seen_at` değeri güncellenir.
10. Backend bir saat geçerli Ed25519 imzalı uygulama token'ı döndürür.
11. Qt istemcisi token'ı gömülü public key ile doğrular ve yalnızca tüm claim kontrolleri başarılıysa authenticated durumuna geçer.

## Cihaz Skoru ve Aktivasyon

Skorlar dokümandaki başlangıç değerlerini kullanır:

- TPM public key: 50
- SMBIOS UUID: 20
- Motherboard Serial: 15
- BIOS Serial: 5
- System Disk Serial: 5
- MachineGuid: 5

Toplam skor en az 70 ise kayıt aynı cihaz sayılır. TPM eşleşmesi tek başına yeterli değildir. İlk aktivasyon `max_devices` sınırı altında yeni kayıt oluşturur. Limit doluyken eşleşmeyen cihaz `DEVICE_LIMIT_REACHED`, revoked cihaz `DEVICE_REVOKED` hatası alır. TPM reset veya anakart değişimi yeni cihaz/reset süreci gerektirir.

## Veri Modeli

PostgreSQL migration'ları en az şu tabloları oluşturur:

- `users`: UUIDv7, normalize email, Argon2id password hash, status, timestamps.
- `licenses`: UUIDv7, license HMAC, user, product, status, max devices, expiry, timestamps.
- `devices`: UUIDv7, user/license, TPM public key ve hash, HMAC'lenmiş donanım alanları, fingerprint, status, timestamps.
- `auth_sessions`: UUIDv7, user/license, pending/verified/expired durumu, expiry ve timestamps.
- `device_challenges`: UUIDv7, session, challenge hash, expiry, consumed timestamp ve created timestamp.

Status alanları veritabanı constraint'leriyle sınırlandırılır. İlişki ve lookup alanları indekslenir. Migration'lar ileri ve geri yönlü dosyalar halinde sürümlenir.

## API Sözleşmesi

İlk sürüm endpoint'leri:

- `GET /healthz`
- `POST /v1/auth/login`
- `POST /v1/device/verify`

Tüm cevaplar `X-Request-ID` header'ı taşır. Başarısız cevap gövdesi `{ "ok": false, "code": "...", "message": "...", "request_id": "..." }` biçimindedir. Desteklenen hata kodları `INVALID_REQUEST`, `INVALID_CREDENTIALS`, `LICENSE_NOT_FOUND`, `LICENSE_EXPIRED`, `LICENSE_REVOKED`, `DEVICE_LIMIT_REACHED`, `DEVICE_REVOKED`, `CHALLENGE_EXPIRED`, `CHALLENGE_CONSUMED`, `INVALID_DEVICE_SIGNATURE`, `RATE_LIMITED` ve `SERVER_ERROR` değerleridir.

İstek gövdelerinin boyutu sınırlanır, bilinmeyen JSON alanları reddedilir ve gerekli alanlar açıkça doğrulanır. HTTP status kodları hata türleriyle tutarlı kullanılır. Parola, açık lisans anahtarı, token, TPM public key'in tamamı ve ham donanım değerleri loglanmaz.

## Oturum Token'ı

Token Ed25519 ile imzalanır ve `sub`, `license_id`, `device_id`, `product`, `features`, `iss`, `aud`, `iat` ve `exp` claim'lerini taşır. Issuer ve audience yapılandırmadan gelir. Private signing key yalnızca backend'de bulunur. Qt istemcisine sadece public key derleme sırasında verilir. Anahtar veya gerekli güvenlik yapılandırması eksikse backend başlamaz.

## UI ve Durum Yönetimi

HWID Obtainer eksik alanları saklamaz; her alan için başarı veya hata durumu gösterir. TPM bulunmadığında fingerprint tanılama amacıyla hesaplanabilir fakat TPM testi başarısız olur ve bu kimlik login için geçerli sayılmaz.

License Client `LoggedOut`, `CollectingDevice`, `Authenticating`, `WaitingForDeviceChallenge`, `VerifyingDevice`, `Authenticated` ve `Failed` durumlarını kullanır. Asenkron işlem boyunca form tekrar gönderime kapatılır. Structured backend hata kodları kullanıcı dostu, sır vermeyen metinlere çevrilir. Teknik ayrıntı ve request ID destek amacıyla ayrı gösterilebilir.

## Güvenlik ve Hata Yönetimi

- Challenge tek kullanımlık ve iki dakika geçerlidir; replay transaction ve row lock ile engellenir.
- Login IP başına 5/dakika, device verify session başına 10/dakika ile sınırlandırılır.
- Secret değerler yalnızca environment veya mounted secret üzerinden alınır; örnek dosyada gerçek secret bulunmaz.
- API panic recovery uygular ancak dışarıya stack trace döndürmez.
- PostgreSQL bağlantı hataları sağlık kontrolüne yansır.
- İstemci ağ timeout'u, HTTP status, JSON şeması ve structured error code kontrolü yapar.
- Production client HTTP fallback yapmaz.

## Test Stratejisi

C++ testleri normalizasyon, fingerprint determinismi, SMBIOS parser sınırları ve eksik sinyal davranışını kapsar. TPM destekli Windows ortamında rastgele challenge imzası doğrulanır; değiştirilmiş challenge ve değiştirilmiş signature reddedilir.

Go birim testleri Argon2id doğrulama, HMAC determinismi, lisans normalizasyonu, cihaz skor eşiği, token claim'leri ve hata eşlemelerini kapsar. PostgreSQL entegrasyon testleri başarılı login/ilk aktivasyon, hatalı parola, süresi dolmuş veya revoked lisans, challenge expiry, challenge replay, geçersiz ECDSA imzası, mevcut cihaz eşleşmesi, cihaz limiti ve revoked cihaz senaryolarını çalıştırır.

Uçtan uca kabul senaryosu şöyledir: Docker Compose ile PostgreSQL başlatılır; migration uygulanır; yönetim komutlarıyla kullanıcı ve lisans oluşturulur; gerçek Windows TPM'li Qt istemcisi login olur; backend cihazı aktive eder ve istemci imzalı token'ı doğrular.

## Tamamlanma Ölçütleri

- İki ayrı Qt executable ortak `shared` kitaplığını kullanarak derlenir.
- HWID Obtainer dokümandaki tüm ana donanım alanlarını gösterir, fingerprint kopyalar, JSON dışa aktarır ve üç TPM testini çalıştırır.
- Yönetim komutları açık parola veya lisans değerini veritabanına yazmadan kullanıcı/lisans oluşturur.
- Login ve device verify endpoint'leri gerçek PostgreSQL üzerinde çalışır.
- Challenge tekrar kullanılamaz ve iki dakikadan sonra reddedilir.
- Cihaz skoru ile aktivasyon limiti uygulanır.
- Production login TPM yokken reddedilir.
- Qt istemcisi doğrulanmamış veya süresi geçmiş token ile authenticated durumuna geçmez.
- C++ ve Go testleri ile uçtan uca kabul akışı başarılıdır.
