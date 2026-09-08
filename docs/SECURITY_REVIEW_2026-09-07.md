# StarLoader ve KeyStar güvenlik düzeltmeleri — 7 Eylül 2026

Bu inceleme yerel kaynak kodu, testler ve bilinen bağımlılık açıklarını kapsar.
Canlı servislerde değişiklik, anahtar rotasyonu veya yayın yapılmadı. Bütün olası
açıkların bulunduğu garantisi değildir.

## Düzeltilenler

- **StarLoader Go:** Bearer oturumu kaldırıldı; tam 600 saniyelik Ed25519 token,
  `kid`, `app`, `product_id`, `sid`, `jti`, `nbf`, `cnf.jkt` bağları eklendi.
  ES256 DPoP doğrulaması yöntem, URI, token özeti, cihaz anahtarı ve zamanı denetler.
  PostgreSQL'de atomik tekrar kullanım engeli instance/restart sınırlarını aşar.
- **StarLoader istek sınırı:** Sahte oturum UUID'leri yerine kaynak IP'ye göre
  dakikada 10 cihaz doğrulama isteği; başka kullanıcıların kotasını doldurma önlendi.
- **StarLoader yapılandırması:** Olmayan yönetici web paneline ait artık ayarlar ve
  bozuk testler temizlendi. Go 1.26.6, pgx 5.9.2 ve güncel x/crypto/x/text sürümleri.
- **C++ istemci:** Parola/token taşıyan bütün API yönlendirmeleri reddedilir.
  KeyStar'ın istediği P-256 `device_jwk`, aynı CNG cihaz anahtarından üretilir.
- **KeyStar oturumları:** Disabled/suspended/maintenance uygulamalar mevcut
  Bearer ve DPoP oturumlarıyla erişemez. Geçersiz token'lar oturum kotası ayırmaz;
  kaynak IP başına 120/dakika giriş sınırı kriptografik doğrulama işini sınırlar.
- **KeyStar yönetici girişi:** Login/MFA, izin verilen listede olmayan Origin'i
  cookie oluşturmadan reddeder. Origin göndermeyen sunucu istemcileri korunur.
- **KeyStar token sözleşmesi:** Proof-bound token'a lisans kaydındaki gerçek
  `product_id` eklendi; istemci değeriyle eşleşmelidir.
- **KeyStar yönetim arayüzü:** CSV hücrelerindeki formüller metin olarak aktarılır.
  Çıkış isteği başarısızsa başarı gösterilmez; kullanıcı hata görür ve tekrar deneyebilir.
- **KeyStar C++ SDK:** Loopback HTTP denetiminde userinfo/port yanıltması kapatıldı.
  WinHTTP URL bileşenlerinin ayrıştırılması düzeltildi; gerçek yerel HTTP isteği test edildi.

## Doğrulama

- StarLoader Go paketleri, PostgreSQL entegrasyonları ve `go vet` başarılı.
- Aynı DPoP kanıtını 8 eşzamanlı isteğin yalnızca biri tüketebiliyor;
  ayrı Store örneği de sonraki tekrarı reddediyor.
- KeyStar Go birim/entegrasyon testleri ve `go vet` çalıştırıldı.
- StarLoader C++: çalıştırılan 19 test başarılı.
- KeyStar SDK: Windows derlemesi ve test paketi başarılı; loopback HTTP 200 doğrulandı.
- Yönetim arayüzü: 35 dosyada 124 test ve üretim derlemesi başarılı.
- Go taramalarında çağrılan kod yollarında bilinen açık bulunmadı. Tarayıcı,
  çağrılmayan modül bölümlerinde 3 uyarı bildirdi; bunlar sömürü kanıtı değildir.
- Kaynak sır taraması eşleşme bulmadı. Test veritabanı ayrı geçici PostgreSQL kümesindeydi.

## Yayına almadan önce

StarLoader'ın bağımsız Go sunucusunda önce migration **000003** uygulanmalı.
`.env.example` içindeki `LICENSE_KEY_ID`, `APPLICATION_ID`, `PRODUCT_ID`,
`PUBLIC_BASE_URL` gerçek istemci/deployment değerleriyle doldurulmalı.
Eski Bearer token'lar bilinçli olarak geçersizdir; kullanıcı yeniden giriş yapar.

KeyStar kullanırken uygulama `proof_bound` olmalı; istemcideki
`STARLOADER_PRODUCT_ID`, ilgili lisansın gerçek ürün UUID'si olmalı (`starloader`
ürün adı/slug değeri değildir). KeyStar'ın mevcut uygulama anahtarı, public URI
ve istemci TLS pinleri eşleşmelidir. Eski proof-bound token'lar yeniden giriş ister.

Korumalı üretim binary'si, canlı TLS pinleri ve canlı uçtan uca akış
bu çalışmada doğrulanmadı. Qt'nin ortak kurulumuna dokunulmadı; istemci aşağıdaki
ayrı OpenSSL kurulumuna taşındı.
Linux curl taşıyıcısının ortak URL politikası test edildi; Linux binary derlenmedi.
Çoklu NAT kullanıcıları için IP sınırları yük profiline göre değerlendirilmelidir.

## 2026-09-08 devam çalışması

- OpenSSL 3.5.8, resmi kaynak arşivinin SHA256 değeri doğrulanarak Qt'nin MinGW
  derleyicisiyle derlendi. Kaynak: https://openssl-library.org/source/
  SHA256: `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`.
- Kurulum proje altındaki `build-deps/openssl-install` klasöründedir; presetler
  burayı kullanır. Kaynak ve ikili dosyalar Git'e dahil değildir.
- CMake en az 3.5.8 gerektirir; eski 1.1.1 kurulumuyla yapılandırmanın reddedildiği
  doğrulandı. MinGW import-library önbelleği yenilenerek eski DLL/yeni başlık
  karışması giderildi. Paketleme eski 1.1.1 DLL'lerini çıktı klasöründen kaldırır.
- Yerel profil artık ürün kimliğini `starloader` ile ezmez. Presetler ürün
  kimliğini `STARLOADER_PRODUCT_ID`, üretim pinlerini `STARLOADER_TLS_SPKI_PINS`
  ortam değişkenlerinden alır. Test derlemesindeki `security-verification`
  yalnızca test değeridir; gerçek lisans UUID'si yerine kullanılamaz.
- Gerçek TPM testi: 9 başarılı, 0 hata, 0 atlama; gerçek cihaz imzası ve
  değiştirilmiş mesaj/imza reddi doğrulandı. Mevcut TPM anahtarı sıfırlanmadı.
- OpenSSL güncellemesinden sonra istemci yeniden derlendi; canlı giriş testi
  dışındaki 20 testin tamamı geçti. EXE import tablosu `libcrypto-3-x64.dll`
  gösteriyor; çıktı klasöründe yeni crypto/ssl DLL'leri var, eski 1.1.1 DLL'leri yok.
- Canlı API adresinin HTTPS sertifikası doğrulanarak bağlantı kuruldu;
  HEAD `/healthz` isteği HTTP 405 döndürdü. Bu, oturum veya SPKI pin testi değildir.
- Canlı giriş için gerçek ürün UUID'si, doğrulanmış iki TLS pini ve yerelde
  `STARLOADER_NATIVE_LIVE_EMAIL`, `STARLOADER_NATIVE_LIVE_PASSWORD`,
  `STARLOADER_NATIVE_LIVE_MAX_DEVICES` ayarları gerekir. Bunlar bulunmadığı için
  kimlik doğrulamalı canlı test çalıştırılmadı. Canlı veritabanına migration veya
  uygulama profili değişikliği uygulanmadı.
