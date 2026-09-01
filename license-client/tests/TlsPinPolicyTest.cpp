#include "security/TlsPinPolicy.h"

#include <QCryptographicHash>
#include <QSslCertificate>
#include <QTest>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <memory>

namespace {
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

struct CertificateFixture {
    QSslCertificate certificate;
    QByteArray pin;
};

void requireFixtureStep(bool condition, const char *step)
{
    if (!condition) qFatal("X.509 fixture generation failed at %s", step);
}

CertificateFixture makeCertificate(qint64 serial)
{
    EVP_PKEY_CTX *rawContext = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    requireFixtureStep(rawContext != nullptr, "context");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(rawContext, EVP_PKEY_CTX_free);
    requireFixtureStep(EVP_PKEY_keygen_init(context.get()) == 1, "keygen init");
    requireFixtureStep(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) == 1,
                       "curve selection");
    EVP_PKEY *rawKey = nullptr;
    requireFixtureStep(EVP_PKEY_keygen(context.get(), &rawKey) == 1, "keygen");
    PkeyPtr key(rawKey, EVP_PKEY_free);

    X509Ptr certificate(X509_new(), X509_free);
    requireFixtureStep(certificate != nullptr, "certificate");
    requireFixtureStep(X509_set_version(certificate.get(), 2) == 1, "version");
    requireFixtureStep(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) == 1, "serial");
    requireFixtureStep(X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0) != nullptr, "not before");
    requireFixtureStep(X509_gmtime_adj(X509_get_notAfter(certificate.get()), 3600) != nullptr, "not after");
    requireFixtureStep(X509_set_pubkey(certificate.get(), key.get()) == 1, "public key");
    X509_NAME *name = X509_get_subject_name(certificate.get());
    requireFixtureStep(name != nullptr, "subject");
    requireFixtureStep(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                                  reinterpret_cast<const unsigned char *>("api.example.test"),
                                                  -1, -1, 0) == 1,
                       "subject name");
    requireFixtureStep(X509_set_issuer_name(certificate.get(), name) == 1, "issuer");
    requireFixtureStep(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0, "sign");

    unsigned char *der = nullptr;
    const int derLength = i2d_X509(certificate.get(), &der);
    requireFixtureStep(derLength > 0, "certificate DER");
    const QByteArray certificateDer(reinterpret_cast<const char *>(der), derLength);
    OPENSSL_free(der);

    X509_PUBKEY *publicKey = X509_get_X509_PUBKEY(certificate.get());
    requireFixtureStep(publicKey != nullptr, "SPKI");
    unsigned char *spkiDer = nullptr;
    const int spkiLength = i2d_X509_PUBKEY(publicKey, &spkiDer);
    requireFixtureStep(spkiLength > 0, "SPKI DER");
    const QByteArray spki(reinterpret_cast<const char *>(spkiDer), spkiLength);
    OPENSSL_free(spkiDer);

    return {
        QSslCertificate(certificateDer, QSsl::Der),
        QByteArrayLiteral("sha256/")
            + QCryptographicHash::hash(spki, QCryptographicHash::Sha256).toBase64(),
    };
}
} // namespace

class TlsPinPolicyTest final : public QObject
{
    Q_OBJECT
private slots:
    void acceptsCurrentAndStagedNextPins();
    void rejectsInvalidPolicyAndRequestBindings();
    void permitsOnlyNumericLoopbackHttpInLocalDevelopment();
};

void TlsPinPolicyTest::acceptsCurrentAndStagedNextPins()
{
    const CertificateFixture current = makeCertificate(1);
    const CertificateFixture next = makeCertificate(2);
    const TlsPinPolicy policy(QStringLiteral("api.example.test"),
                              {current.pin, next.pin}, false);

    QVERIFY(policy.isValid());
    QVERIFY(policy.verify(QUrl(QStringLiteral("https://api.example.test/v1/me")),
                          current.certificate));
    QVERIFY(policy.verify(QUrl(QStringLiteral("https://api.example.test/v1/me")),
                          next.certificate));
}

void TlsPinPolicyTest::rejectsInvalidPolicyAndRequestBindings()
{
    const CertificateFixture current = makeCertificate(3);
    const CertificateFixture next = makeCertificate(4);
    const CertificateFixture wrong = makeCertificate(5);
    const QUrl expected(QStringLiteral("https://api.example.test/v1/me"));

    const TlsPinPolicy policy(QStringLiteral("api.example.test"),
                              {current.pin, next.pin}, false);
    QVERIFY(!policy.verify(QUrl(QStringLiteral("https://redirect.example.test/v1/me")),
                           current.certificate));
    QVERIFY(!policy.verify(expected, wrong.certificate));
    QVERIFY(!policy.verify(expected, QSslCertificate{}));

    QVERIFY(!TlsPinPolicy(QStringLiteral("api.example.test"), {}, false).isValid());
    QVERIFY(!TlsPinPolicy(QStringLiteral("api.example.test"),
                          {QByteArrayLiteral("not-a-pin"), next.pin}, false).isValid());
    QVERIFY(!TlsPinPolicy(QStringLiteral("api.example.test"),
                          {current.pin, current.pin}, false).isValid());
    QVERIFY(!TlsPinPolicy(QStringLiteral("api.example.test"),
                          {current.pin, next.pin, wrong.pin}, false).isValid());
}

void TlsPinPolicyTest::permitsOnlyNumericLoopbackHttpInLocalDevelopment()
{
    const TlsPinPolicy local(QStringLiteral("127.0.0.1"), {}, true);
    QVERIFY(local.isValid());
    QVERIFY(local.verify(QUrl(QStringLiteral("http://127.0.0.1:8080/v1/me")),
                         QSslCertificate{}));
    QVERIFY(!local.verify(QUrl(QStringLiteral("http://localhost:8080/v1/me")),
                          QSslCertificate{}));
    QVERIFY(!local.verify(QUrl(QStringLiteral("http://127.0.0.2:8080/v1/me")),
                          QSslCertificate{}));
}

QTEST_MAIN(TlsPinPolicyTest)
#include "TlsPinPolicyTest.moc"
