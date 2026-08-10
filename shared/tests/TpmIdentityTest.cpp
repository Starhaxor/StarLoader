#include "security/EcdsaSignature.h"
#include "security/TpmIdentity.h"
#include "hardware/HardwareCollector.h"

#include <QCryptographicHash>
#include <QtTest>

#ifdef Q_OS_WIN
#include <windows.h>
#include <bcrypt.h>

namespace {

class BCryptAlgorithmHandle final
{
public:
    ~BCryptAlgorithmHandle()
    {
        if (handle_)
            BCryptCloseAlgorithmProvider(handle_, 0);
    }

    BCRYPT_ALG_HANDLE *put() { return &handle_; }
    BCRYPT_ALG_HANDLE get() const { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class BCryptKeyHandle final
{
public:
    ~BCryptKeyHandle()
    {
        if (handle_)
            BCryptDestroyKey(handle_);
    }

    BCRYPT_KEY_HANDLE *put() { return &handle_; }
    BCRYPT_KEY_HANDLE get() const { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
};

struct SignatureFixture
{
    QByteArray publicBlob;
    QByteArray challenge;
    QByteArray signature;
};

SignatureFixture makeSoftwareSignatureFixture()
{
    BCryptAlgorithmHandle algorithm;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            algorithm.put(), BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0))) {
        return {};
    }

    BCryptKeyHandle key;
    if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(algorithm.get(), key.put(), 256, 0))
        || !BCRYPT_SUCCESS(BCryptFinalizeKeyPair(key.get(), 0))) {
        return {};
    }

    ULONG publicBlobSize = 0;
    if (!BCRYPT_SUCCESS(BCryptExportKey(
            key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &publicBlobSize, 0))) {
        return {};
    }

    SignatureFixture fixture;
    fixture.publicBlob.resize(static_cast<qsizetype>(publicBlobSize));
    if (!BCRYPT_SUCCESS(BCryptExportKey(
            key.get(),
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            reinterpret_cast<PUCHAR>(fixture.publicBlob.data()),
            publicBlobSize,
            &publicBlobSize,
            0))) {
        return {};
    }
    fixture.publicBlob.resize(static_cast<qsizetype>(publicBlobSize));

    fixture.challenge = QByteArray(32, '\x2a');
    const QByteArray digest = QCryptographicHash::hash(fixture.challenge, QCryptographicHash::Sha256);

    ULONG signatureSize = 0;
    if (!BCRYPT_SUCCESS(BCryptSignHash(
            key.get(),
            nullptr,
            reinterpret_cast<PUCHAR>(const_cast<char *>(digest.constData())),
            static_cast<ULONG>(digest.size()),
            nullptr,
            0,
            &signatureSize,
            0))) {
        return {};
    }

    fixture.signature.resize(static_cast<qsizetype>(signatureSize));
    if (!BCRYPT_SUCCESS(BCryptSignHash(
            key.get(),
            nullptr,
            reinterpret_cast<PUCHAR>(const_cast<char *>(digest.constData())),
            static_cast<ULONG>(digest.size()),
            reinterpret_cast<PUCHAR>(fixture.signature.data()),
            signatureSize,
            &signatureSize,
            0))) {
        return {};
    }
    fixture.signature.resize(static_cast<qsizetype>(signatureSize));
    return fixture;
}

} // namespace
#endif

class TpmIdentityTest final : public QObject
{
    Q_OBJECT

private slots:
    void verifierAcceptsValidCngP256Signature();
    void verifierRejectsWrongChallengeTamperingAndMalformedInputs();
    void signatureBindsChallenge();
};

void TpmIdentityTest::verifierAcceptsValidCngP256Signature()
{
#ifdef Q_OS_WIN
    const SignatureFixture fixture = makeSoftwareSignatureFixture();
    QVERIFY(!fixture.publicBlob.isEmpty());
    QVERIFY(!fixture.signature.isEmpty());
    QVERIFY(EcdsaSignature::verifyCngP256(
        fixture.publicBlob, fixture.challenge, fixture.signature));
#else
    QSKIP("CNG verifier is Windows-only");
#endif
}

void TpmIdentityTest::verifierRejectsWrongChallengeTamperingAndMalformedInputs()
{
#ifdef Q_OS_WIN
    const SignatureFixture fixture = makeSoftwareSignatureFixture();
    QVERIFY(!fixture.publicBlob.isEmpty());
    QVERIFY(!fixture.signature.isEmpty());

    QByteArray changedSignature = fixture.signature;
    changedSignature[0] ^= 1;
    QVERIFY(!EcdsaSignature::verifyCngP256(
        fixture.publicBlob, fixture.challenge + "x", fixture.signature));
    QVERIFY(!EcdsaSignature::verifyCngP256(
        fixture.publicBlob, fixture.challenge, changedSignature));
    QVERIFY(!EcdsaSignature::verifyCngP256(
        fixture.publicBlob.chopped(1), fixture.challenge, fixture.signature));
    QVERIFY(!EcdsaSignature::verifyCngP256(
        fixture.publicBlob, QByteArrayView(), fixture.signature));
    QVERIFY(!EcdsaSignature::verifyCngP256(
        fixture.publicBlob, fixture.challenge, fixture.signature.chopped(1)));
#else
    QSKIP("CNG verifier is Windows-only");
#endif
}

void TpmIdentityTest::signatureBindsChallenge()
{
    if (!TpmIdentity::isAvailable())
        QSKIP("TPM 2.0 unavailable on test host");

    QString error;
    QVERIFY2(TpmIdentity::ensureKey(&error), qPrintable(error));

    const QByteArray challenge(32, '\x2a');
    const QByteArray publicKey = TpmIdentity::publicKeyBlob();
    const QByteArray signature = TpmIdentity::signChallenge(challenge, &error);
    QVERIFY(!publicKey.isEmpty());
    const QString publicKeyHash = QString::fromLatin1(
        QCryptographicHash::hash(publicKey, QCryptographicHash::Sha256).toHex().toUpper());
    QCOMPARE(TpmIdentity::publicKeySha256(), publicKeyHash);
    QVERIFY2(!signature.isEmpty(), qPrintable(error));
    QVERIFY(EcdsaSignature::verifyCngP256(publicKey, challenge, signature));
    QVERIFY(!EcdsaSignature::verifyCngP256(publicKey, challenge + "x", signature));

    QByteArray changed = signature;
    changed[0] ^= 1;
    QVERIFY(!EcdsaSignature::verifyCngP256(publicKey, challenge, changed));

    QVERIFY(TpmIdentity::signChallenge(QByteArrayView(), &error).isEmpty());
    QVERIFY(!error.isEmpty());

    const HardwareIdentity identity = HardwareCollector().collect();
    QCOMPARE(identity.tpmPublicKeyHash, publicKeyHash);
}

QTEST_MAIN(TpmIdentityTest)
#include "TpmIdentityTest.moc"
