#include "DeviceProof.h"

#include "security/TpmIdentity.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QRegularExpression>

#include <algorithm>

namespace {
constexpr quint32 kEcdsaP256PublicMagic = 0x31534345;
constexpr qsizetype kCoordinateSize = 32;
constexpr qsizetype kPublicBlobSize = 8 + (2 * kCoordinateSize);
constexpr qsizetype kRawSignatureSize = 64;
const QString kProofFailure = QStringLiteral("Device proof could not be created.");

ProofResult rejected()
{
    ProofResult result;
    result.error = kProofFailure;
    return result;
}

quint32 readLittleEndian32(QByteArrayView input, qsizetype offset)
{
    const auto byte = [&input](qsizetype index) {
        return static_cast<quint32>(static_cast<unsigned char>(input.at(index)));
    };
    return byte(offset) | (byte(offset + 1) << 8) | (byte(offset + 2) << 16) | (byte(offset + 3) << 24);
}

QByteArray base64Url(QByteArrayView input)
{
    return QByteArray(input.data(), input.size()).toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

bool parsePublicBlob(QByteArrayView blob, QByteArray *x, QByteArray *y)
{
    if (blob.size() != kPublicBlobSize
        || readLittleEndian32(blob, 0) != kEcdsaP256PublicMagic
        || readLittleEndian32(blob, 4) != kCoordinateSize) {
        return false;
    }
    *x = QByteArray(blob.data() + 8, kCoordinateSize);
    *y = QByteArray(blob.data() + 8 + kCoordinateSize, kCoordinateSize);
    return true;
}

QString thumbprintFor(const QByteArray &xEncoded, const QByteArray &yEncoded)
{
    const QByteArray canonical = QByteArrayLiteral("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"")
        + xEncoded + QByteArrayLiteral("\",\"y\":\"") + yEncoded + QByteArrayLiteral("\"}");
    return QString::fromLatin1(base64Url(QCryptographicHash::hash(canonical, QCryptographicHash::Sha256)));
}

bool canonicalHtu(const QUrl &input, bool localDevelopment, QString *htu)
{
    if (!input.isValid() || input.isRelative() || input.host().isEmpty()
        || !input.userName().isEmpty() || !input.password().isEmpty()) {
        return false;
    }

    const QString scheme = input.scheme().toLower();
    if (scheme != QStringLiteral("https")) {
        QHostAddress address;
        if (!localDevelopment || scheme != QStringLiteral("http")
            || !address.setAddress(input.host()) || !address.isLoopback()) {
            return false;
        }
    }

    QUrl canonical = input.adjusted(QUrl::NormalizePathSegments
                                    | QUrl::RemoveQuery
                                    | QUrl::RemoveFragment);
    canonical.setScheme(scheme);
    canonical.setHost(input.host().toLower());
    if ((scheme == QStringLiteral("https") && canonical.port() == 443)
        || (scheme == QStringLiteral("http") && canonical.port() == 80)) {
        canonical.setPort(-1);
    }
    if (!canonical.isValid() || canonical.host().isEmpty())
        return false;
    *htu = canonical.toString(QUrl::FullyEncoded);
    return !htu->isEmpty();
}

QByteArray secureRandomJti()
{
    QByteArray random(16, Qt::Uninitialized);
    for (qsizetype offset = 0; offset < random.size(); offset += 4) {
        const quint32 word = QRandomGenerator::system()->generate();
        for (qsizetype index = 0; index < 4; ++index)
            random[offset + index] = static_cast<char>((word >> (index * 8)) & 0xff);
    }
    return random;
}

bool validMethod(const QString &method)
{
    static const QRegularExpression syntax(QStringLiteral("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"));
    return syntax.match(method).hasMatch();
}
} // namespace

bool TpmProofSigner::publicKeyBlob(QByteArray *publicBlob, QString *error)
{
    if (!publicBlob)
        return false;
    if (error)
        error->clear();
    *publicBlob = TpmIdentity::publicKeyBlob();
    if (!publicBlob->isEmpty())
        return true;
    if (error)
        *error = QStringLiteral("The TPM public key is unavailable.");
    return false;
}

bool TpmProofSigner::sign(QByteArrayView input, QByteArray *signature,
                          QByteArray *publicBlob, QString *error)
{
    if (!signature || !publicBlob || input.isEmpty())
        return false;
    if (!publicKeyBlob(publicBlob, error))
        return false;
    *signature = TpmIdentity::signChallenge(input, error);
    return !signature->isEmpty();
}

DeviceProofBuilder::DeviceProofBuilder(IDeviceProofSigner &signer, Clock clock,
                                       RandomSource randomSource, bool localDevelopment)
    : signer_(signer),
      clock_(clock ? std::move(clock) : Clock([] { return QDateTime::currentSecsSinceEpoch(); })),
      randomSource_(randomSource ? std::move(randomSource) : RandomSource(secureRandomJti)),
      localDevelopment_(localDevelopment)
{
}

ProofResult DeviceProofBuilder::build(const QString &method, const QUrl &url,
                                      const QString &accessToken,
                                      const QString &expectedThumbprint) const
{
    const QByteArray tokenBytes = accessToken.toLatin1();
    QString htu;
    if (accessToken.isEmpty() || QString::fromLatin1(tokenBytes) != accessToken
        || !validMethod(method) || !canonicalHtu(url, localDevelopment_, &htu)) {
        return rejected();
    }

    QByteArray publicBlob;
    QString signerError;
    if (!signer_.publicKeyBlob(&publicBlob, &signerError))
        return rejected();

    QByteArray x;
    QByteArray y;
    if (!parsePublicBlob(publicBlob, &x, &y))
        return rejected();
    const QByteArray xEncoded = base64Url(x);
    const QByteArray yEncoded = base64Url(y);
    const QString thumbprint = thumbprintFor(xEncoded, yEncoded);
    if (expectedThumbprint != thumbprint)
        return rejected();

    const QByteArray random = randomSource_();
    if (random.size() != 16)
        return rejected();

    const QJsonObject jwk{
        {QStringLiteral("crv"), QStringLiteral("P-256")},
        {QStringLiteral("kty"), QStringLiteral("EC")},
        {QStringLiteral("x"), QString::fromLatin1(xEncoded)},
        {QStringLiteral("y"), QString::fromLatin1(yEncoded)},
    };
    const QJsonObject header{
        {QStringLiteral("alg"), QStringLiteral("ES256")},
        {QStringLiteral("jwk"), jwk},
        {QStringLiteral("typ"), QStringLiteral("dpop+jwt")},
    };
    const QJsonObject payload{
        {QStringLiteral("ath"), QString::fromLatin1(base64Url(QCryptographicHash::hash(tokenBytes, QCryptographicHash::Sha256)))},
        {QStringLiteral("htm"), method.toUpper()},
        {QStringLiteral("htu"), htu},
        {QStringLiteral("iat"), clock_()},
        {QStringLiteral("jti"), QString::fromLatin1(base64Url(random))},
    };

    const QByteArray encodedHeader = base64Url(QJsonDocument(header).toJson(QJsonDocument::Compact));
    const QByteArray encodedPayload = base64Url(QJsonDocument(payload).toJson(QJsonDocument::Compact));
    QByteArray signingInput = encodedHeader + '.' + encodedPayload;
    QByteArray signature;
    QByteArray signedPublicBlob;
    const bool signedSuccessfully = signer_.sign(signingInput, &signature, &signedPublicBlob, &signerError);
    std::fill(signingInput.begin(), signingInput.end(), '\0');
    signingInput.clear();
    if (!signedSuccessfully || signature.size() != kRawSignatureSize
        || signedPublicBlob != publicBlob) {
        return rejected();
    }

    ProofResult result;
    result.valid = true;
    result.compactJws = QString::fromLatin1(encodedHeader + '.' + encodedPayload + '.' + base64Url(signature));
    result.jwkThumbprint = thumbprint;
    return result;
}
