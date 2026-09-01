#include "TlsPinPolicy.h"

#include <QCryptographicHash>
#include <QHostAddress>
#include <QSslCertificate>

#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <memory>

namespace {
constexpr auto PinPrefix = "sha256/";

bool decodePin(const QByteArray &encodedPin, QByteArray *digest)
{
    if (!digest || !encodedPin.startsWith(PinPrefix)) return false;
    const QByteArray encodedDigest = encodedPin.sliced(sizeof(PinPrefix) - 1);
    const auto decoded = QByteArray::fromBase64Encoding(
        encodedDigest, QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded || decoded.decoded.size() != QCryptographicHash::hashLength(QCryptographicHash::Sha256)
        || decoded.decoded.toBase64() != encodedDigest) {
        return false;
    }
    *digest = decoded.decoded;
    return true;
}

QByteArray certificateSpkiDigest(const QSslCertificate &certificate)
{
    const QByteArray certificateDer = certificate.toDer();
    if (certificateDer.isEmpty()) return {};

    const unsigned char *cursor = reinterpret_cast<const unsigned char *>(certificateDer.constData());
    X509 *rawCertificate = d2i_X509(nullptr, &cursor, certificateDer.size());
    if (!rawCertificate || cursor != reinterpret_cast<const unsigned char *>(certificateDer.constData())
            + certificateDer.size()) {
        X509_free(rawCertificate);
        return {};
    }
    const std::unique_ptr<X509, decltype(&X509_free)> parsed(rawCertificate, X509_free);
    X509_PUBKEY *publicKey = X509_get_X509_PUBKEY(parsed.get());
    if (!publicKey) return {};

    const int spkiLength = i2d_X509_PUBKEY(publicKey, nullptr);
    if (spkiLength <= 0) return {};
    QByteArray spki(spkiLength, Qt::Uninitialized);
    unsigned char *output = reinterpret_cast<unsigned char *>(spki.data());
    if (i2d_X509_PUBKEY(publicKey, &output) != spkiLength) return {};
    return QCryptographicHash::hash(spki, QCryptographicHash::Sha256);
}

bool isNumericLoopback(const QString &host)
{
    QHostAddress address;
    return address.setAddress(host) && address.isLoopback();
}
} // namespace

TlsPinPolicy::TlsPinPolicy(QString expectedHost, QList<QByteArray> sha256Pins,
                           bool localDevelopment)
    : expectedHost_(std::move(expectedHost)), localDevelopment_(localDevelopment)
{
    expectedHost_ = expectedHost_.trimmed().toLower();
    if (expectedHost_.isEmpty()) return;

    if (localDevelopment_) {
        valid_ = sha256Pins.isEmpty() && isNumericLoopback(expectedHost_);
        return;
    }

    if (sha256Pins.size() != 2) return;
    for (const QByteArray &pin : sha256Pins) {
        QByteArray digest;
        if (!decodePin(pin, &digest)) return;
        pinDigests_.append(digest);
    }
    valid_ = pinDigests_.at(0) != pinDigests_.at(1);
}

bool TlsPinPolicy::isValid() const
{
    return valid_;
}

bool TlsPinPolicy::permitsRequestUrl(const QUrl &requestUrl) const
{
    if (!valid_ || !requestUrl.isValid() || !requestUrl.userInfo().isEmpty()
        || requestUrl.host().compare(expectedHost_, Qt::CaseInsensitive) != 0) {
        return false;
    }
    if (localDevelopment_) {
        return requestUrl.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) == 0
            && isNumericLoopback(requestUrl.host());
    }
    return requestUrl.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0;
}

bool TlsPinPolicy::verify(const QUrl &requestUrl, const QSslCertificate &peer) const
{
    if (!permitsRequestUrl(requestUrl)) return false;
    if (localDevelopment_) return peer.isNull();
    if (peer.isNull()) return false;

    const QByteArray actualDigest = certificateSpkiDigest(peer);
    if (actualDigest.size() != QCryptographicHash::hashLength(QCryptographicHash::Sha256)) return false;
    unsigned int matched = 0;
    for (const QByteArray &pinDigest : pinDigests_) {
        matched |= static_cast<unsigned int>(
            CRYPTO_memcmp(actualDigest.constData(), pinDigest.constData(), actualDigest.size()) == 0);
    }
    return matched != 0;
}
