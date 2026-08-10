#include "Fingerprint.h"

#include "HardwareNormalization.h"

#include <QCryptographicHash>

QString Fingerprint::generate(const HardwareIdentity &identity)
{
    QByteArray input;

    const auto append = [&input](const QString &value) {
        input += normalizeHardwareValue(value).toUtf8();
        input += '|';
    };

    append(identity.smbiosUuid);
    append(identity.motherboardSerial);
    append(identity.biosSerial);
    append(identity.systemDiskSerial);
    append(identity.machineGuid);
    append(identity.tpmPublicKeyHash);

    return QCryptographicHash::hash(input, QCryptographicHash::Sha256).toHex().toUpper();
}
