#pragma once

#include <QByteArrayView>

class EcdsaSignature
{
public:
    static bool verifyCngP256(
        QByteArrayView publicBlob,
        QByteArrayView challenge,
        QByteArrayView signature);
};
