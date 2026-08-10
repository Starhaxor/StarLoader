#include "SmbiosParser.h"

#include <QByteArray>

#include <algorithm>
#include <optional>

namespace {

quint8 byteAt(QByteArrayView bytes, qsizetype offset)
{
    return static_cast<quint8>(bytes[offset]);
}

std::optional<qsizetype> findStringSetEnd(QByteArrayView table, qsizetype start)
{
    for (qsizetype offset = start; offset + 1 < table.size(); ++offset) {
        if (table[offset] == '\0' && table[offset + 1] == '\0') {
            return offset;
        }
    }

    return std::nullopt;
}

QString smbiosString(QByteArrayView table,
                     qsizetype stringsStart,
                     qsizetype stringsEnd,
                     quint8 wantedIndex)
{
    if (wantedIndex == 0) {
        return {};
    }

    quint8 currentIndex = 1;
    qsizetype stringStart = stringsStart;
    while (stringStart <= stringsEnd) {
        qsizetype stringEnd = stringStart;
        while (stringEnd <= stringsEnd && table[stringEnd] != '\0') {
            ++stringEnd;
        }

        if (currentIndex == wantedIndex) {
            return QString::fromLatin1(table.data() + stringStart,
                                       stringEnd - stringStart)
                .trimmed();
        }

        if (stringEnd == stringsEnd) {
            break;
        }

        stringStart = stringEnd + 1;
        ++currentIndex;
    }

    return {};
}

QString formatUuid(QByteArrayView formatted)
{
    constexpr qsizetype uuidOffset = 8;
    constexpr qsizetype uuidSize = 16;
    if (formatted.size() < uuidOffset + uuidSize) {
        return {};
    }

    const auto uuid = formatted.sliced(uuidOffset, uuidSize);
    const bool allZero = std::all_of(uuid.begin(), uuid.end(), [](char value) {
        return static_cast<quint8>(value) == 0;
    });
    const bool allOnes = std::all_of(uuid.begin(), uuid.end(), [](char value) {
        return static_cast<quint8>(value) == 0xff;
    });
    if (allZero || allOnes) {
        return {};
    }

    QByteArray ordered;
    ordered.reserve(uuidSize);
    ordered.append(uuid[3]);
    ordered.append(uuid[2]);
    ordered.append(uuid[1]);
    ordered.append(uuid[0]);
    ordered.append(uuid[5]);
    ordered.append(uuid[4]);
    ordered.append(uuid[7]);
    ordered.append(uuid[6]);
    ordered.append(uuid.sliced(8));

    const QByteArray hex = ordered.toHex();
    return QStringLiteral("%1-%2-%3-%4-%5")
        .arg(QString::fromLatin1(hex.sliced(0, 8)),
             QString::fromLatin1(hex.sliced(8, 4)),
             QString::fromLatin1(hex.sliced(12, 4)),
             QString::fromLatin1(hex.sliced(16, 4)),
             QString::fromLatin1(hex.sliced(20, 12)));
}

} // namespace

SmbiosInfo SmbiosParser::parse(QByteArrayView rawTable)
{
    SmbiosInfo result;
    qsizetype recordStart = 0;

    while (recordStart + 4 <= rawTable.size()) {
        const quint8 type = byteAt(rawTable, recordStart);
        const quint8 formattedLength = byteAt(rawTable, recordStart + 1);
        if (formattedLength < 4
            || formattedLength > rawTable.size() - recordStart) {
            break;
        }

        const qsizetype stringsStart = recordStart + formattedLength;
        const auto stringsEnd = findStringSetEnd(rawTable, stringsStart);
        if (!stringsEnd) {
            break;
        }

        const auto formatted = rawTable.sliced(recordStart, formattedLength);
        if (type == 0 && formattedLength > 5) {
            result.biosSerial = smbiosString(rawTable,
                                             stringsStart,
                                             *stringsEnd,
                                             byteAt(formatted, 5));
        } else if (type == 1) {
            result.systemUuid = formatUuid(formatted);
        } else if (type == 2 && formattedLength > 7) {
            result.motherboardSerial = smbiosString(rawTable,
                                                    stringsStart,
                                                    *stringsEnd,
                                                    byteAt(formatted, 7));
        }

        recordStart = *stringsEnd + 2;
        if (type == 127) {
            break;
        }
    }

    return result;
}
