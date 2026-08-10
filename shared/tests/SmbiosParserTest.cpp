#include "hardware/SmbiosParser.h"

#include <QByteArray>
#include <QtTest>

class SmbiosParserTest final : public QObject
{
    Q_OBJECT

private slots:
    void parsesIdentityFieldsFromCompleteRecords();
    void rejectsTruncatedFormattedSection();
    void returnsEmptyForMissingStringIndices();
    void rejectsUnterminatedStringSection();
};

void SmbiosParserTest::parsesIdentityFieldsFromCompleteRecords()
{
    QByteArray table;

    // Type 0 offset 0x05 is BIOS Version, not a serial number.
    table += QByteArray::fromHex("000900000001000000");
    table.append("BIOS-123", 8);
    table.append("\0\0", 2);

    // Type 1: UUID bytes use SMBIOS/RFC 4122 mixed-endian encoding.
    table += QByteArray::fromHex(
        "011801000000000033221100554477668899aabbccddeeff");
    table.append("\0\0", 2);

    // Type 2: baseboard serial string index is byte 7.
    table += QByteArray::fromHex("0208020000000001");
    table.append("BOARD-456", 9);
    table.append("\0\0", 2);

    table += QByteArray::fromHex("7f0403000000");

    const auto result = SmbiosParser::parse(table);

    QVERIFY(result.biosSerial.isEmpty());
    QCOMPARE(result.systemUuid, QString("00112233-4455-6677-8899-aabbccddeeff"));
    QCOMPARE(result.motherboardSerial, QString("BOARD-456"));
}

void SmbiosParserTest::rejectsTruncatedFormattedSection()
{
    const QByteArray malformed = QByteArray::fromHex("010801000000");
    const auto result = SmbiosParser::parse(malformed);
    QVERIFY(result.systemUuid.isEmpty());
}

void SmbiosParserTest::returnsEmptyForMissingStringIndices()
{
    QByteArray table;
    table += QByteArray::fromHex("000600000002");
    table.append("ONLY-ONE", 8);
    table.append("\0\0", 2);
    table += QByteArray::fromHex("0208020000000002");
    table.append("ONLY-ONE", 8);
    table.append("\0\0", 2);
    table += QByteArray::fromHex("7f0403000000");

    const auto result = SmbiosParser::parse(table);

    QVERIFY(result.biosSerial.isEmpty());
    QVERIFY(result.motherboardSerial.isEmpty());
}

void SmbiosParserTest::rejectsUnterminatedStringSection()
{
    QByteArray table = QByteArray::fromHex("000600000001");
    table.append("BIOS-123", 8);
    table.append('\0');

    const auto result = SmbiosParser::parse(table);

    QVERIFY(result.biosSerial.isEmpty());
}

QTEST_MAIN(SmbiosParserTest)
#include "SmbiosParserTest.moc"
