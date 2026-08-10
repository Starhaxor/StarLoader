#include "api/ApiClient.h"

#include <QTcpServer>
#include <QTcpSocket>
#include <QRegularExpression>
#include <QtTest>

class ApiClientTest final : public QObject
{
    Q_OBJECT

private slots:
    void sendsExactLoginContractAndParsesReply();
    void parsesStructuredFailuresWithoutLeakingCredentials();
    void rejectsMalformedSuccessJson();
    void sendsExactDeviceVerificationContract();
    void abortsTimedOutRequest();
    void rejectsNonLoopbackHttpUnlessExplicitlyEnabled();
};

void ApiClientTest::sendsExactLoginContractAndParsesReply()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost));
    QByteArray request;
    connect(&server, &QTcpServer::newConnection, this, [&] {
        QTcpSocket *socket = server.nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
            request += socket->readAll();
            if (!request.contains("\r\n\r\n")) return;
            const QByteArray response = "{\"ok\":true,\"session_id\":\"0198940d-7cec-7000-8000-000000000001\",\"challenge\":\"Y2hhbGxlbmdl\",\"challenge_expires_at\":\"2026-08-10T12:00:00Z\"}";
            socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(response.size()) + "\r\n\r\n" + response);
            socket->disconnectFromHost();
        });
    });
    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())));
    QSignalSpy complete(&client, &ApiClient::loginSucceeded);
    client.login({QStringLiteral("person@example.com"), QStringLiteral("secret-password"), QStringLiteral("LICENSE-SECRET"), QStringLiteral("fingerprint")});
    if (complete.isEmpty()) QVERIFY(complete.wait(3000));
    QVERIFY(request.startsWith("POST /v1/auth/login HTTP/1.1\r\n"));
    QVERIFY(request.contains("Content-Type: application/json"));
    QVERIFY(request.toLower().contains("x-request-id: "));
    const QRegularExpression requestIdPattern(QStringLiteral("(?im)^x-request-id: [0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\r?$"));
    QVERIFY(requestIdPattern.match(QString::fromLatin1(request)).hasMatch());
    QVERIFY(request.contains("\"email\":\"person@example.com\""));
    QVERIFY(request.contains("\"password\":\"secret-password\""));
    QVERIFY(request.contains("\"license_key\":\"LICENSE-SECRET\""));
    QCOMPARE(complete.at(0).at(0).value<LoginResponse>().sessionId, QStringLiteral("0198940d-7cec-7000-8000-000000000001"));
}

void ApiClientTest::parsesStructuredFailuresWithoutLeakingCredentials()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost));
    connect(&server, &QTcpServer::newConnection, this, [&] {
        QTcpSocket *socket = server.nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, socket, [socket] {
            socket->readAll();
            const QByteArray response = "{\"ok\":false,\"code\":\"INVALID_CREDENTIALS\",\"message\":\"invalid credentials\",\"request_id\":\"req-body\"}";
            socket->write("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(response.size()) + "\r\nX-Request-ID: req-header\r\n\r\n" + response);
            socket->disconnectFromHost();
        });
    });
    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())));
    QSignalSpy failed(&client, &ApiClient::loginFailed);
    client.login({QStringLiteral("person@example.com"), QStringLiteral("never-in-error"), QStringLiteral("never-in-error-license"), QStringLiteral("fingerprint")});
    if (failed.isEmpty()) QVERIFY(failed.wait(3000));
    const ApiError error = failed.at(0).at(0).value<ApiError>();
    QCOMPARE(error.code, QStringLiteral("INVALID_CREDENTIALS"));
    QCOMPARE(error.requestId, QStringLiteral("req-body"));
    QVERIFY(!error.message.contains(QStringLiteral("never-in-error")));
}

void ApiClientTest::rejectsMalformedSuccessJson()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server;
    QVERIFY(server.listen(QHostAddress::LocalHost));
    connect(&server, &QTcpServer::newConnection, this, [&] {
        QTcpSocket *socket = server.nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, socket, [socket] {
            socket->readAll();
            const QByteArray response = "not-json";
            socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(response.size()) + "\r\n\r\n" + response);
            socket->disconnectFromHost();
        });
    });
    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())));
    QSignalSpy failed(&client, &ApiClient::loginFailed);
    client.login({QStringLiteral("a@b.c"), QStringLiteral("password"), QStringLiteral("license"), QStringLiteral("fingerprint")});
    if (failed.isEmpty()) QVERIFY(failed.wait(3000));
    QCOMPARE(failed.at(0).at(0).value<ApiError>().code, QStringLiteral("MALFORMED_RESPONSE"));
}

void ApiClientTest::sendsExactDeviceVerificationContract()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    QByteArray request;
    connect(&server, &QTcpServer::newConnection, this, [&] {
        QTcpSocket *socket = server.nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
            request += socket->readAll(); if (!request.contains("\r\n\r\n")) return;
            const QByteArray response = "{\"ok\":true,\"token\":\"jws\",\"token_expires_at\":\"2026-08-10T12:00:00Z\",\"license_id\":\"license-1\",\"device_id\":\"device-1\"}";
            socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(response.size()) + "\r\n\r\n" + response);
            socket->disconnectFromHost();
        });
    });
    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())));
    QSignalSpy complete(&client, &ApiClient::deviceVerified);
    client.verifyDevice({QStringLiteral("0198940d-7cec-7000-8000-000000000001"), QStringLiteral("Y2hhbGxlbmdl"), QStringLiteral("c2lnbmF0dXJl"), QStringLiteral("cHVibGljLWtleQ=="), {QStringLiteral("smbios"), QStringLiteral("board"), QStringLiteral("bios"), QStringLiteral("disk"), QStringLiteral("guid"), QStringLiteral("fingerprint")}});
    if (complete.isEmpty()) QVERIFY(complete.wait(3000));
    QVERIFY(request.startsWith("POST /v1/device/verify HTTP/1.1\r\n"));
    QVERIFY(request.contains("\"session_id\":\"0198940d-7cec-7000-8000-000000000001\""));
    QVERIFY(request.contains("\"challenge\":\"Y2hhbGxlbmdl\""));
    QVERIFY(request.contains("\"challenge_signature\":\"c2lnbmF0dXJl\""));
    QVERIFY(request.contains("\"tpm_public_key\":\"cHVibGljLWtleQ==\""));
    QVERIFY(request.contains("\"hardware\":{\"bios_serial\":\"bios\",\"fingerprint\":\"fingerprint\",\"machine_guid\":\"guid\",\"motherboard_serial\":\"board\",\"smbios_uuid\":\"smbios\",\"system_disk_serial\":\"disk\"}"));
}

void ApiClientTest::abortsTimedOutRequest()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    connect(&server, &QTcpServer::newConnection, this, [&] { server.nextPendingConnection(); });
    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())), 25);
    QSignalSpy failed(&client, &ApiClient::loginFailed);
    client.login({QStringLiteral("a@b.c"), QStringLiteral("password"), QStringLiteral("license"), QStringLiteral("fingerprint")});
    QVERIFY(failed.wait(1000));
    QCOMPARE(failed.at(0).at(0).value<ApiError>().code, QStringLiteral("TIMEOUT"));
}

void ApiClientTest::rejectsNonLoopbackHttpUnlessExplicitlyEnabled()
{
    qunsetenv("STARLOADER_ALLOW_HTTP_LOCAL");
    ApiClient client(QUrl(QStringLiteral("http://example.com")));
    QSignalSpy failed(&client, &ApiClient::loginFailed);
    client.login({QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("l"), QStringLiteral("f")});
    if (failed.isEmpty()) QVERIFY(failed.wait(1000));
    QCOMPARE(failed.at(0).at(0).value<ApiError>().code, QStringLiteral("INSECURE_TRANSPORT"));
}

QTEST_MAIN(ApiClientTest)
#include "ApiClientTest.moc"
