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
    void sendsExactProfileContractAndParsesReply();
    void rejectsMalformedProfileResponses();
    void profileFailuresNeverExposeBearerToken();
    void cancelledProfileDoesNotBlockNextRequest();
    void abortsTimedOutRequest();
    void rejectsNonLoopbackHttpUnlessExplicitlyEnabled();
    void rejectsLocalhostNameEvenWhenLocalHttpIsEnabled();
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
    client.login({QStringLiteral("person@example.com"), QStringLiteral("secret-password"), QStringLiteral("fingerprint")}, 21);
    if (complete.isEmpty()) QVERIFY(complete.wait(3000));
    QVERIFY(request.startsWith("POST /v1/auth/login HTTP/1.1\r\n"));
    QVERIFY(request.contains("Content-Type: application/json"));
    QVERIFY(request.toLower().contains("x-request-id: "));
    const QRegularExpression requestIdPattern(QStringLiteral("(?im)^x-request-id: [0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\r?$"));
    QVERIFY(requestIdPattern.match(QString::fromLatin1(request)).hasMatch());
    QVERIFY(request.contains("\"email\":\"person@example.com\""));
    QVERIFY(request.contains("\"password\":\"secret-password\""));
    QVERIFY(request.contains("\"device_fingerprint\":\"fingerprint\""));
    QVERIFY(!request.contains("license_key"));
    QCOMPARE(complete.at(0).at(0).value<LoginResponse>().sessionId, QStringLiteral("0198940d-7cec-7000-8000-000000000001"));
    QCOMPARE(complete.at(0).at(1).toULongLong(), quint64(21));
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
    client.login({QStringLiteral("person@example.com"), QStringLiteral("never-in-error"), QStringLiteral("fingerprint")}, 22);
    if (failed.isEmpty()) QVERIFY(failed.wait(3000));
    const ApiError error = failed.at(0).at(0).value<ApiError>();
    QCOMPARE(error.code, QStringLiteral("INVALID_CREDENTIALS"));
    QCOMPARE(error.requestId, QStringLiteral("req-body"));
    QVERIFY(!error.message.contains(QStringLiteral("never-in-error")));
    QCOMPARE(failed.at(0).at(1).toULongLong(), quint64(22));
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
    client.login({QStringLiteral("a@b.c"), QStringLiteral("password"), QStringLiteral("fingerprint")});
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
    client.verifyDevice({QStringLiteral("0198940d-7cec-7000-8000-000000000001"), QStringLiteral("Y2hhbGxlbmdl"), QStringLiteral("c2lnbmF0dXJl"), QStringLiteral("cHVibGljLWtleQ=="), {QStringLiteral("smbios"), QStringLiteral("board"), QStringLiteral("bios"), QStringLiteral("disk"), QStringLiteral("guid"), QStringLiteral("fingerprint")}}, 23);
    if (complete.isEmpty()) QVERIFY(complete.wait(3000));
    QVERIFY(request.startsWith("POST /v1/device/verify HTTP/1.1\r\n"));
    QVERIFY(request.contains("\"session_id\":\"0198940d-7cec-7000-8000-000000000001\""));
    QVERIFY(request.contains("\"challenge\":\"Y2hhbGxlbmdl\""));
    QVERIFY(request.contains("\"challenge_signature\":\"c2lnbmF0dXJl\""));
    QVERIFY(request.contains("\"tpm_public_key\":\"cHVibGljLWtleQ==\""));
    QVERIFY(request.contains("\"hardware\":{\"bios_serial\":\"bios\",\"fingerprint\":\"fingerprint\",\"machine_guid\":\"guid\",\"motherboard_serial\":\"board\",\"smbios_uuid\":\"smbios\",\"system_disk_serial\":\"disk\"}"));
    QCOMPARE(complete.at(0).at(1).toULongLong(), quint64(23));
}

void ApiClientTest::sendsExactProfileContractAndParsesReply()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    QByteArray request;
    connect(&server, &QTcpServer::newConnection, this, [&] {
        QTcpSocket *socket = server.nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
            request += socket->readAll();
            if (!request.contains("\r\n\r\n")) return;
            const QByteArray response = R"({"ok":true,"email":"test2@test.com","account_status":"active","product":"StarLoader","license_status":"active","license_expires_at":"2026-09-12T17:42:56Z","max_devices":1,"device_id":"019ffc3f-0396-7266-b82c-35371486cc4e","device_status":"active","session_expires_at":"2026-08-13T18:50:15Z"})";
            socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(response.size()) + "\r\nX-Request-ID: profile-request\r\n\r\n" + response);
            socket->disconnectFromHost();
        });
    });
    const QString token = QStringLiteral("header.payload.signature");
    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())));
    QSignalSpy complete(&client, &ApiClient::profileLoaded);
    client.loadProfile(token, 42);
    if (complete.isEmpty()) QVERIFY(complete.wait(3000));

    const qsizetype headerEnd = request.indexOf("\r\n\r\n");
    QVERIFY(headerEnd >= 0);
    QCOMPARE(request.left(request.indexOf("\r\n")), QByteArray("GET /v1/me HTTP/1.1"));
    QCOMPARE(request.mid(headerEnd + 4), QByteArray());
    const QRegularExpression authorizationPattern(QStringLiteral("(?im)^Authorization: Bearer header\\.payload\\.signature\\r?$"));
    const QRegularExpressionMatchIterator authorizationHeaders = authorizationPattern.globalMatch(QString::fromLatin1(request));
    int authorizationCount = 0;
    for (auto headers = authorizationHeaders; headers.hasNext(); headers.next()) ++authorizationCount;
    QCOMPARE(authorizationCount, 1);

    const UserProfileResponse profile = complete.at(0).at(0).value<UserProfileResponse>();
    QCOMPARE(profile.email, QStringLiteral("test2@test.com"));
    QCOMPARE(profile.accountStatus, QStringLiteral("active"));
    QCOMPARE(profile.product, QStringLiteral("StarLoader"));
    QCOMPARE(profile.licenseStatus, QStringLiteral("active"));
    QCOMPARE(profile.licenseExpiresAt, QDateTime::fromString(QStringLiteral("2026-09-12T17:42:56Z"), Qt::ISODate));
    QCOMPARE(profile.maxDevices, 1);
    QCOMPARE(profile.deviceId, QStringLiteral("019ffc3f-0396-7266-b82c-35371486cc4e"));
    QCOMPARE(profile.deviceStatus, QStringLiteral("active"));
    QCOMPARE(profile.sessionExpiresAt, QDateTime::fromString(QStringLiteral("2026-08-13T18:50:15Z"), Qt::ISODate));
    QCOMPARE(profile.requestId, QStringLiteral("profile-request"));
    QCOMPARE(complete.at(0).at(1).toULongLong(), quint64(42));
}

void ApiClientTest::rejectsMalformedProfileResponses()
{
    const QJsonObject valid{
        {QStringLiteral("ok"), true}, {QStringLiteral("email"), QStringLiteral("test2@test.com")},
        {QStringLiteral("account_status"), QStringLiteral("active")}, {QStringLiteral("product"), QStringLiteral("StarLoader")},
        {QStringLiteral("license_status"), QStringLiteral("active")}, {QStringLiteral("license_expires_at"), QStringLiteral("2026-09-12T17:42:56Z")},
        {QStringLiteral("max_devices"), 1}, {QStringLiteral("device_id"), QStringLiteral("device-1")},
        {QStringLiteral("device_status"), QStringLiteral("active")}, {QStringLiteral("session_expires_at"), QStringLiteral("2026-08-13T18:50:15Z")},
    };
    QList<QByteArray> responses;
    const QStringList requiredFields{
        QStringLiteral("email"), QStringLiteral("account_status"), QStringLiteral("product"), QStringLiteral("license_status"),
        QStringLiteral("license_expires_at"), QStringLiteral("max_devices"), QStringLiteral("device_id"),
        QStringLiteral("device_status"), QStringLiteral("session_expires_at"),
    };
    for (const QString &field : requiredFields) {
        QJsonObject missing = valid;
        missing.remove(field);
        responses.append(QJsonDocument(missing).toJson(QJsonDocument::Compact));
    }
    for (const QPair<QString, QJsonValue> &mutation : QList<QPair<QString, QJsonValue>>{
             {QStringLiteral("email"), QStringLiteral("   ")},
             {QStringLiteral("license_expires_at"), QStringLiteral("not-a-date")},
             {QStringLiteral("max_devices"), 0},
             {QStringLiteral("session_expires_at"), QStringLiteral("not-a-date")},
         }) {
        QJsonObject malformed = valid;
        malformed.insert(mutation.first, mutation.second);
        responses.append(QJsonDocument(malformed).toJson(QJsonDocument::Compact));
    }
    for (const QByteArray &response : responses) {
        qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
        QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
        connect(&server, &QTcpServer::newConnection, this, [&] {
            QTcpSocket *socket = server.nextPendingConnection();
            connect(socket, &QTcpSocket::readyRead, socket, [socket, response] {
                if (!socket->readAll().contains("\r\n\r\n")) return;
                socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(response.size()) + "\r\n\r\n" + response);
                socket->disconnectFromHost();
            });
        });
        ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())));
        QSignalSpy failed(&client, &ApiClient::profileFailed);
        client.loadProfile(QStringLiteral("valid-token"));
        if (failed.isEmpty()) QVERIFY(failed.wait(3000));
        QCOMPARE(failed.at(0).at(0).value<ApiError>().code, QStringLiteral("MALFORMED_RESPONSE"));
    }
}

void ApiClientTest::profileFailuresNeverExposeBearerToken()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    const QString token = QStringLiteral("sensitive-bearer-token");
    connect(&server, &QTcpServer::newConnection, this, [&] {
        QTcpSocket *socket = server.nextPendingConnection();
        connect(socket, &QTcpSocket::readyRead, socket, [socket, token] {
            socket->readAll();
            const QByteArray response = QJsonDocument(QJsonObject{
                {QStringLiteral("ok"), false},
                {QStringLiteral("code"), token},
                {QStringLiteral("message"), QStringLiteral("rejected %1").arg(token)},
                {QStringLiteral("request_id"), token},
            }).toJson(QJsonDocument::Compact);
            socket->write("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(response.size()) + "\r\n\r\n" + response);
            socket->disconnectFromHost();
        });
    });
    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())));
    QSignalSpy failed(&client, &ApiClient::profileFailed);
    client.loadProfile(token, 73);
    if (failed.isEmpty()) QVERIFY(failed.wait(3000));
    const ApiError error = failed.at(0).at(0).value<ApiError>();
    QVERIFY(!error.code.contains(token));
    QVERIFY(!error.message.contains(token));
    QVERIFY(!error.requestId.contains(token));
    QCOMPARE(failed.at(0).at(1).toULongLong(), quint64(73));
}

void ApiClientTest::cancelledProfileDoesNotBlockNextRequest()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    int connectionCount = 0;
    QByteArray profileRequest;
    QByteArray loginRequest;
    connect(&server, &QTcpServer::newConnection, this, [&] {
        while (server.hasPendingConnections()) {
            QTcpSocket *socket = server.nextPendingConnection();
            const int connection = ++connectionCount;
            connect(socket, &QTcpSocket::readyRead, socket, [&, socket, connection] {
                QByteArray &request = connection == 1 ? profileRequest : loginRequest;
                request += socket->readAll();
                if (!request.contains("\r\n\r\n") || connection == 1) return;
                const QByteArray response = R"({"ok":true,"session_id":"0198940d-7cec-7000-8000-000000000001","challenge":"Y2hhbGxlbmdl","challenge_expires_at":"2026-08-10T12:00:00Z"})";
                socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(response.size()) + "\r\n\r\n" + response);
                socket->disconnectFromHost();
            });
        }
    });

    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())));
    client.loadProfile(QStringLiteral("old-token"), 1);
    QTRY_VERIFY(profileRequest.startsWith("GET /v1/me HTTP/1.1\r\n"));
    client.cancelProfile();

    QSignalSpy complete(&client, &ApiClient::loginSucceeded);
    QSignalSpy failed(&client, &ApiClient::loginFailed);
    client.login({QStringLiteral("person@example.com"), QStringLiteral("password"), QStringLiteral("fingerprint")});
    if (complete.isEmpty()) QVERIFY(complete.wait(3000));
    QCOMPARE(failed.size(), 0);
    QVERIFY(loginRequest.startsWith("POST /v1/auth/login HTTP/1.1\r\n"));
}

void ApiClientTest::abortsTimedOutRequest()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost));
    connect(&server, &QTcpServer::newConnection, this, [&] { server.nextPendingConnection(); });
    ApiClient client(QUrl(QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort())), 25);
    QSignalSpy failed(&client, &ApiClient::loginFailed);
    client.login({QStringLiteral("a@b.c"), QStringLiteral("password"), QStringLiteral("fingerprint")});
    QVERIFY(failed.wait(1000));
    QCOMPARE(failed.at(0).at(0).value<ApiError>().code, QStringLiteral("TIMEOUT"));
}

void ApiClientTest::rejectsNonLoopbackHttpUnlessExplicitlyEnabled()
{
    qunsetenv("STARLOADER_ALLOW_HTTP_LOCAL");
    ApiClient client(QUrl(QStringLiteral("http://example.com")));
    QSignalSpy failed(&client, &ApiClient::loginFailed);
    client.login({QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("f")});
    if (failed.isEmpty()) QVERIFY(failed.wait(1000));
    QCOMPARE(failed.at(0).at(0).value<ApiError>().code, QStringLiteral("INSECURE_TRANSPORT"));
}

void ApiClientTest::rejectsLocalhostNameEvenWhenLocalHttpIsEnabled()
{
    qputenv("STARLOADER_ALLOW_HTTP_LOCAL", "1");
    ApiClient client(QUrl(QStringLiteral("http://localhost:8080")));
    QSignalSpy failed(&client, &ApiClient::loginFailed);
    client.login({QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("f")});
    if (failed.isEmpty()) QVERIFY(failed.wait(1000));
    QCOMPARE(failed.at(0).at(0).value<ApiError>().code, QStringLiteral("INSECURE_TRANSPORT"));
}

QTEST_MAIN(ApiClientTest)
#include "ApiClientTest.moc"
