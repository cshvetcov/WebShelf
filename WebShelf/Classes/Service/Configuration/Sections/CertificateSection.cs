using System.Security.Cryptography.X509Certificates;
using WebShelf.Classes.Crypto;

namespace WebShelf.Classes.Service.Configuration.Sections;

/// <summary>
/// Инициализатор секции TLS-сертификата: загружает PFX-сертификат для
/// прослушивания по https, выполняя миграцию открытого пароля в защищённый.
/// </summary>
/// <remarks>
/// Класс выделен из <c>Data</c> механическим переносом (шаг 6 дорожной
/// карты декомпозиции, точка решения о секциях: <c>Data</c> после выноса
/// записи остаётся больше ~550 строк). Правки при переносе — константа
/// <c>Class=</c> в логах перенесённого кода (принцип 6 дорожной карты)
/// и возврат результата вместо мутации состояния <c>Data</c>: метод
/// возвращает загруженный сертификат через выходной параметр,
/// присваивание свойству выполняет оркестратор <see cref="Data.ReadConfigAsync"/>.
/// Шаг 8 дорожной карты (улучшение У3): криптография поступает параметрами
/// как инстансные зависимости <see cref="KeyStore"/> и <see cref="CryptoEngine"/>
/// вместо статических вызовов фасада — поведение не менялось.
/// </remarks>
internal static class CertificateSection
{
    private const string ClassName = "WebShelf.Classes.Service.Configuration.Sections.CertificateSection";

    /// <summary>
    /// Загружает TLS-сертификат для схемы https из ключей конфигурации:
    /// <c>certpath</c> — путь к PFX-файлу, пароль — из <c>scertpass</c> (зашифрованный)
    /// либо из <c>certpass</c> (открытый, шифруется и переносится в <c>scertpass</c>).
    /// При схеме http инициализация пропускается (<see langword="true"/>, сертификат
    /// не требуется). Сертификат обязан содержать закрытый ключ.
    /// </summary>
    /// <param name="config">Словарь конфигурации (результат разбора Server.conf).</param>
    /// <param name="scheme">Схема прослушивания, установленная оркестратором
    /// к моменту вызова; сертификат требуется только при <c>https</c>.</param>
    /// <param name="credentialsWriter">Писатель защищённых учётных данных в Server.conf.</param>
    /// <param name="keyStore">Хранилище ключей — источник мастер-ключа
    /// (в Production — singleton из DI; улучшение У3 дорожной карты декомпозиции).</param>
    /// <param name="cryptoEngine">Криптографический движок — расшифровка и
    /// шифрование пароля сертификата (в Production — singleton из DI).</param>
    /// <param name="certificate">Выходной параметр: загруженный сертификат
    /// либо <see langword="null"/> (не требуется или ошибка).</param>
    /// <returns><see langword="true"/>, если сертификат загружен или не требуется; иначе <see langword="false"/>.</returns>
    internal static bool TryInitCertificate(
        Dictionary<string, string> config,
        string? scheme,
        SecureCredentialsWriter credentialsWriter,
        KeyStore keyStore,
        CryptoEngine cryptoEngine,
        out X509Certificate2? certificate)
    {
        const string method = nameof(TryInitCertificate);

        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentNullException.ThrowIfNull(cryptoEngine);

        certificate = null;

        try
        {
            // Сертификат нужен только для прослушивания по https
            if (!string.Equals(scheme, "https", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!config.TryGetValue("certpath", out string? certPath) || string.IsNullOrWhiteSpace(certPath))
            {
                Log.Error(
                    "Отсутствует или пустой ключ certpath (обязателен при scheme=https). Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            // Относительный путь ищется рядом с бинарниками приложения
            string resolvedPath = certPath.Trim();
            if (!Path.IsPathRooted(resolvedPath))
            {
                resolvedPath = Path.Combine(AppContext.BaseDirectory, resolvedPath);
            }

            if (!File.Exists(resolvedPath))
            {
                Log.Error(
                    "Файл TLS-сертификата не найден. Path={Path}. Class={Class}, Method={Method}",
                    resolvedPath, ClassName, method);
                return false;
            }

            byte[]? masterKey = keyStore.EnsureMasterKey();
            if (masterKey is null)
            {
                Log.Error(
                    "Мастер-ключ недоступен при загрузке TLS-сертификата. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            string? password = null;

            bool hasSecurePass = config.TryGetValue("scertpass", out string? sPass) &&
                                 !string.IsNullOrWhiteSpace(sPass);
            bool hasPlainPass = config.TryGetValue("certpass", out string? pPass) &&
                                !string.IsNullOrWhiteSpace(pPass);

            if (hasSecurePass)
            {
                try
                {
                    password = cryptoEngine.Decrypt(sPass!.Trim(), masterKey);
                }
                catch (Exception ex)
                {
                    Log.Error(ex,
                        "Не удалось расшифровать scertpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                // Остаточный открытый certpass подлежит очистке: секреты
                // не должны оставаться в конфигурации в незашифрованном виде
                if (hasPlainPass)
                {
                    if (credentialsWriter.WriteSecureCredentials(SecureCredentialsWriter.TlsCredentialKeys, null, sPass!.Trim()))
                    {
                        Log.Information(
                            "Остаточный открытый certpass очищен в конфигурации. Class={Class}, Method={Method}",
                            ClassName, method);
                    }
                    else
                    {
                        Log.Warning(
                            "Не удалось очистить остаточный открытый certpass. Class={Class}, Method={Method}",
                            ClassName, method);
                    }
                }
            }
            else if (hasPlainPass)
            {
                password = pPass!.Trim();

                try
                {
                    string encryptedPass = cryptoEngine.Encrypt(password, masterKey);
                    if (!credentialsWriter.WriteSecureCredentials(SecureCredentialsWriter.TlsCredentialKeys, null, encryptedPass))
                    {
                        Log.Error(
                            "Не удалось записать scertpass в конфигурацию. Class={Class}, Method={Method}",
                            ClassName, method);
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex,
                        "Не удалось зашифровать certpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                Log.Information(
                    "Пароль TLS-сертификата зашифрован и сохранён в scertpass. Class={Class}, Method={Method}",
                    ClassName, method);
            }

            // Пароль не требуется для PFX без защиты; null допустим
            X509Certificate2 loadedCertificate;
            try
            {
                // X509CertificateLoader (SYSLIB0057): современный способ загрузки PFX
                loadedCertificate = X509CertificateLoader.LoadPkcs12FromFile(resolvedPath, password);
            }
            catch (Exception ex)
            {
                Log.Error(ex,
                    "Не удалось загрузить TLS-сертификат (неверный файл или пароль). Path={Path}. Class={Class}, Method={Method}",
                    resolvedPath, ClassName, method);
                return false;
            }

            // Для серверного TLS обязателен закрытый ключ
            if (!loadedCertificate.HasPrivateKey)
            {
                Log.Error(
                    "Сертификат не содержит закрытого ключа. Path={Path}. Class={Class}, Method={Method}",
                    resolvedPath, ClassName, method);
                loadedCertificate.Dispose();
                return false;
            }

            // Предупреждение о сроке действия не блокирует запуск
            if (loadedCertificate.NotAfter < DateTimeOffset.UtcNow)
            {
                Log.Warning(
                    "Срок действия TLS-сертификата истёк. NotAfter={NotAfter}. Class={Class}, Method={Method}",
                    loadedCertificate.NotAfter, ClassName, method);
            }
            else if (loadedCertificate.NotAfter < DateTimeOffset.UtcNow.AddDays(14))
            {
                Log.Warning(
                    "Срок действия TLS-сертификата истекает менее чем через 14 дней. NotAfter={NotAfter}. Class={Class}, Method={Method}",
                    loadedCertificate.NotAfter, ClassName, method);
            }

            certificate = loadedCertificate;

            Log.Information(
                "TLS-сертификат загружен. Subject={Subject}, Thumbprint={Thumbprint}, NotAfter={NotAfter}. Class={Class}, Method={Method}",
                loadedCertificate.Subject, loadedCertificate.Thumbprint, loadedCertificate.NotAfter, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка инициализации TLS-сертификата. Class={Class}, Method={Method}",
                ClassName, method);
            certificate?.Dispose();
            certificate = null;
            return false;
        }
    }
}
