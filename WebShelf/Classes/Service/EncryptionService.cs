using System;
using System.Security.Cryptography;
using System.Text;
using Serilog;
using WebShelf.Classes.Crypto;

namespace WebShelf.Classes.Service;

/// <summary>
/// Статический сервис синхронного шифрования.
/// Реализация: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).
/// Формат полезной нагрузки: версия (1 байт) | IV (16) | ciphertext | MAC (32).
/// </summary>
/// <remarks>
/// Шаг 3 дорожной карты декомпозиции: хранилище ключей (создание ключей,
/// InstanceId и мастер-ключ в HKCU под защитой DPAPI, кэширование) вынесено
/// в <see cref="KeyStore"/>. Методы-делегаты сохранены до шага 8, чтобы
/// существующие точки вызова (<c>Data</c>, <c>Domain</c>, <c>Database</c>,
/// <c>Program</c>, тесты) продолжали работать без правок. Фасад не содержит
/// собственного состояния: кэш мастер-ключа и блокировки принадлежат
/// <see cref="KeyStore"/>.
/// </remarks>
internal static class EncryptionService
{
    private const string ClassName = "WebShelf.Classes.Service.EncryptionService";

    private const byte FormatVersion = 1;
    private const int MasterKeySizeBytes = 32;
    private const int IvSizeBytes = 16;
    private const int HmacSizeBytes = 32;
    private const int CipherBlockSizeBytes = 16;

    private static readonly byte[] AesKeyDerivationLabel = Encoding.UTF8.GetBytes("WebShelf.Classes.Service.EncryptionService.AES.v1");

    private static readonly byte[] HmacKeyDerivationLabel = Encoding.UTF8.GetBytes("WebShelf.Classes.Service.EncryptionService.HMAC.v1");

    #region Фасад хранилища ключей (KeyStore, до шага 8)

    /// <summary>
    /// Создаёт новый случайный мастер-ключ размером 32 байта.
    /// Делегирует <see cref="KeyStore.CreateKey"/>.
    /// </summary>
    /// <returns>Массив из 32 криптографически стойких случайных байт.</returns>
    /// <exception cref="CryptographicException">При сбое генератора случайных чисел.</exception>
    internal static byte[] CreateKey()
    {
        return KeyStore.CreateKey();
    }

    /// <summary>
    /// Создаёт новый случайный мастер-ключ и возвращает его в виде Base64-строки.
    /// Делегирует <see cref="KeyStore.CreateKeyBase64"/>.
    /// </summary>
    /// <returns>Ключ в кодировке Base64.</returns>
    /// <exception cref="CryptographicException">При сбое генератора случайных чисел.</exception>
    internal static string CreateKeyBase64()
    {
        return KeyStore.CreateKeyBase64();
    }

    /// <summary>
    /// Обеспечивает наличие InstanceId (ULID): читает из <c>HKEY_CURRENT_USER</c>
    /// (DPAPI CurrentUser), при отсутствии генерирует, защищает и записывает.
    /// Делегирует <see cref="KeyStore.EnsureInstanceId"/>.
    /// </summary>
    /// <returns>Полный ULID (26 символов) или <see langword="null"/> при ошибке.</returns>
    internal static string? EnsureInstanceId()
    {
        return KeyStore.EnsureInstanceId();
    }

    /// <summary>
    /// Обеспечивает наличие мастер-ключа: читает из <c>HKEY_CURRENT_USER</c>
    /// (DPAPI CurrentUser), при отсутствии создаёт и сохраняет.
    /// Делегирует <see cref="KeyStore.EnsureMasterKey"/>.
    /// </summary>
    /// <param name="key">
    /// Готовый ключ (32 байта). Если не <see langword="null"/>, генерация не выполняется —
    /// ключ проверяется, защищается DPAPI и записывается в реестр (при необходимости).
    /// </param>
    /// <returns>
    /// Копия мастер-ключа (32 байта) или <see langword="null"/>,
    /// если не удалось прочитать/сохранить либо формат ключа некорректен.
    /// </returns>
    internal static byte[]? EnsureMasterKey(byte[]? key = null)
    {
        return KeyStore.EnsureMasterKey(key);
    }

    /// <summary>
    /// Принудительно очищает кэш мастер-ключа (обнуление памяти).
    /// Делегирует <see cref="KeyStore.ClearMasterKeyCache"/>.
    /// </summary>
    internal static void ClearMasterKeyCache()
    {
        KeyStore.ClearMasterKeyCache();
    }

    #endregion

    #region Шифрование byte[]

    /// <summary>
    /// Шифрует массив байтов (AES-256-CBC, Encrypt-then-MAC).
    /// </summary>
    /// <param name="data">Открытые данные.</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <returns>
    /// Зашифрованные данные в формате:
    /// версия | IV | ciphertext | HMAC-SHA256.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="data"/> или <paramref name="key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">Длина ключа не равна 32 байтам.</exception>
    /// <exception cref="CryptographicException">Ошибка криптографической операции.</exception>
    internal static byte[] Encrypt(byte[] data, byte[] key)
    {
        const string method = nameof(Encrypt);

        try
        {
            if (data is null)
                throw new ArgumentNullException(nameof(data));

            ValidateKey(key);

            byte[] aesKey;
            byte[] hmacKey;
            DeriveKeys(key, out aesKey, out hmacKey);

            try
            {
                byte[] iv;
                byte[] cipherText;

                using (Aes aes = Aes.Create())
                {
                    aes.Key = aesKey;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.GenerateIV();
                    iv = aes.IV;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        cipherText = encryptor.TransformFinalBlock(data, 0, data.Length);
                    }
                }

                int resultLength = 1 + IvSizeBytes + cipherText.Length + HmacSizeBytes;
                byte[] result = new byte[resultLength];
                result[0] = FormatVersion;
                Buffer.BlockCopy(iv, 0, result, 1, IvSizeBytes);
                Buffer.BlockCopy(cipherText, 0, result, 1 + IvSizeBytes, cipherText.Length);

                using (HMACSHA256 hmac = new HMACSHA256(hmacKey))
                {
                    byte[] mac = hmac.ComputeHash(result, 0, result.Length - HmacSizeBytes);
                    Buffer.BlockCopy(mac, 0, result, result.Length - HmacSizeBytes, HmacSizeBytes);
                }

                Log.Debug(
                    "Данные зашифрованы. PlainLength={PlainLength}, CipherLength={CipherLength}. Class={Class}, Method={Method}",
                    data.Length, result.Length, ClassName, method);

                return result;
            }
            finally
            {
                ClearKeyMaterial(aesKey);
                ClearKeyMaterial(hmacKey);
            }
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (ArgumentException)
        {
            throw;
        }
        catch (CryptographicException ex)
        {
            Log.Error(ex,
                "Ошибка шифрования. Class={Class}, Method={Method}",
                ClassName, method);
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    /// <summary>
    /// Шифрует массив байтов, используя ключ в Base64-формате.
    /// </summary>
    /// <param name="data">Открытые данные.</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <returns>Зашифрованные данные (версия | IV | ciphertext | MAC).</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="data"/> или <paramref name="base64Key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка ключа.</exception>
    /// <exception cref="ArgumentException">Длина ключа после декодирования не равна 32 байтам.</exception>
    /// <exception cref="CryptographicException">Ошибка криптографической операции.</exception>
    internal static byte[] Encrypt(byte[] data, string base64Key)
    {
        const string method = nameof(Encrypt);

        try
        {
            if (base64Key is null)
                throw new ArgumentNullException(nameof(base64Key));

            byte[] key = Convert.FromBase64String(base64Key);
            try
            {
                return Encrypt(data, key);
            }
            finally
            {
                ClearKeyMaterial(key);
            }
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (FormatException ex)
        {
            Log.Warning(ex,
                "Некорректный Base64-ключ. Class={Class}, Method={Method}",
                ClassName, method);
            throw;
        }
        catch (Exception ex) when (ex is not ArgumentException and not CryptographicException)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    #endregion

    #region Шифрование string

    /// <summary>
    /// Шифрует строку (UTF-8). Результат возвращается в Base64.
    /// </summary>
    /// <param name="plainText">Открытый текст.</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <returns>Зашифрованные данные в Base64.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="plainText"/> или <paramref name="key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">Длина ключа не равна 32 байтам.</exception>
    /// <exception cref="CryptographicException">Ошибка криптографической операции.</exception>
    internal static string Encrypt(string plainText, byte[] key)
    {
        const string method = nameof(Encrypt);

        try
        {
            if (plainText is null)
                throw new ArgumentNullException(nameof(plainText));

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = Encrypt(plainBytes, key);
            return Convert.ToBase64String(encryptedBytes);
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (ArgumentException)
        {
            throw;
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    /// <summary>
    /// Шифрует строку, используя ключ в Base64-формате.
    /// Результат возвращается в Base64.
    /// </summary>
    /// <param name="plainText">Открытый текст.</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <returns>Зашифрованные данные в Base64.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="plainText"/> или <paramref name="base64Key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка ключа.</exception>
    /// <exception cref="ArgumentException">Длина ключа после декодирования не равна 32 байтам.</exception>
    /// <exception cref="CryptographicException">Ошибка криптографической операции.</exception>
    internal static string Encrypt(string plainText, string base64Key)
    {
        const string method = nameof(Encrypt);

        try
        {
            if (plainText is null)
                throw new ArgumentNullException(nameof(plainText));
            if (base64Key is null)
                throw new ArgumentNullException(nameof(base64Key));

            byte[] key = Convert.FromBase64String(base64Key);
            try
            {
                return Encrypt(plainText, key);
            }
            finally
            {
                ClearKeyMaterial(key);
            }
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (FormatException ex)
        {
            Log.Warning(ex,
                "Некорректный Base64-ключ. Class={Class}, Method={Method}",
                ClassName, method);
            throw;
        }
        catch (Exception ex) when (ex is not ArgumentException and not CryptographicException)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    #endregion

    #region Расшифровка byte[]

    /// <summary>
    /// Расшифровывает массив байтов, ранее полученный методом <see cref="Encrypt(byte[], byte[])"/>.
    /// </summary>
    /// <param name="encryptedData">Зашифрованные данные (версия | IV | ciphertext | MAC).</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <returns>Открытые данные.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="encryptedData"/> или <paramref name="key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">Длина ключа не равна 32 байтам.</exception>
    /// <exception cref="CryptographicException">
    /// Некорректный формат, неверная версия, сбой проверки MAC или ошибка расшифровки.
    /// </exception>
    internal static byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        const string method = nameof(Decrypt);

        try
        {
            if (encryptedData is null)
                throw new ArgumentNullException(nameof(encryptedData));

            ValidateKey(key);

            int minimumLength = 1 + IvSizeBytes + CipherBlockSizeBytes + HmacSizeBytes;
            if (encryptedData.Length < minimumLength)
            {
                Log.Warning(
                    "Некорректные зашифрованные данные: недостаточная длина. Length={Length}. Class={Class}, Method={Method}",
                    encryptedData.Length, ClassName, method);
                throw new CryptographicException("Некорректные зашифрованные данные.");
            }

            if (encryptedData[0] != FormatVersion)
            {
                Log.Warning(
                    "Неподдерживаемая версия формата шифрования. Version={Version}. Class={Class}, Method={Method}",
                    encryptedData[0], ClassName, method);
                throw new CryptographicException("Неподдерживаемая версия формата шифрования.");
            }

            int cipherTextLength = encryptedData.Length - 1 - IvSizeBytes - HmacSizeBytes;
            if (cipherTextLength <= 0 || cipherTextLength % CipherBlockSizeBytes != 0)
            {
                Log.Warning(
                    "Некорректная длина ciphertext. CipherTextLength={CipherTextLength}. Class={Class}, Method={Method}",
                    cipherTextLength, ClassName, method);
                throw new CryptographicException("Некорректная длина зашифрованных данных.");
            }

            byte[] aesKey;
            byte[] hmacKey;
            DeriveKeys(key, out aesKey, out hmacKey);

            try
            {
                int macOffset = encryptedData.Length - HmacSizeBytes;

                using (HMACSHA256 hmac = new HMACSHA256(hmacKey))
                {
                    byte[] expectedMac = hmac.ComputeHash(encryptedData, 0, macOffset);

                    // Сравнение MAC за постоянное время (реализация BCL) — защита от timing-атак
                    bool isValidMac = CryptographicOperations.FixedTimeEquals(
                        expectedMac,
                        encryptedData.AsSpan(macOffset, HmacSizeBytes));
                    if (!isValidMac)
                    {
                        Log.Warning(
                            "Проверка целостности данных не пройдена. Class={Class}, Method={Method}",
                            ClassName, method);
                        throw new CryptographicException("Проверка целостности данных не пройдена.");
                    }
                }

                byte[] iv = new byte[IvSizeBytes];
                byte[] cipherText = new byte[cipherTextLength];
                Buffer.BlockCopy(encryptedData, 1, iv, 0, IvSizeBytes);
                Buffer.BlockCopy(encryptedData, 1 + IvSizeBytes, cipherText, 0, cipherTextLength);

                byte[] plainText;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = aesKey;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.IV = iv;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        plainText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                    }
                }

                Log.Debug(
                    "Данные расшифрованы. CipherLength={CipherLength}, PlainLength={PlainLength}. Class={Class}, Method={Method}",
                    encryptedData.Length, plainText.Length, ClassName, method);

                return plainText;
            }
            finally
            {
                ClearKeyMaterial(aesKey);
                ClearKeyMaterial(hmacKey);
            }
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (ArgumentException)
        {
            throw;
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    /// <summary>
    /// Расшифровывает массив байтов, используя ключ в Base64-формате.
    /// </summary>
    /// <param name="encryptedData">Зашифрованные данные.</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <returns>Открытые данные.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="encryptedData"/> или <paramref name="base64Key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка ключа.</exception>
    /// <exception cref="ArgumentException">Длина ключа после декодирования не равна 32 байтам.</exception>
    /// <exception cref="CryptographicException">Ошибка проверки целостности или расшифровки.</exception>
    internal static byte[] Decrypt(byte[] encryptedData, string base64Key)
    {
        const string method = nameof(Decrypt);

        try
        {
            if (base64Key is null)
                throw new ArgumentNullException(nameof(base64Key));

            byte[] key = Convert.FromBase64String(base64Key);
            try
            {
                return Decrypt(encryptedData, key);
            }
            finally
            {
                ClearKeyMaterial(key);
            }
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (FormatException ex)
        {
            Log.Warning(ex,
                "Некорректный Base64-ключ. Class={Class}, Method={Method}",
                ClassName, method);
            throw;
        }
        catch (Exception ex) when (ex is not ArgumentException and not CryptographicException)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    #endregion

    #region Расшифровка string

    /// <summary>
    /// Расшифровывает строку в Base64-формате (UTF-8).
    /// </summary>
    /// <param name="encryptedBase64">Зашифрованные данные в Base64.</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <returns>Открытый текст.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="encryptedBase64"/> или <paramref name="key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка данных.</exception>
    /// <exception cref="ArgumentException">Длина ключа не равна 32 байтам.</exception>
    /// <exception cref="CryptographicException">Ошибка проверки целостности или расшифровки.</exception>
    internal static string Decrypt(string encryptedBase64, byte[] key)
    {
        const string method = nameof(Decrypt);

        try
        {
            if (encryptedBase64 is null)
                throw new ArgumentNullException(nameof(encryptedBase64));

            byte[] encryptedData = Convert.FromBase64String(encryptedBase64);
            byte[] plainBytes = Decrypt(encryptedData, key);
            return Encoding.UTF8.GetString(plainBytes);
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (FormatException ex)
        {
            Log.Warning(ex,
                "Некорректная Base64-строка зашифрованных данных. Class={Class}, Method={Method}",
                ClassName, method);
            throw;
        }
        catch (ArgumentException)
        {
            throw;
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    /// <summary>
    /// Расшифровывает строку в Base64-формате, используя ключ в Base64-формате.
    /// </summary>
    /// <param name="encryptedBase64">Зашифрованные данные в Base64.</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <returns>Открытый текст.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="encryptedBase64"/> или <paramref name="base64Key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка.</exception>
    /// <exception cref="ArgumentException">Длина ключа после декодирования не равна 32 байтам.</exception>
    /// <exception cref="CryptographicException">Ошибка проверки целостности или расшифровки.</exception>
    internal static string Decrypt(string encryptedBase64, string base64Key)
    {
        const string method = nameof(Decrypt);

        try
        {
            if (encryptedBase64 is null)
                throw new ArgumentNullException(nameof(encryptedBase64));
            if (base64Key is null)
                throw new ArgumentNullException(nameof(base64Key));

            byte[] key = Convert.FromBase64String(base64Key);
            try
            {
                return Decrypt(encryptedBase64, key);
            }
            finally
            {
                ClearKeyMaterial(key);
            }
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (FormatException ex)
        {
            Log.Warning(ex,
                "Некорректная Base64-строка. Class={Class}, Method={Method}",
                ClassName, method);
            throw;
        }
        catch (Exception ex) when (ex is not ArgumentException and not CryptographicException)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    #endregion

    #region Вспомогательные методы

    /// <summary>
    /// Проверяет, что мастер-ключ не равен <see langword="null"/> и имеет длину 32 байта.
    /// </summary>
    private static void ValidateKey(byte[] key)
    {
        if (key is null)
            throw new ArgumentNullException(nameof(key));

        if (key.Length != MasterKeySizeBytes)
        {
            throw new ArgumentException(
                $"Ключ должен содержать {MasterKeySizeBytes} байт. Используйте CreateKey или CreateKeyBase64.",
                nameof(key));
        }
    }

    /// <summary>
    /// Выводит из мастер-ключа отдельные ключи для AES и HMAC (HMAC-SHA256-KDF по меткам).
    /// </summary>
    private static void DeriveKeys(byte[] masterKey, out byte[] aesKey, out byte[] hmacKey)
    {
        using (HMACSHA256 kdf = new HMACSHA256(masterKey))
        {
            aesKey = kdf.ComputeHash(AesKeyDerivationLabel);
            hmacKey = kdf.ComputeHash(HmacKeyDerivationLabel);
        }
    }

    /// <summary>
    /// Обнуляет массив с ключевым материалом в памяти.
    /// </summary>
    private static void ClearKeyMaterial(byte[]? key)
    {
        if (key is null)
            return;

        Array.Clear(key, 0, key.Length);
    }

    #endregion
}