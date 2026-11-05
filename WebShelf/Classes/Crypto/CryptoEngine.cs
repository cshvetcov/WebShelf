using System.Security.Cryptography;
using System.Text;

namespace WebShelf.Classes.Crypto;

/// <summary>
/// Криптографический движок: синхронное шифрование AES-256-CBC + HMAC-SHA256
/// (Encrypt-then-MAC). Формат полезной нагрузки: версия (1 байт) | IV (16) |
/// ciphertext (PKCS7) | MAC (32).
/// </summary>
/// <remarks>
/// Проверка целостности (MAC, сравнение за постоянное время) выполняется
/// <b>до</b> расшифровки AES; ключевой материал обнуляется в <c>finally</c>.
/// Класс выделен из <c>EncryptionService</c> механическим переносом (шаг 4
/// дорожной карты декомпозиции); изменения при переносе — только константа
/// <c>Class=</c> в логах перенесённого кода (принцип 6 дорожной карты).
/// Криптоформат заморожен: в <c>Server.conf</c> рабочих инсталляций лежат
/// данные в этом формате, изменение любого байта схемы (версия, метки вывода
/// ключей, порядок полей, алгоритмы) делает конфиги нечитаемыми.
/// Движок не зависит от реестра и DPAPI и работает с явно переданным ключом —
/// тестируется на любой ОС. Шаг 8 дорожной карты (улучшение У3): класс
/// переведён со статического на инстансный и регистрируется в DI как готовый
/// singleton (<c>AddSingleton(instance)</c>); перегрузки объявлены
/// <see langword="virtual"/>, чтобы юнит-тесты могли подменять движок фейком.
/// Поведение не изменилось: движок не содержит состояния.
/// </remarks>
internal class CryptoEngine
{
    private const string ClassName = "WebShelf.Classes.Crypto.CryptoEngine";

    private const byte FormatVersion = 1;

    private const int MasterKeySizeBytes = 32;
    private const int IvSizeBytes = 16;
    private const int HmacSizeBytes = 32;
    private const int CipherBlockSizeBytes = 16;

    // Метки вывода ключей — часть замороженного криптоформата (HMAC-SHA256-KDF по
    // меткам): значения перенесены из EncryptionService дословно и не меняются
    // при переименовании/перемещении класса (изменение метки = изменение формата).
    private static readonly byte[] AesKeyDerivationLabel = Encoding.UTF8.GetBytes("WebShelf.Classes.Service.EncryptionService.AES.v1");

    private static readonly byte[] HmacKeyDerivationLabel = Encoding.UTF8.GetBytes("WebShelf.Classes.Service.EncryptionService.HMAC.v1");

    /// <summary>
    /// Создаёт экземпляр <see cref="CryptoEngine"/>.
    /// Производственный код создаёт один экземпляр в <c>Program.Main</c>
    /// и регистрирует его в DI как singleton; движок не содержит состояния.
    /// </summary>
    public CryptoEngine()
    {
    }

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
    internal virtual byte[] Encrypt(byte[] data, byte[] key)
    {
        const string method = nameof(Encrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(data);

            ValidateKey(key);

            DeriveKeys(key, out byte[] aesKey, out byte[] hmacKey);

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

                    using ICryptoTransform encryptor = aes.CreateEncryptor();
                    cipherText = encryptor.TransformFinalBlock(data, 0, data.Length);
                }

                int resultLength = 1 + IvSizeBytes + cipherText.Length + HmacSizeBytes;
                byte[] result = new byte[resultLength];
                result[0] = FormatVersion;
                Buffer.BlockCopy(iv, 0, result, 1, IvSizeBytes);
                Buffer.BlockCopy(cipherText, 0, result, 1 + IvSizeBytes, cipherText.Length);

                using HMACSHA256 hmac = new(hmacKey);
                byte[] mac = hmac.ComputeHash(result, 0, result.Length - HmacSizeBytes);
                Buffer.BlockCopy(mac, 0, result, result.Length - HmacSizeBytes, HmacSizeBytes);

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
    internal virtual byte[] Encrypt(byte[] data, string base64Key)
    {
        const string method = nameof(Encrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(base64Key);

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
    internal virtual string Encrypt(string plainText, byte[] key)
    {
        const string method = nameof(Encrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(plainText);

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
    internal virtual string Encrypt(string plainText, string base64Key)
    {
        const string method = nameof(Encrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(plainText);
            ArgumentNullException.ThrowIfNull(base64Key);

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
    internal virtual byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        const string method = nameof(Decrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(encryptedData);

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

            DeriveKeys(key, out byte[] aesKey, out byte[] hmacKey);

            try
            {
                int macOffset = encryptedData.Length - HmacSizeBytes;

                using HMACSHA256 hmac = new(hmacKey);
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

                    using ICryptoTransform decryptor = aes.CreateDecryptor();
                    plainText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
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
    internal virtual byte[] Decrypt(byte[] encryptedData, string base64Key)
    {
        const string method = nameof(Decrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(base64Key);

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
    internal virtual string Decrypt(string encryptedBase64, byte[] key)
    {
        const string method = nameof(Decrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(encryptedBase64);

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
    internal virtual string Decrypt(string encryptedBase64, string base64Key)
    {
        const string method = nameof(Decrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(encryptedBase64);
            ArgumentNullException.ThrowIfNull(base64Key);

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
        ArgumentNullException.ThrowIfNull(key);

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
        using HMACSHA256 kdf = new(masterKey);
        aesKey = kdf.ComputeHash(AesKeyDerivationLabel);
        hmacKey = kdf.ComputeHash(HmacKeyDerivationLabel);
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
