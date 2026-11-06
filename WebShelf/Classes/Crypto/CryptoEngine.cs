using System.Security.Cryptography;
using System.Text;

namespace WebShelf.Classes.Crypto;

/// <summary>
/// Криптографический движок: синхронное аутентифицированное шифрование
/// AES-256-GCM (AEAD). Формат полезной нагрузки: версия (1 байт) | nonce (12) |
/// ciphertext | тег аутентификации (16).
/// </summary>
/// <remarks>
/// Ключ AES-256 выводится из мастер-ключа через HKDF-SHA256 (RFC 5869) по
/// замороженной метке; ключевой материал обнуляется в <c>finally</c>.
/// Аутентификация выполняется самим режимом GCM: тег покрывает nonce,
/// ciphertext и дополнительные аутентифицированные данные (AAD), отдельная
/// проверка MAC и сравнение за постоянное время не требуются — критическая
/// операция реализована внутри BCL.
/// <para>
/// Дополнительные аутентифицированные данные (AAD) = версия формата ‖ контекст
/// вызова. Каждый вызов <see cref="Encrypt(byte[], byte[], string)"/> и
/// <see cref="Decrypt(byte[], byte[], string)"/> обязан передавать непустой
/// контекст — метку назначения данных (см. <see cref="CryptoContexts"/>).
/// Контекст привязывает шифроблоб к конкретному полю Server.conf или внутреннему
/// полю класса: блоб, зашифрованный в одном контексте, не расшифровывается в
/// другом, поэтому перестановка зашифрованных значений между полями конфигурации
/// невозможна.
/// </para>
/// <para>
/// Криптоформат заморожен: в <c>Server.conf</c> инсталляций лежат данные в этом
/// формате, изменение любого байта схемы (версия, метка и соль вывода ключа,
/// порядок полей, состав AAD, алгоритмы) делает конфиги нечитаемыми. Формат
/// зафиксирован эталонной константой совместимости в <c>CryptoEngineTests</c>.
/// </para>
/// <para>
/// Nonce — случайные 96 бит (<see cref="RandomNumberGenerator"/>). Ограничение
/// NIST SP 800-38D на случайные nonce: не более 2^32 шифрований на ключ.
/// Для объёмов <c>Server.conf</c> (единичные записи при записи учётных данных)
/// запас избыточен; формат не предназначен для шифрования крупных массивов
/// данных.
/// </para>
/// Движок не зависит от реестра и DPAPI и работает с явно переданным ключом —
/// тестируется на любой ОС. Регистрируется в DI как готовый singleton
/// (<c>AddSingleton(instance)</c>); перегрузки объявлены
/// <see langword="virtual"/>, чтобы юнит-тесты могли подменять движок фейком.
/// Движок не содержит состояния.
/// </remarks>
internal class CryptoEngine
{
    private const string ClassName = "WebShelf.Classes.Crypto.CryptoEngine";

    private const byte FormatVersion = 2;

    private const int MasterKeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int AesKeySizeBytes = 32;

    // Метка вывода ключа HKDF — часть замороженного криптоформата: значение
    // не меняется при переименовании/перемещении класса (изменение метки =
    // изменение формата).
    private static readonly byte[] AesKeyDerivationLabel = Encoding.UTF8.GetBytes("WebShelf.Classes.Crypto.CryptoEngine.AES-GCM.v2");

    // Соль HKDF — 32 нулевых байта: значение по умолчанию RFC 5869, задано
    // явно, чтобы вывод ключей не зависел от обработки null в перегрузках BCL.
    // Часть замороженного криптоформата.
    private static readonly byte[] HkdfSalt = new byte[32];

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
    /// Шифрует массив байтов (AES-256-GCM, AEAD).
    /// </summary>
    /// <param name="data">Открытые данные (допускается пустой массив).</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <param name="context">Контекст шифрования — метка назначения данных
    /// (см. <see cref="CryptoContexts"/>); подмешивается в AAD и привязывает
    /// блоб к назначению.</param>
    /// <returns>
    /// Зашифрованные данные в формате:
    /// версия | nonce | ciphertext | тег аутентификации GCM.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="data"/> или <paramref name="key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">Длина ключа не равна 32 байтам
    /// или контекст пустой.</exception>
    /// <exception cref="CryptographicException">Ошибка криптографической операции.</exception>
    internal virtual byte[] Encrypt(byte[] data, byte[] key, string context)
    {
        const string method = nameof(Encrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(data);

            ValidateKey(key);
            ValidateContext(context);

            byte[] aesKey = DeriveAesKey(key);

            try
            {
                byte[] associatedData = BuildAssociatedData(context);
                byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
                byte[] cipherText = new byte[data.Length];
                byte[] tag = new byte[TagSizeBytes];

                using (AesGcm aesGcm = new(aesKey, TagSizeBytes))
                {
                    aesGcm.Encrypt(nonce, data, cipherText, tag, associatedData);
                }

                int resultLength = 1 + NonceSizeBytes + cipherText.Length + TagSizeBytes;
                byte[] result = new byte[resultLength];
                result[0] = FormatVersion;
                Buffer.BlockCopy(nonce, 0, result, 1, NonceSizeBytes);
                Buffer.BlockCopy(cipherText, 0, result, 1 + NonceSizeBytes, cipherText.Length);
                Buffer.BlockCopy(tag, 0, result, 1 + NonceSizeBytes + cipherText.Length, TagSizeBytes);

                Log.Debug(
                    "Данные зашифрованы. PlainLength={PlainLength}, CipherLength={CipherLength}, Context={Context}. Class={Class}, Method={Method}",
                    data.Length, result.Length, context, ClassName, method);

                return result;
            }
            finally
            {
                ClearKeyMaterial(aesKey);
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
    /// <param name="data">Открытые данные (допускается пустой массив).</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <param name="context">Контекст шифрования — метка назначения данных
    /// (см. <see cref="CryptoContexts"/>); подмешивается в AAD и привязывает
    /// блоб к назначению.</param>
    /// <returns>Зашифрованные данные (версия | nonce | ciphertext | тег).</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="data"/> или <paramref name="base64Key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка ключа.</exception>
    /// <exception cref="ArgumentException">Длина ключа после декодирования не равна 32 байтам
    /// или контекст пустой.</exception>
    /// <exception cref="CryptographicException">Ошибка криптографической операции.</exception>
    internal virtual byte[] Encrypt(byte[] data, string base64Key, string context)
    {
        const string method = nameof(Encrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(base64Key);

            byte[] key = Convert.FromBase64String(base64Key);
            try
            {
                return Encrypt(data, key, context);
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
    /// <param name="context">Контекст шифрования — метка назначения данных
    /// (см. <see cref="CryptoContexts"/>); подмешивается в AAD и привязывает
    /// блоб к назначению.</param>
    /// <returns>Зашифрованные данные в Base64.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="plainText"/> или <paramref name="key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">Длина ключа не равна 32 байтам
    /// или контекст пустой.</exception>
    /// <exception cref="CryptographicException">Ошибка криптографической операции.</exception>
    internal virtual string Encrypt(string plainText, byte[] key, string context)
    {
        const string method = nameof(Encrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(plainText);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = Encrypt(plainBytes, key, context);
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
    /// <param name="context">Контекст шифрования — метка назначения данных
    /// (см. <see cref="CryptoContexts"/>); подмешивается в AAD и привязывает
    /// блоб к назначению.</param>
    /// <returns>Зашифрованные данные в Base64.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="plainText"/> или <paramref name="base64Key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка ключа.</exception>
    /// <exception cref="ArgumentException">Длина ключа после декодирования не равна 32 байтам
    /// или контекст пустой.</exception>
    /// <exception cref="CryptographicException">Ошибка криптографической операции.</exception>
    internal virtual string Encrypt(string plainText, string base64Key, string context)
    {
        const string method = nameof(Encrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(plainText);
            ArgumentNullException.ThrowIfNull(base64Key);

            byte[] key = Convert.FromBase64String(base64Key);
            try
            {
                return Encrypt(plainText, key, context);
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
    /// Расшифровывает массив байтов, ранее полученный методом
    /// <see cref="Encrypt(byte[], byte[], string)"/> в том же контексте.
    /// </summary>
    /// <param name="encryptedData">Зашифрованные данные
    /// (версия | nonce | ciphertext | тег).</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <param name="context">Контекст шифрования — тот же, что использовался
    /// при шифровании; расшифровка в чужом контексте завершается сбоем
    /// проверки тега.</param>
    /// <returns>Открытые данные.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="encryptedData"/> или <paramref name="key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">Длина ключа не равна 32 байтам
    /// или контекст пустой.</exception>
    /// <exception cref="CryptographicException">
    /// Некорректный формат, неверная версия, сбой проверки тега
    /// (подмена данных, чужой ключ или чужой контекст) или ошибка расшифровки.
    /// </exception>
    internal virtual byte[] Decrypt(byte[] encryptedData, byte[] key, string context)
    {
        const string method = nameof(Decrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(encryptedData);

            ValidateKey(key);
            ValidateContext(context);

            int minimumLength = 1 + NonceSizeBytes + TagSizeBytes;
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

            byte[] aesKey = DeriveAesKey(key);

            try
            {
                int cipherTextLength = encryptedData.Length - 1 - NonceSizeBytes - TagSizeBytes;

                byte[] nonce = new byte[NonceSizeBytes];
                byte[] cipherText = new byte[cipherTextLength];
                byte[] tag = new byte[TagSizeBytes];
                Buffer.BlockCopy(encryptedData, 1, nonce, 0, NonceSizeBytes);
                Buffer.BlockCopy(encryptedData, 1 + NonceSizeBytes, cipherText, 0, cipherTextLength);
                Buffer.BlockCopy(encryptedData, 1 + NonceSizeBytes + cipherTextLength, tag, 0, TagSizeBytes);

                byte[] associatedData = BuildAssociatedData(context);
                byte[] plainText = new byte[cipherTextLength];

                using AesGcm aesGcm = new(aesKey, TagSizeBytes);
                try
                {
                    aesGcm.Decrypt(nonce, cipherText, tag, plainText, associatedData);
                }
                catch (CryptographicException ex)
                {
                    // Сбой тега GCM: подмена данных, чужой ключ или чужой контекст AAD
                    Log.Warning(ex,
                        "Проверка целостности данных не пройдена. Context={Context}. Class={Class}, Method={Method}",
                        context, ClassName, method);
                    throw new CryptographicException("Проверка целостности данных не пройдена.");
                }

                Log.Debug(
                    "Данные расшифрованы. CipherLength={CipherLength}, PlainLength={PlainLength}, Context={Context}. Class={Class}, Method={Method}",
                    encryptedData.Length, plainText.Length, context, ClassName, method);

                return plainText;
            }
            finally
            {
                ClearKeyMaterial(aesKey);
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
    /// <param name="encryptedData">Зашифрованные данные
    /// (версия | nonce | ciphertext | тег).</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <param name="context">Контекст шифрования — тот же, что использовался
    /// при шифровании; расшифровка в чужом контексте завершается сбоем
    /// проверки тега.</param>
    /// <returns>Открытые данные.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="encryptedData"/> или <paramref name="base64Key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка ключа.</exception>
    /// <exception cref="ArgumentException">Длина ключа после декодирования не равна 32 байтам
    /// или контекст пустой.</exception>
    /// <exception cref="CryptographicException">Ошибка проверки тега или расшифровки.</exception>
    internal virtual byte[] Decrypt(byte[] encryptedData, string base64Key, string context)
    {
        const string method = nameof(Decrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(base64Key);

            byte[] key = Convert.FromBase64String(base64Key);
            try
            {
                return Decrypt(encryptedData, key, context);
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
    /// <param name="context">Контекст шифрования — тот же, что использовался
    /// при шифровании; расшифровка в чужом контексте завершается сбоем
    /// проверки тега.</param>
    /// <returns>Открытый текст.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="encryptedBase64"/> или <paramref name="key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка данных.</exception>
    /// <exception cref="ArgumentException">Длина ключа не равна 32 байтам
    /// или контекст пустой.</exception>
    /// <exception cref="CryptographicException">Ошибка проверки тега или расшифровки.</exception>
    internal virtual string Decrypt(string encryptedBase64, byte[] key, string context)
    {
        const string method = nameof(Decrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(encryptedBase64);

            byte[] encryptedData = Convert.FromBase64String(encryptedBase64);
            byte[] plainBytes = Decrypt(encryptedData, key, context);
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
    /// <param name="context">Контекст шифрования — тот же, что использовался
    /// при шифровании; расшифровка в чужом контексте завершается сбоем
    /// проверки тега.</param>
    /// <returns>Открытый текст.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="encryptedBase64"/> или <paramref name="base64Key"/> равен <see langword="null"/>.
    /// </exception>
    /// <exception cref="FormatException">Некорректная Base64-строка.</exception>
    /// <exception cref="ArgumentException">Длина ключа после декодирования не равна 32 байтам
    /// или контекст пустой.</exception>
    /// <exception cref="CryptographicException">Ошибка проверки тега или расшифровки.</exception>
    internal virtual string Decrypt(string encryptedBase64, string base64Key, string context)
    {
        const string method = nameof(Decrypt);

        try
        {
            ArgumentNullException.ThrowIfNull(encryptedBase64);
            ArgumentNullException.ThrowIfNull(base64Key);

            byte[] key = Convert.FromBase64String(base64Key);
            try
            {
                return Decrypt(encryptedBase64, key, context);
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
    /// Проверяет, что контекст шифрования задан и не пустой: контекст обязателен —
    /// он привязывает блоб к назначению через AAD.
    /// </summary>
    private static void ValidateContext(string context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (string.IsNullOrWhiteSpace(context))
        {
            throw new ArgumentException(
                "Контекст шифрования не может быть пустым. Укажите назначение данных (см. CryptoContexts).",
                nameof(context));
        }
    }

    /// <summary>
    /// Строит дополнительные аутентифицированные данные (AAD) GCM:
    /// версия формата ‖ UTF-8-байты контекста. Состав AAD — часть
    /// замороженного криптоформата.
    /// </summary>
    private static byte[] BuildAssociatedData(string context)
    {
        byte[] contextBytes = Encoding.UTF8.GetBytes(context);
        byte[] associatedData = new byte[1 + contextBytes.Length];
        associatedData[0] = FormatVersion;
        Buffer.BlockCopy(contextBytes, 0, associatedData, 1, contextBytes.Length);
        return associatedData;
    }

    /// <summary>
    /// Выводит из мастер-ключа ключ AES-256 (HKDF-SHA256 по замороженной метке,
    /// RFC 5869; соль — 32 нулевых байта).
    /// </summary>
    private static byte[] DeriveAesKey(byte[] masterKey)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, AesKeySizeBytes, HkdfSalt, AesKeyDerivationLabel);
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
