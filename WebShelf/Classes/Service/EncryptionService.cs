using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using Serilog;

namespace WebShelf.Classes.Service;

/// <summary>
/// Статический сервис синхронного шифрования.
/// Реализация: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).
/// Формат полезной нагрузки: версия (1 байт) | IV (16) | ciphertext | MAC (32).
/// Мастер-ключ хранится в <c>HKEY_CURRENT_USER</c> под защитой DPAPI
/// (<see cref="DataProtectionScope.CurrentUser"/>) с кэшированием в памяти
/// (sliding TTL + absolute max).
/// </summary>
/// <remarks>
/// Ключ привязан к учётной записи процесса. В Production сервис должен
/// работать под выделенной служебной учёткой (например, DOMAIN\svc_webshelf),
/// чтобы HKCU и DPAPI относились к ней, а не к интерактивному пользователю.
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

    /// <summary>Путь ключа реестра относительно <c>HKEY_CURRENT_USER</c>.</summary>
    private const string RegistryKeyPath = @"Software\WebShelf\Encryption";

    /// <summary>Имя значения реестра с защищённым мастер-ключом.</summary>
    private const string RegistryValueName = "MasterKey";

    /// <summary>Всегда CurrentUser: ключ привязан к identity процесса.</summary>
    private const DataProtectionScope ProtectionScope = DataProtectionScope.CurrentUser;

    /// <summary>Sliding-окно: продлевается при каждом использовании кэша.</summary>
    private static readonly TimeSpan MasterKeyCacheTtl = TimeSpan.FromMinutes(5);

    /// <summary>Максимальное время непрерывного хранения ключа в кэше (absolute cap).</summary>
    private static readonly TimeSpan MasterKeyCacheAbsoluteMax = TimeSpan.FromMinutes(30);

    private static readonly object MasterKeyCacheSync = new();

    /// <summary>
    /// Синхронизация чтения/генерации/записи мастер-ключа в реестр:
    /// исключает гонку при первом параллельном вызове EnsureMasterKey.
    /// </summary>
    private static readonly object RegistrySync = new();
    private static byte[]? _cachedMasterKey;
    private static DateTimeOffset _cachedMasterKeyExpiresUtc = DateTimeOffset.MinValue;
    private static DateTimeOffset _cachedMasterKeyLoadedUtc = DateTimeOffset.MinValue;

    #region Создание ключа

    /// <summary>
    /// Создаёт новый случайный мастер-ключ размером 32 байта.
    /// </summary>
    /// <returns>Массив из 32 криптографически стойких случайных байт.</returns>
    /// <exception cref="CryptographicException">При сбое генератора случайных чисел.</exception>
    internal static byte[] CreateKey()
    {
        const string method = nameof(CreateKey);

        try
        {
            byte[] key = new byte[MasterKeySizeBytes];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            Log.Debug(
                "Создан новый мастер-ключ. Class={Class}, Method={Method}",
                ClassName, method);

            return key;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    /// <summary>
    /// Создаёт новый случайный мастер-ключ и возвращает его в виде Base64-строки.
    /// </summary>
    /// <returns>Ключ в кодировке Base64.</returns>
    /// <exception cref="CryptographicException">При сбое генератора случайных чисел.</exception>
    internal static string CreateKeyBase64()
    {
        const string method = nameof(CreateKeyBase64);

        try
        {
            byte[] key = CreateKey();
            try
            {
                return Convert.ToBase64String(key);
            }
            finally
            {
                ClearKeyMaterial(key);
            }
        }
        catch (Exception ex) when (ex is not CryptographicException)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }

    #endregion

    #region Master key (HKCU + DPAPI CurrentUser + кэш)

    /// <summary>
    /// Обеспечивает наличие мастер-ключа: читает из <c>HKEY_CURRENT_USER</c> (DPAPI CurrentUser),
    /// при отсутствии создаёт и сохраняет. При успехе возвращает ключ (копию),
    /// при ошибке — <see langword="null"/>.
    /// </summary>
    /// <param name="key">
    /// Готовый ключ (32 байта). Если не <see langword="null"/>, генерация не выполняется —
    /// ключ проверяется, защищается DPAPI и записывается в реестр (при необходимости).
    /// </param>
    /// <returns>
    /// Копия мастер-ключа (32 байта) или <see langword="null"/>,
    /// если не удалось прочитать/сохранить либо формат ключа некорректен.
    /// </returns>
    /// <remarks>
    /// Хранение всегда в HKCU под <see cref="DataProtectionScope.CurrentUser"/>.
    /// Расшифровать blob может только код, работающий под той же учётной записью Windows.
    /// В памяти ключ кэшируется со sliding TTL (5 мин) и absolute max (30 мин).
    /// </remarks>
    internal static byte[]? EnsureMasterKey(byte[]? key = null)
    {
        const string method = nameof(EnsureMasterKey);

        try
        {
            // --- 1. Кэш ---
            byte[]? fromCache = TryGetCachedMasterKey();
            if (fromCache is not null)
            {
                if (key is not null)
                {
                    if (!IsValidMasterKey(key) || !CryptographicOperations.FixedTimeEquals(fromCache, key))
                    {
                        ClearKeyMaterial(fromCache);
                        Log.Warning(
                            "Переданный ключ не совпадает с кэшированным или имеет неверный формат. Class={Class}, Method={Method}",
                            ClassName, method);
                        return null;
                    }
                }

                Log.Debug(
                    "Мастер-ключ получен из кэша. Class={Class}, Method={Method}",
                    ClassName, method);
                return fromCache;
            }

            // --- 2. Валидация входного ключа (если задан) ---
            if (key is not null && !IsValidMasterKey(key))
            {
                Log.Warning(
                    "Некорректный формат переданного мастер-ключа. Length={Length}. Class={Class}, Method={Method}",
                    key.Length, ClassName, method);
                return null;
            }

            // --- 3. Чтение из HKCU и генерация — под блокировкой RegistrySync,
            // чтобы исключить гонку генерации при первом параллельном вызове ---
            lock (RegistrySync)
            {
                byte[]? storedProtected = TryReadProtectedKeyFromRegistry();
                if (storedProtected is not null)
                {
                    try
                    {
                        byte[] unprotected = ProtectedData.Unprotect(
                            storedProtected, optionalEntropy: null, ProtectionScope);
                        try
                        {
                            if (!IsValidMasterKey(unprotected))
                            {
                                Log.Warning(
                                    "Ключ из реестра имеет некорректную длину. Length={Length}. Class={Class}, Method={Method}",
                                    unprotected.Length, ClassName, method);
                                return null;
                            }

                            if (key is not null && !CryptographicOperations.FixedTimeEquals(unprotected, key))
                            {
                                Log.Warning(
                                    "Переданный ключ не совпадает с ключом в реестре. Class={Class}, Method={Method}",
                                    ClassName, method);
                                return null;
                            }

                            byte[] result = (byte[])unprotected.Clone();
                            SetCachedMasterKey(unprotected);

                            Log.Information(
                                "Мастер-ключ прочитан из HKCU. Class={Class}, Method={Method}",
                                ClassName, method);
                            return result;
                        }
                        finally
                        {
                            ClearKeyMaterial(unprotected);
                        }
                    }
                    catch (CryptographicException ex)
                    {
                        Log.Error(ex,
                            "Не удалось расшифровать мастер-ключ из реестра (DPAPI CurrentUser). Class={Class}, Method={Method}",
                            ClassName, method);
                        return null;
                    }
                    finally
                    {
                        ClearKeyMaterial(storedProtected);
                    }
                }

                // --- 4. Ключа в реестре нет: генерируем или берём переданный ---
                byte[] masterKey;
                bool generated;

                if (key is not null)
                {
                    masterKey = (byte[])key.Clone();
                    generated = false;
                }
                else
                {
                    masterKey = CreateKey();
                    generated = true;
                }

                try
                {
                    byte[] protectedBlob = ProtectedData.Protect(
                        masterKey, optionalEntropy: null, ProtectionScope);
                    try
                    {
                        if (!TryWriteProtectedKeyToRegistry(protectedBlob))
                        {
                            Log.Error(
                                "Не удалось записать мастер-ключ в HKCU. Class={Class}, Method={Method}",
                                ClassName, method);
                            ClearKeyMaterial(masterKey);
                            return null;
                        }
                    }
                    finally
                    {
                        ClearKeyMaterial(protectedBlob);
                    }

                    byte[] result = (byte[])masterKey.Clone();
                    SetCachedMasterKey(masterKey);

                    Log.Information(
                        "Мастер-ключ {Action} и сохранён в HKCU. Class={Class}, Method={Method}",
                        generated ? "сгенерирован" : "принят",
                        ClassName, method);

                    return result;
                }
                catch (CryptographicException ex)
                {
                    Log.Error(ex,
                        "Ошибка DPAPI при защите мастер-ключа. Class={Class}, Method={Method}",
                        ClassName, method);
                    ClearKeyMaterial(masterKey);
                    return null;
                }
                catch (UnauthorizedAccessException ex)
                {
                    Log.Error(ex,
                        "Нет прав на запись в HKCU. Class={Class}, Method={Method}",
                        ClassName, method);
                    ClearKeyMaterial(masterKey);
                    return null;
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Принудительно очищает кэш мастер-ключа (обнуление памяти).
    /// </summary>
    internal static void ClearMasterKeyCache()
    {
        const string method = nameof(ClearMasterKeyCache);

        try
        {
            lock (MasterKeyCacheSync)
            {
                ClearCachedMasterKey_NoLock();
            }

            Log.Debug(
                "Кэш мастер-ключа очищен. Class={Class}, Method={Method}",
                ClassName, method);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
        }
    }

    /// <summary>
    /// Проверяет, что массив — валидный мастер-ключ (ровно 32 байта).
    /// </summary>
    private static bool IsValidMasterKey(byte[]? key)
    {
        return key is not null && key.Length == MasterKeySizeBytes;
    }

    /// <summary>
    /// Читает защищённый блоб мастер-ключа из <c>HKEY_CURRENT_USER</c>.
    /// </summary>
    /// <returns>Защищённые байты или <see langword="null"/>, если значения нет или оно пустое.</returns>
    private static byte[]? TryReadProtectedKeyFromRegistry()
    {
        const string method = nameof(TryReadProtectedKeyFromRegistry);

        try
        {
            using RegistryKey? subKey = Registry.CurrentUser.OpenSubKey(RegistryKeyPath, writable: false);
            if (subKey is null)
                return null;

            object? value = subKey.GetValue(RegistryValueName);
            if (value is not byte[] blob || blob.Length == 0)
                return null;

            return (byte[])blob.Clone();
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка чтения мастер-ключа из HKCU. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Записывает защищённый блоб мастер-ключа в <c>HKEY_CURRENT_USER</c>.
    /// </summary>
    /// <returns><see langword="true"/> при успешной записи.</returns>
    private static bool TryWriteProtectedKeyToRegistry(byte[] protectedBlob)
    {
        const string method = nameof(TryWriteProtectedKeyToRegistry);

        try
        {
            using RegistryKey subKey = Registry.CurrentUser.CreateSubKey(RegistryKeyPath, writable: true);
            subKey.SetValue(RegistryValueName, protectedBlob, RegistryValueKind.Binary);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка записи мастер-ключа в HKCU. Class={Class}, Method={Method}",
                ClassName, method);
            return false;
        }
    }

    /// <summary>
    /// Возвращает копию ключа из кэша с sliding TTL и absolute max.
    /// Если окно истекло или превышен потолок непрерывного хранения — очищает кэш и возвращает <see langword="null"/>.
    /// </summary>
    private static byte[]? TryGetCachedMasterKey()
    {
        lock (MasterKeyCacheSync)
        {
            if (_cachedMasterKey is null)
                return null;

            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (now - _cachedMasterKeyLoadedUtc >= MasterKeyCacheAbsoluteMax)
            {
                ClearCachedMasterKey_NoLock();
                return null;
            }

            if (now >= _cachedMasterKeyExpiresUtc)
            {
                ClearCachedMasterKey_NoLock();
                return null;
            }

            DateTimeOffset slidingExpiry = now.Add(MasterKeyCacheTtl);
            DateTimeOffset absoluteExpiry = _cachedMasterKeyLoadedUtc.Add(MasterKeyCacheAbsoluteMax);
            _cachedMasterKeyExpiresUtc = slidingExpiry < absoluteExpiry
                ? slidingExpiry
                : absoluteExpiry;

            return (byte[])_cachedMasterKey.Clone();
        }
    }

    /// <summary>
    /// Сохраняет копию ключа в кэш: фиксирует момент загрузки и начальный срок sliding TTL.
    /// </summary>
    private static void SetCachedMasterKey(byte[] key)
    {
        lock (MasterKeyCacheSync)
        {
            ClearCachedMasterKey_NoLock();

            DateTimeOffset now = DateTimeOffset.UtcNow;
            _cachedMasterKey = (byte[])key.Clone();
            _cachedMasterKeyLoadedUtc = now;
            _cachedMasterKeyExpiresUtc = now.Add(MasterKeyCacheTtl);
        }
    }

    /// <summary>
    /// Очистка кэша без захвата блокировки (вызывать только внутри <see cref="MasterKeyCacheSync"/>).
    /// </summary>
    private static void ClearCachedMasterKey_NoLock()
    {
        if (_cachedMasterKey is not null)
        {
            ClearKeyMaterial(_cachedMasterKey);
            _cachedMasterKey = null;
        }

        _cachedMasterKeyExpiresUtc = DateTimeOffset.MinValue;
        _cachedMasterKeyLoadedUtc = DateTimeOffset.MinValue;
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