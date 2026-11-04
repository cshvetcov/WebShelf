using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using Serilog;

namespace WebShelf.Classes.Crypto;

/// <summary>
/// Хранилище ключей приложения: создание новых ключей, InstanceId (ULID)
/// и мастер-ключ шифрования. Хранение — <c>HKEY_CURRENT_USER</c> под защитой
/// DPAPI (<see cref="DataProtectionScope.CurrentUser"/>) с кэшированием
/// мастер-ключа в памяти (sliding TTL + absolute max).
/// </summary>
/// <remarks>
/// Класс выделен из <c>EncryptionService</c> механическим переносом
/// (шаг 3 дорожной карты декомпозиции); изменения при переносе — только
/// константа <c>Class=</c> в логах перенесённого кода (принцип 6 дорожной карты).
/// Ключ привязан к учётной записи процесса. В Production сервис должен
/// работать под выделенной служебной учёткой (например, DOMAIN\svc_webshelf),
/// чтобы HKCU и DPAPI относились к ней, а не к интерактивному пользователю.
/// </remarks>
internal static class KeyStore
{
    private const string ClassName = "WebShelf.Classes.Crypto.KeyStore";

    private const int MasterKeySizeBytes = 32;

    /// <summary>Длина InstanceId (ULID) — 26 символов Crockford Base32.</summary>
    private const int InstanceIdLength = 26;

    /// <summary>
    /// Фиксированный InstanceId (26 нулей) для Debug-сборки: экземпляры приложения
    /// на разных компьютерах обращаются к одним и тем же AD-группам
    /// WebShelf-000000000000-*.
    /// </summary>
    private const string DebugFixedInstanceId = "00000000000000000000000000";

    /// <summary>Путь ключа реестра относительно <c>HKEY_CURRENT_USER</c>.</summary>
    private const string RegistryKeyPath = @"Software\WebShelf\Encryption";

    /// <summary>Имя значения реестра с защищённым мастер-ключом.</summary>
    private const string RegistryValueName = "MasterKey";

    /// <summary>Имя значения реестра с защищённым InstanceId (ULID).</summary>
    private const string RegistryInstanceIdValueName = "InstanceId";

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

    #region InstanceId (HKCU + DPAPI CurrentUser)

    /// <summary>
    /// Обеспечивает наличие InstanceId: читает из <c>HKEY_CURRENT_USER</c> (DPAPI CurrentUser),
    /// при отсутствии генерирует ULID, защищает DPAPI и записывает.
    /// Существующие данные никогда не удаляются. При невозможности прочитать
    /// повреждённые данные возвращает <see langword="null"/> (вызов должен аварийно завершиться).
    /// </summary>
    /// <returns>Полный ULID (26 символов) или <see langword="null"/> при ошибке.</returns>
    /// <remarks>
    /// В Debug-сборке реестр не используется: всегда возвращается фиксированный
    /// InstanceId из нулей (<see cref="DebugFixedInstanceId"/>), чтобы экземпляры
    /// на разных компьютерах при отладке ссылались на одни и те же AD-группы.
    /// </remarks>
    internal static string? EnsureInstanceId()
    {
        const string method = nameof(EnsureInstanceId);

#if DEBUG
        // Debug: фиксированное значение из нулей, реестр не читается и не пишется —
        // значение не зависит от ранее сохранённого ULID и одинаково на всех машинах
        Log.Information(
            "InstanceId (Debug): используется фиксированное значение из нулей. Class={Class}, Method={Method}",
            ClassName, method);
        return DebugFixedInstanceId;
#else
        try
        {
            lock (RegistrySync)
            {
                byte[]? storedProtected = TryReadProtectedInstanceIdFromRegistry();
                if (storedProtected is not null)
                {
                    try
                    {
                        byte[] unprotected = ProtectedData.Unprotect(
                            storedProtected, optionalEntropy: null, ProtectionScope);
                        try
                        {
                            string id = Encoding.UTF8.GetString(unprotected).Trim();
                            if (!IsValidUlidString(id))
                            {
                                Log.Error(
                                    "InstanceId в реестре имеет некорректный формат. Length={Length}. Class={Class}, Method={Method}",
                                    id.Length, ClassName, method);
                                return null;
                            }

                            Log.Information(
                                "InstanceId прочитан из HKCU. Class={Class}, Method={Method}",
                                ClassName, method);
                            return id;
                        }
                        finally
                        {
                            ClearKeyMaterial(unprotected);
                        }
                    }
                    catch (CryptographicException ex)
                    {
                        Log.Error(ex,
                            "Не удалось расшифровать InstanceId из реестра (DPAPI). Данные не удаляются. Class={Class}, Method={Method}",
                            ClassName, method);
                        return null;
                    }
                    finally
                    {
                        ClearKeyMaterial(storedProtected);
                    }
                }

                string newId = Ulid.NewUlid().ToString();
                byte[] plainBytes = Encoding.UTF8.GetBytes(newId);
                try
                {
                    byte[] protectedBlob = ProtectedData.Protect(
                        plainBytes, optionalEntropy: null, ProtectionScope);
                    try
                    {
                        if (!TryWriteProtectedInstanceIdToRegistry(protectedBlob))
                        {
                            Log.Error(
                                "Не удалось записать InstanceId в HKCU. Class={Class}, Method={Method}",
                                ClassName, method);
                            return null;
                        }
                    }
                    finally
                    {
                        ClearKeyMaterial(protectedBlob);
                    }

                    Log.Information(
                        "InstanceId сгенерирован и сохранён в HKCU. Class={Class}, Method={Method}",
                        ClassName, method);
                    return newId;
                }
                finally
                {
                    ClearKeyMaterial(plainBytes);
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            return null;
        }
#endif
    }

    /// <summary>
    /// Проверяет строку ULID: 26 символов Crockford Base32.
    /// </summary>
    private static bool IsValidUlidString(string value)
    {
        if (value.Length != InstanceIdLength)
            return false;

        foreach (char c in value)
        {
            bool ok = (c >= '0' && c <= '9')
                      || (c >= 'A' && c <= 'Z')
                      || (c >= 'a' && c <= 'z');
            if (!ok)
                return false;
        }

        return true;
    }

    /// <summary>
    /// Читает защищённый блоб InstanceId из <c>HKEY_CURRENT_USER</c>.
    /// </summary>
    private static byte[]? TryReadProtectedInstanceIdFromRegistry()
    {
        const string method = nameof(TryReadProtectedInstanceIdFromRegistry);

        try
        {
            using RegistryKey? subKey = Registry.CurrentUser.OpenSubKey(RegistryKeyPath, writable: false);
            if (subKey is null)
                return null;

            object? value = subKey.GetValue(RegistryInstanceIdValueName);
            if (value is not byte[] blob || blob.Length == 0)
                return null;

            return (byte[])blob.Clone();
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка чтения InstanceId из HKCU. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Записывает защищённый блоб InstanceId в <c>HKEY_CURRENT_USER</c>.
    /// Существующие значения не удаляются — только дописывается/обновляется InstanceId.
    /// </summary>
    private static bool TryWriteProtectedInstanceIdToRegistry(byte[] protectedBlob)
    {
        const string method = nameof(TryWriteProtectedInstanceIdToRegistry);

        try
        {
            using RegistryKey subKey = Registry.CurrentUser.CreateSubKey(RegistryKeyPath, writable: true);
            subKey.SetValue(RegistryInstanceIdValueName, protectedBlob, RegistryValueKind.Binary);
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка записи InstanceId в HKCU. Class={Class}, Method={Method}",
                ClassName, method);
            return false;
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

    /// <summary>
    /// Обнуляет массив с ключевым материалом в памяти.
    /// Собственная копия хелпера EncryptionService (обнуление массива):
    /// классы намеренно не зависят друг от друга — криптографическое ядро
    /// остаётся в EncryptionService до шага 4 дорожной карты декомпозиции.
    /// </summary>
    private static void ClearKeyMaterial(byte[]? key)
    {
        if (key is null)
            return;

        Array.Clear(key, 0, key.Length);
    }
}
