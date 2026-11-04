using System.Security.Cryptography;
using Microsoft.Win32;
using WebShelf.Classes.Crypto;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты хранилища ключей KeyStore (шаг 3 декомпозиции): создание ключей,
/// InstanceId (HKCU + DPAPI) и мастер-ключ (HKCU + DPAPI + кэш со sliding TTL).
/// Тесты без побочных эффектов (создание ключей, валидация переданного ключа,
/// очистка кэша) выполняются на любой ОС; тесты, затрагивающие реестр и DPAPI,
/// выполняются только на Windows и автоматически пропускаются на других
/// платформах.
/// Тесты, временно подменяющие реестровое значение мастер-ключа, сериализуются
/// с его потребителями в непараллельной коллекции
/// <see cref="MasterKeyRegistryCollection"/>.
/// </summary>
[Collection(MasterKeyRegistryCollection)]
public class KeyStoreTests
{
    /// <summary>
    /// Имя коллекции xUnit, сериализующей выполнение тестов, работающих
    /// с реестровым мастер-ключом (чтение, запись, временная подмена значения).
    /// Потребители мастер-ключа (DomainTests, DatabaseTests, DataTests,
    /// DataConfigMigrationTests, AccountEndpointsTests) включаются в ту же
    /// коллекцию: параллельное обращение к HKCU недопустимо.
    /// </summary>
    public const string MasterKeyRegistryCollection = "MasterKeyRegistry";

    /// <summary>Размер валидного мастер-ключа в байтах.</summary>
    private const int MasterKeySizeBytes = 32;

    /// <summary>Путь ключа реестра относительно <c>HKEY_CURRENT_USER</c> (как в KeyStore).</summary>
    private const string RegistryKeyPath = @"Software\WebShelf\Encryption";

    /// <summary>Имя значения реестра с защищённым мастер-ключом (как в KeyStore).</summary>
    private const string RegistryValueName = "MasterKey";

    /// <summary>Создаёт случайный валидный мастер-ключ (32 байта).</summary>
    private static byte[] CreateTestKey()
    {
        byte[] key = new byte[MasterKeySizeBytes];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    #region Создание ключа

    /// <summary>
    /// CreateKey возвращает массив ровно из 32 байт.
    /// </summary>
    [Fact]
    public void CreateKey_Returns32Bytes()
    {
        byte[] key = KeyStore.CreateKey();

        Assert.NotNull(key);
        Assert.Equal(MasterKeySizeBytes, key.Length);
    }

    /// <summary>
    /// CreateKey при повторных вызовах генерирует разные ключи.
    /// </summary>
    [Fact]
    public void CreateKey_GeneratesDifferentKeys()
    {
        byte[] first = KeyStore.CreateKey();
        byte[] second = KeyStore.CreateKey();

        Assert.False(CryptographicOperations.FixedTimeEquals(first, second));
    }

    /// <summary>
    /// CreateKeyBase64 возвращает строку, декодирующуюся в 32 байта.
    /// </summary>
    [Fact]
    public void CreateKeyBase64_DecodesTo32Bytes()
    {
        string base64Key = KeyStore.CreateKeyBase64();

        byte[] key = Convert.FromBase64String(base64Key);
        Assert.Equal(MasterKeySizeBytes, key.Length);
    }

    #endregion

    #region Валидация входного ключа и кэш (любая ОС)

    /// <summary>
    /// EnsureMasterKey отклоняет ключ неверной длины до обращения к реестру:
    /// выполняется на любой ОС и не создаёт побочных эффектов.
    /// </summary>
    [Fact]
    public void EnsureMasterKey_InvalidKeyLength_ReturnsNull()
    {
        KeyStore.ClearMasterKeyCache();

        byte[] invalidKey = new byte[16];

        Assert.Null(KeyStore.EnsureMasterKey(invalidKey));
    }

    /// <summary>
    /// Очистка кэша мастер-ключа безопасна при пустом кэше и после отказа:
    /// повторные вызовы не выбрасывают исключений на любой ОС.
    /// </summary>
    [Fact]
    public void ClearMasterKeyCache_RepeatedCalls_NeverThrow()
    {
        KeyStore.ClearMasterKeyCache();
        KeyStore.ClearMasterKeyCache();

        // Отказ (невалидный ключ) не оставляет кэш в несогласованном состоянии
        Assert.Null(KeyStore.EnsureMasterKey(new byte[16]));

        KeyStore.ClearMasterKeyCache();
    }

    #endregion

    #region Платформы без реестра/DPAPI (не Windows)

    /// <summary>
    /// На платформе без реестра/DPAPI EnsureMasterKey возвращает
    /// <see langword="null"/> без выброса исключений наружу — фактическое
    /// поведение (возврат null, а не исключение) зафиксировано как контракт
    /// перенесённого кода.
    /// </summary>
    [Fact]
    public void EnsureMasterKey_PlatformWithoutRegistry_ReturnsNullWithoutThrowing()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "На Windows реестр доступен — тест не применим.");

        KeyStore.ClearMasterKeyCache();

        // Автогенерация: чтение реестра недоступно, запись под DPAPI невозможна
        Assert.Null(KeyStore.EnsureMasterKey());

        // Готовый ключ: даже при валидном ключе защита DPAPI недоступна
        Assert.Null(KeyStore.EnsureMasterKey(CreateTestKey()));
    }

    #endregion

    #region InstanceId

    /// <summary>
    /// В Debug-сборке EnsureInstanceId возвращает фиксированное значение
    /// из 26 нулей без обращения к реестру. В Release тест пропускается:
    /// обращение к реестру/DPAPI создаёт побочные эффекты на машине.
    /// </summary>
    [Fact]
    public void EnsureInstanceId_DebugBuild_ReturnsFixed26Zeros()
    {
#if DEBUG
        string? instanceId = KeyStore.EnsureInstanceId();

        Assert.NotNull(instanceId);
        Assert.Equal(26, instanceId.Length);
        Assert.Equal("00000000000000000000000000", instanceId);
#else
        Assert.Skip("Тест актуален только для Debug-сборки (реестр не используется).");
#endif
    }

    /// <summary>
    /// Идемпотентность EnsureInstanceId в Release на Windows: повторный вызов
    /// возвращает сохранённый в реестре ULID, а не генерирует новый
    /// (write-once поведение). В Debug-сборке тест пропускается — Debug
    /// не обращается к реестру (фиксированное значение покрывается тестом выше).
    /// </summary>
    [Fact]
    public void EnsureInstanceId_ReleaseOnWindows_Idempotent_TwoCallsMatch()
    {
#if DEBUG
        Assert.Skip("В Debug-сборке реестр не используется — идемпотентность хранения проверяется только в Release.");
#else
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: InstanceId хранится в HKCU под защитой DPAPI.");

        string? first = KeyStore.EnsureInstanceId();
        Assert.NotNull(first);

        string? second = KeyStore.EnsureInstanceId();
        Assert.NotNull(second);
        Assert.Equal(first, second);
#endif
    }

    #endregion

    #region Мастер-ключ (только Windows: реестр + DPAPI)

    /// <summary>
    /// EnsureMasterKey без параметров возвращает валидный ключ из реестра/кэша,
    /// повторные вызовы (в том числе после очистки кэша) дают один и тот же ключ:
    /// идемпотентность — значение не перегенерируется.
    /// Выполняется только на Windows — хранилище HKCU + DPAPI.
    /// </summary>
    [Fact]
    public void EnsureMasterKey_OnWindows_ReturnsStableKey()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? first = KeyStore.EnsureMasterKey();
        Assert.NotNull(first);
        Assert.Equal(MasterKeySizeBytes, first.Length);

        byte[]? second = KeyStore.EnsureMasterKey();
        Assert.NotNull(second);
        Assert.True(CryptographicOperations.FixedTimeEquals(first, second));

        KeyStore.ClearMasterKeyCache();
        byte[]? third = KeyStore.EnsureMasterKey();
        Assert.NotNull(third);
        Assert.True(CryptographicOperations.FixedTimeEquals(first, third));
    }

    /// <summary>
    /// Переданный ключ сверяется с сохранённым: совпавший возвращается
    /// из реестра после сброса кэша (ветка «прочитан из HKCU»), несовпадающий
    /// отклоняется (<see langword="null"/>) в обеих ветках — и по кэшу,
    /// и по реестру, — без изменения сохранённого значения; штатное
    /// обращение после отказа по-прежнему возвращает сохранённый ключ.
    /// </summary>
    [Fact]
    public void EnsureMasterKey_OnWindows_ExplicitKeyMatchAndMismatch()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? stored = KeyStore.EnsureMasterKey();
        Assert.SkipUnless(stored is not null, "Мастер-ключ недоступен.");
        byte[] key = stored!; // SkipUnless гарантирует ненулевое значение при продолжении

        // Совпавший ключ читается из реестра (кэш пуст — ветка чтения из HKCU)
        KeyStore.ClearMasterKeyCache();
        byte[]? matched = KeyStore.EnsureMasterKey(key);
        Assert.NotNull(matched);
        Assert.True(CryptographicOperations.FixedTimeEquals(key, matched));

        // Несовпадение при пустом кэше — ветка реестра: отказ без изменения значения
        KeyStore.ClearMasterKeyCache();
        Assert.Null(KeyStore.EnsureMasterKey(CreateTestKey()));

        // Несовпадение при тёплом кэше — ветка кэша: отказ без изменения значения
        Assert.Null(KeyStore.EnsureMasterKey(CreateTestKey()));

        // Состояние не испорчено: штатное обращение возвращает сохранённый ключ
        byte[]? stable = KeyStore.EnsureMasterKey();
        Assert.NotNull(stable);
        Assert.True(CryptographicOperations.FixedTimeEquals(key, stable));
    }

    /// <summary>
    /// Round-trip записи и чтения (критерий шага 3): при отсутствии значения
    /// в реестре EnsureMasterKey принимает переданный ключ («принят и сохранён»),
    /// а повторное чтение после сброса кэша возвращает тот же ключ. Существующее
    /// значение перед подменой сохраняется в бэкап и восстанавливается в
    /// <c>finally</c> — тест не оставляет следов на машине (кэш очищается).
    /// </summary>
    [Fact]
    public void EnsureMasterKey_OnWindows_WriteAndReadRoundTrip()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? backup = ReadRegistryMasterKeyValue();
        try
        {
            if (backup is not null)
            {
                // Изымаем существующее значение: ветка записи достижима только при его отсутствии
                DeleteRegistryMasterKeyValue();
                KeyStore.ClearMasterKeyCache();
            }

            byte[] newKey = CreateTestKey();
            byte[]? accepted = KeyStore.EnsureMasterKey(newKey);
            Assert.NotNull(accepted);
            Assert.True(CryptographicOperations.FixedTimeEquals(newKey, accepted));

            // Ключ сохранён в реестре: чтение после сброса кэша возвращает тот же ключ
            KeyStore.ClearMasterKeyCache();
            byte[]? reread = KeyStore.EnsureMasterKey();
            Assert.NotNull(reread);
            Assert.True(CryptographicOperations.FixedTimeEquals(newKey, reread));
        }
        finally
        {
            KeyStore.ClearMasterKeyCache();
            RestoreRegistryMasterKeyValue(backup);
        }
    }

    /// <summary>
    /// Отказ реестра: повреждённый (нечитаемый DPAPI) блоб мастер-ключа —
    /// EnsureMasterKey возвращает <see langword="null"/> без исключения наружу,
    /// значение не удаляется и не заменяется сгенерированным ключом
    /// (write-once: повреждённые данные сохраняются для разбора вручную).
    /// Исходное значение сохраняется в бэкап и восстанавливается в <c>finally</c>.
    /// </summary>
    [Fact]
    public void EnsureMasterKey_OnWindows_CorruptedBlob_ReturnsNullAndPreservesValue()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? backup = ReadRegistryMasterKeyValue();
        try
        {
            byte[] corrupted = new byte[64];
            RandomNumberGenerator.Fill(corrupted);
            WriteRegistryMasterKeyValue(corrupted);
            KeyStore.ClearMasterKeyCache();

            // Чтение не справляется с блобом — отказ без исключения наружу
            Assert.Null(KeyStore.EnsureMasterKey());

            // Явный валидный ключ не спасает: сохранённый блоб читается первым
            // и не расшифровывается — генерация не выполняется
            Assert.Null(KeyStore.EnsureMasterKey(CreateTestKey()));

            // Повреждённое значение не удалено и не перезаписано
            byte[]? after = ReadRegistryMasterKeyValue();
            Assert.NotNull(after);
            Assert.Equal(corrupted, after);
        }
        finally
        {
            KeyStore.ClearMasterKeyCache();
            RestoreRegistryMasterKeyValue(backup);
        }
    }

    #endregion

    #region Вспомогательные методы прямого доступа к HKCU (только для тестов)

    /// <summary>
    /// Читает текущее защищённое значение мастер-ключа из реестра напрямую —
    /// для бэкапа перед подменой. Возвращает <see langword="null"/>, если значения нет.
    /// </summary>
    private static byte[]? ReadRegistryMasterKeyValue()
    {
        using RegistryKey? subKey = Registry.CurrentUser.OpenSubKey(RegistryKeyPath, writable: false);
        if (subKey is null)
            return null;

        object? value = subKey.GetValue(RegistryValueName);
        if (value is not byte[] blob || blob.Length == 0)
            return null;

        return (byte[])blob.Clone();
    }

    /// <summary>
    /// Записывает защищённое значение мастер-ключа в реестр напрямую.
    /// </summary>
    private static void WriteRegistryMasterKeyValue(byte[] value)
    {
        using RegistryKey subKey = Registry.CurrentUser.CreateSubKey(RegistryKeyPath, writable: true);
        subKey.SetValue(RegistryValueName, value, RegistryValueKind.Binary);
    }

    /// <summary>
    /// Удаляет значение мастер-ключа из реестра (если есть).
    /// </summary>
    private static void DeleteRegistryMasterKeyValue()
    {
        using RegistryKey? subKey = Registry.CurrentUser.OpenSubKey(RegistryKeyPath, writable: true);
        subKey?.DeleteValue(RegistryValueName, throwOnMissingValue: false);
    }

    /// <summary>
    /// Восстанавливает значение мастер-ключа после теста: бэкап — на место,
    /// отсутствие бэкапа (значения изначально не было) — удаление значения,
    /// созданного тестом.
    /// </summary>
    private static void RestoreRegistryMasterKeyValue(byte[]? backup)
    {
        if (backup is null)
        {
            DeleteRegistryMasterKeyValue();
        }
        else
        {
            WriteRegistryMasterKeyValue(backup);
        }
    }

    #endregion
}
