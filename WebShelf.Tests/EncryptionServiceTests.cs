using System.Security.Cryptography;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты сервиса шифрования EncryptionService: циклы шифрования/расшифровки,
/// структура полезной нагрузки, проверка целостности (MAC), валидация ключей.
/// Все тесты используют явно переданный мастер-ключ — реестр и DPAPI не затрагиваются,
/// поэтому выполняются на любой ОС.
/// </summary>
public class EncryptionServiceTests
{
    /// <summary>Размер валидного мастер-ключа в байтах.</summary>
    private const int MasterKeySizeBytes = 32;

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
        byte[] key = EncryptionService.CreateKey();

        Assert.NotNull(key);
        Assert.Equal(MasterKeySizeBytes, key.Length);
    }

    /// <summary>
    /// CreateKey при повторных вызовах генерирует разные ключи.
    /// </summary>
    [Fact]
    public void CreateKey_GeneratesDifferentKeys()
    {
        byte[] first = EncryptionService.CreateKey();
        byte[] second = EncryptionService.CreateKey();

        Assert.False(CryptographicOperations.FixedTimeEquals(first, second));
    }

    /// <summary>
    /// CreateKeyBase64 возвращает строку, декодирующуюся в 32 байта.
    /// </summary>
    [Fact]
    public void CreateKeyBase64_DecodesTo32Bytes()
    {
        string base64Key = EncryptionService.CreateKeyBase64();

        byte[] key = Convert.FromBase64String(base64Key);
        Assert.Equal(MasterKeySizeBytes, key.Length);
    }

    #endregion

    #region Циклы шифрования/расшифровки

    /// <summary>
    /// Цикл Encrypt → Decrypt для массивов байтов разных длин
    /// (включая границы блоков AES: 0, 15, 16, 17 байт) возвращает исходные данные.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(1024)]
    [InlineData(65536)]
    public void EncryptDecrypt_BytesRoundTrip_ReturnsOriginalData(int size)
    {
        byte[] key = CreateTestKey();
        byte[] data = new byte[size];
        RandomNumberGenerator.Fill(data);

        byte[] encrypted = EncryptionService.Encrypt(data, key);
        byte[] decrypted = EncryptionService.Decrypt(encrypted, key);

        Assert.Equal(data, decrypted);
    }

    /// <summary>
    /// Цикл Encrypt → Decrypt для строки с кириллицей возвращает исходный текст.
    /// </summary>
    [Fact]
    public void EncryptDecrypt_UnicodeStringRoundTrip_ReturnsOriginalText()
    {
        byte[] key = CreateTestKey();
        string plainText = "Привет, мир! Тест WebShelf: шифрование секретов.";

        string encrypted = EncryptionService.Encrypt(plainText, key);
        string decrypted = EncryptionService.Decrypt(encrypted, key);

        Assert.Equal(plainText, decrypted);
    }

    /// <summary>
    /// Шифрование одних и тех же данных дважды даёт разные шифртексты
    /// (случайный IV при каждом вызове).
    /// </summary>
    [Fact]
    public void Encrypt_SameDataDifferentCalls_ProducesDifferentCiphertexts()
    {
        byte[] key = CreateTestKey();
        byte[] data = "повторяющиеся данные"u8.ToArray();

        byte[] first = EncryptionService.Encrypt(data, key);
        byte[] second = EncryptionService.Encrypt(data, key);

        Assert.False(CryptographicOperations.FixedTimeEquals(first, second));
    }

    /// <summary>
    /// Полезная нагрузка соответствует формату: версия (1) | IV (16) | ciphertext | MAC (32).
    /// </summary>
    [Fact]
    public void Encrypt_BytesPayload_HasValidStructure()
    {
        byte[] key = CreateTestKey();
        byte[] data = new byte[10];

        byte[] encrypted = EncryptionService.Encrypt(data, key);

        // 10 байт данных дополняются PKCS7 до блока 16 байт
        int expectedLength = 1 + 16 + 16 + 32;
        Assert.Equal(expectedLength, encrypted.Length);
        Assert.Equal(1, encrypted[0]); // версия формата
    }

    /// <summary>
    /// Перегрузки с Base64-ключом и строковыми данными согласованы
    /// с байтовыми перегрузками: результат любой перегрузки расшифровывается
    /// любой другой (шифртексты не равны из-за случайного IV).
    /// </summary>
    [Fact]
    public void EncryptDecrypt_Base64AndStringOverloads_MatchByteOverloads()
    {
        byte[] key = CreateTestKey();
        string base64Key = Convert.ToBase64String(key);
        string plainText = "Проверка согласованности перегрузок";

        // Шифрование строки через байтовый ключ и через Base64-ключ:
        // шифртексты различаются (случайный IV), но оба расшифровываются обоими ключами
        string encryptedByteKey = EncryptionService.Encrypt(plainText, key);
        string encryptedBase64Key = EncryptionService.Encrypt(plainText, base64Key);
        Assert.NotEqual(encryptedByteKey, encryptedBase64Key);
        Assert.Equal(plainText, EncryptionService.Decrypt(encryptedBase64Key, key));
        Assert.Equal(plainText, EncryptionService.Decrypt(encryptedByteKey, base64Key));

        // Расшифровка байтового результата через Base64-ключ
        byte[] data = "байтовые данные"u8.ToArray();
        byte[] encryptedBytes = EncryptionService.Encrypt(data, key);
        byte[] decryptedViaBase64 = EncryptionService.Decrypt(encryptedBytes, base64Key);
        Assert.Equal(data, decryptedViaBase64);
    }

    #endregion

    #region Целостность и формат

    /// <summary>
    /// Расшифровка с другим ключом не проходит проверку MAC
    /// (шифртекст и MAC не подменяются молча).
    /// </summary>
    [Fact]
    public void Decrypt_WrongKey_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] otherKey = CreateTestKey();
        byte[] encrypted = EncryptionService.Encrypt("данные"u8.ToArray(), key);

        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionService.Decrypt(encrypted, otherKey));
    }

    /// <summary>
    /// Подмена байта шифртекста обнаруживается проверкой MAC.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = EncryptionService.Encrypt(new byte[64], key);
        encrypted[1 + 16] ^= 0xFF; // первый байт шифртекста

        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionService.Decrypt(encrypted, key));
    }

    /// <summary>
    /// Подмена последнего байта MAC обнаруживается проверкой целостности.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedMac_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = EncryptionService.Encrypt(new byte[64], key);
        encrypted[^1] ^= 0xFF; // последний байт MAC

        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionService.Decrypt(encrypted, key));
    }

    /// <summary>
    /// Неверная версия формата в первом байте отклоняется.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedVersion_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = EncryptionService.Encrypt(new byte[64], key);
        encrypted[0] = 0x99; // неизвестная версия

        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionService.Decrypt(encrypted, key));
    }

    /// <summary>
    /// Усечённые данные (короче минимума версия+IV+блок+MAC) отклоняются.
    /// </summary>
    [Fact]
    public void Decrypt_TruncatedData_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = EncryptionService.Encrypt(new byte[64], key);
        byte[] truncated = encrypted[..40]; // меньше 1+16+16+32 = 65

        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionService.Decrypt(truncated, key));
    }

    /// <summary>
    /// Данные с добавленными лишними байтами дают некратную блоку длину
    /// шифртекста и отклоняются.
    /// </summary>
    [Fact]
    public void Decrypt_ExtendedData_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = EncryptionService.Encrypt(new byte[64], key);
        byte[] extended = new byte[encrypted.Length + 8];
        Buffer.BlockCopy(encrypted, 0, extended, 0, encrypted.Length);

        Assert.ThrowsAny<CryptographicException>(() =>
            EncryptionService.Decrypt(extended, key));
    }

    #endregion

    #region Валидация аргументов

    /// <summary>
    /// Encrypt с пустыми данными выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullData_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<ArgumentNullException>(() =>
            EncryptionService.Encrypt((byte[])null!, key));
    }

    /// <summary>
    /// Encrypt с пустым ключом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullKey_ThrowsArgumentNullException()
    {
        byte[] data = new byte[10];

        Assert.Throws<ArgumentNullException>(() =>
            EncryptionService.Encrypt(data, (byte[])null!));
    }

    /// <summary>
    /// Decrypt с пустыми данными выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Decrypt_NullData_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<ArgumentNullException>(() =>
            EncryptionService.Decrypt((byte[])null!, key));
    }

    /// <summary>
    /// Ключ недопустимой длины (0, 15, 31, 33 байта) отклоняется ArgumentException.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(31)]
    [InlineData(33)]
    public void Encrypt_InvalidKeyLength_ThrowsArgumentException(int keyLength)
    {
        byte[] key = new byte[keyLength];
        byte[] data = new byte[10];

        Assert.Throws<ArgumentException>(() =>
            EncryptionService.Encrypt(data, key));
    }

    /// <summary>
    /// Некорректная Base64-строка ключа отклоняется FormatException.
    /// </summary>
    [Fact]
    public void Encrypt_InvalidBase64Key_ThrowsFormatException()
    {
        byte[] data = new byte[10];

        Assert.Throws<FormatException>(() =>
            EncryptionService.Encrypt(data, "это-не-base64!!!"));
    }

    /// <summary>
    /// Base64-ключ корректного формата, но неверной длины после декодирования
    /// отклоняется ArgumentException.
    /// </summary>
    [Fact]
    public void Encrypt_Base64KeyOfWrongLength_ThrowsArgumentException()
    {
        byte[] shortKey = new byte[16];
        string base64Key = Convert.ToBase64String(shortKey);
        byte[] data = new byte[10];

        Assert.Throws<ArgumentException>(() =>
            EncryptionService.Encrypt(data, base64Key));
    }

    /// <summary>
    /// Пустая Base64-строка ключа после декодирования даёт ключ нулевой длины
    /// и отклоняется ArgumentException.
    /// </summary>
    [Fact]
    public void Encrypt_EmptyBase64Key_ThrowsArgumentException()
    {
        byte[] data = new byte[10];

        Assert.Throws<ArgumentException>(() =>
            EncryptionService.Encrypt(data, string.Empty));
    }

    /// <summary>
    /// Encrypt строки с пустым Base64-ключом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullBase64Key_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            EncryptionService.Encrypt("текст", (string)null!));
    }

    /// <summary>
    /// Encrypt строки с пустым текстом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullPlainText_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<ArgumentNullException>(() =>
            EncryptionService.Encrypt((string)null!, key));
    }

    /// <summary>
    /// Decrypt строки с некорректной Base64-кодировкой данных отклоняется FormatException.
    /// </summary>
    [Fact]
    public void Decrypt_InvalidBase64Data_ThrowsFormatException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<FormatException>(() =>
            EncryptionService.Decrypt("некорректные-данные", key));
    }

    #endregion

    #region Валидация входного ключа EnsureMasterKey

    /// <summary>
    /// EnsureMasterKey отклоняет ключ неверной длины до обращения к реестру:
    /// выполняется на любой ОС и не создаёт побочных эффектов.
    /// </summary>
    [Fact]
    public void EnsureMasterKey_InvalidKeyLength_ReturnsNull()
    {
        EncryptionService.ClearMasterKeyCache();

        byte[] invalidKey = new byte[16];

        Assert.Null(EncryptionService.EnsureMasterKey(invalidKey));
    }

    #endregion

    #region InstanceId (только Debug: реестр не используется)

    /// <summary>
    /// В Debug-сборке EnsureInstanceId возвращает фиксированное значение
    /// из 26 нулей без обращения к реестру. В Release тест пропускается:
    /// обращение к реестру/DPAPI создаёт побочные эффекты на машине.
    /// </summary>
    [Fact]
    public void EnsureInstanceId_DebugBuild_ReturnsFixed26Zeros()
    {
#if DEBUG
        string? instanceId = EncryptionService.EnsureInstanceId();

        Assert.NotNull(instanceId);
        Assert.Equal(26, instanceId.Length);
        Assert.Equal("00000000000000000000000000", instanceId);
#else
        Assert.Skip("Тест актуален только для Debug-сборки (реестр не используется).");
#endif
    }

    #endregion

    #region Мастер-ключ (только Windows: реестр + DPAPI)

    /// <summary>
    /// EnsureMasterKey без параметров возвращает валидный ключ из реестра/кэша,
    /// повторные вызовы (в том числе после очистки кэша) дают один и тот же ключ.
    /// Выполняется только на Windows — хранилище HKCU + DPAPI.
    /// </summary>
    [Fact]
    public void EnsureMasterKey_OnWindows_ReturnsStableKey()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? first = EncryptionService.EnsureMasterKey();
        Assert.NotNull(first);
        Assert.Equal(MasterKeySizeBytes, first.Length);

        byte[]? second = EncryptionService.EnsureMasterKey();
        Assert.NotNull(second);
        Assert.True(CryptographicOperations.FixedTimeEquals(first, second));

        EncryptionService.ClearMasterKeyCache();
        byte[]? third = EncryptionService.EnsureMasterKey();
        Assert.NotNull(third);
        Assert.True(CryptographicOperations.FixedTimeEquals(first, third));
    }

    #endregion
}
