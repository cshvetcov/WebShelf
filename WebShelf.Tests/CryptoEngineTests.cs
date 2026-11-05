using System.Security.Cryptography;
using System.Text;
using WebShelf.Classes.Crypto;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты криптографического движка CryptoEngine (шаг 4 декомпозиции):
/// циклы шифрования/расшифровки всех 8 перегрузок, структура полезной
/// нагрузки, порядок проверок при расшифровке (MAC до AES), проверка
/// целостности, эталонная константа совместимости формата, валидация ключей.
/// Все тесты используют явно переданный мастер-ключ — реестр и DPAPI
/// не затрагиваются, поэтому выполняются на любой ОС.
/// Тесты перенесены из <see cref="EncryptionServiceTests"/> без изменения
/// кейсов; тесты, добавленные шагом 4, помечены в сводках методов.
/// </summary>
public class CryptoEngineTests
{
    /// <summary>Размер валидного мастер-ключа в байтах.</summary>
    private const int MasterKeySizeBytes = 32;

    /// <summary>
    /// Эталонная Base64-константа совместимости криптоформата (шаг 4 дорожной карты):
    /// снята с реализации EncryptionService ДО выноса криптоядра в CryptoEngine
    /// (HEAD 6cfccdd) для фиксированного вектора — ключ = байты 0x00..0x1F,
    /// открытый текст = <see cref="ReferencePlainText"/>. Константа фиксирует
    /// формат «версия(1) | IV(16) | ciphertext(PKCS7, AES-256-CBC) | MAC(HMAC-SHA256)»
    /// и схему вывода ключей (метки HMAC-SHA256-KDF): если шаг изменит формат,
    /// расшифровка константы сломается.
    /// </summary>
    private const string ReferenceConstantBase64 =
        "ARcBw/pyuK9yABemGH8lmP9CMk6poaka4CyP4KDYa3hEpGNYRnSV+ifKrb/6EXTrrcC/UHHqySXXU5Tv48yl/pjdfg8fMRvfM/9wO6iEiE0hjNx5RdhHUVGCEgcyzdFSdrxICadzi4/CYyXk+oP5j92gp3zV3iQGlC3VcQvlDDspJpOC8rOtkXRjtMMi7/WbJQ==";

    /// <summary>
    /// Открытый текст эталонной константы: латиница и кириллица — фиксирует
    /// и UTF-8-кодирование строковых перегрузок.
    /// </summary>
    private const string ReferencePlainText =
        "WebShelf CryptoEngine: эталон совместимости криптоформата v1";

    /// <summary>Длина полезной нагрузки эталонной константы в байтах.</summary>
    private const int ReferencePayloadLength = 145;

    /// <summary>Создаёт случайный валидный мастер-ключ (32 байта).</summary>
    private static byte[] CreateTestKey()
    {
        byte[] key = new byte[MasterKeySizeBytes];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    /// <summary>
    /// Эталонный ключ фиксированного вектора: 32 последовательных байта 0x00..0x1F.
    /// </summary>
    private static byte[] CreateReferenceKey()
    {
        byte[] key = new byte[MasterKeySizeBytes];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)i;
        }

        return key;
    }

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

        byte[] encrypted = CryptoEngine.Encrypt(data, key);
        byte[] decrypted = CryptoEngine.Decrypt(encrypted, key);

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

        string encrypted = CryptoEngine.Encrypt(plainText, key);
        string decrypted = CryptoEngine.Decrypt(encrypted, key);

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

        byte[] first = CryptoEngine.Encrypt(data, key);
        byte[] second = CryptoEngine.Encrypt(data, key);

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

        byte[] encrypted = CryptoEngine.Encrypt(data, key);

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
        string encryptedByteKey = CryptoEngine.Encrypt(plainText, key);
        string encryptedBase64Key = CryptoEngine.Encrypt(plainText, base64Key);
        Assert.NotEqual(encryptedByteKey, encryptedBase64Key);
        Assert.Equal(plainText, CryptoEngine.Decrypt(encryptedBase64Key, key));
        Assert.Equal(plainText, CryptoEngine.Decrypt(encryptedByteKey, base64Key));

        // Расшифровка байтового результата через Base64-ключ
        byte[] data = "байтовые данные"u8.ToArray();
        byte[] encryptedBytes = CryptoEngine.Encrypt(data, key);
        byte[] decryptedViaBase64 = CryptoEngine.Decrypt(encryptedBytes, base64Key);
        Assert.Equal(data, decryptedViaBase64);
    }

    /// <summary>
    /// Round-trip всех 8 перегрузок: каждая из 4 перегрузок Encrypt даёт
    /// данные, расшифровываемые соответствующими перегрузками Decrypt
    /// (байтовый и Base64-ключ, байтовые и строковые данные), включая
    /// перекрёстные комбинации форм ключа.
    /// </summary>
    [Fact]
    public void EncryptDecrypt_AllEightOverloads_RoundTrip()
    {
        byte[] key = CreateTestKey();
        string base64Key = Convert.ToBase64String(key);
        byte[] data = "данные всех перегрузок"u8.ToArray();
        string plainText = "Строка всех перегрузок";

        // Encrypt: byte[]+byte[] (1), byte[]+string (2), string+byte[] (3), string+string (4)
        byte[] encryptedBytesKey = CryptoEngine.Encrypt(data, key);
        byte[] encryptedBytesBase64Key = CryptoEngine.Encrypt(data, base64Key);
        string encryptedTextKey = CryptoEngine.Encrypt(plainText, key);
        string encryptedTextBase64Key = CryptoEngine.Encrypt(plainText, base64Key);

        // Decrypt: byte[]+byte[] (5), byte[]+string (6), string+byte[] (7), string+string (8)
        Assert.Equal(data, CryptoEngine.Decrypt(encryptedBytesKey, key));
        Assert.Equal(data, CryptoEngine.Decrypt(encryptedBytesBase64Key, base64Key));
        Assert.Equal(plainText, CryptoEngine.Decrypt(encryptedTextKey, key));
        Assert.Equal(plainText, CryptoEngine.Decrypt(encryptedTextBase64Key, base64Key));

        // Перекрёстные комбинации форм ключа: результат одной формы читается другой
        Assert.Equal(data, CryptoEngine.Decrypt(encryptedBytesKey, base64Key));
        Assert.Equal(data, CryptoEngine.Decrypt(encryptedBytesBase64Key, key));
        Assert.Equal(plainText, CryptoEngine.Decrypt(encryptedTextKey, base64Key));
        Assert.Equal(plainText, CryptoEngine.Decrypt(encryptedTextBase64Key, key));
    }

    #endregion

    #region Эталон совместимости криптоформата (шаг 4)

    /// <summary>
    /// Эталонная константа, снятая с реализации ДО шага 4, расшифровывается
    /// движком CryptoEngine после выноса криптоядра: формат и схема вывода
    /// ключей не изменились. Проверяется и структура полезной нагрузки.
    /// </summary>
    [Fact]
    public void Decrypt_ReferenceConstant_ReturnsOriginalText()
    {
        byte[] key = CreateReferenceKey();

        byte[] payload = Convert.FromBase64String(ReferenceConstantBase64);

        // Структура замороженного формата: версия(1) | IV(16) | ciphertext(96) | MAC(32)
        // (92 байта UTF-8 открытого текста + PKCS7 → 96 байт ciphertext)
        Assert.Equal(ReferencePayloadLength, payload.Length);
        Assert.Equal(1, payload[0]);

        // Строковая перегрузка (byte[]-ключ)
        Assert.Equal(ReferencePlainText, CryptoEngine.Decrypt(ReferenceConstantBase64, key));

        // Байтовая перегрузка (byte[]-ключ)
        byte[] plainBytes = CryptoEngine.Decrypt(payload, key);
        Assert.Equal(ReferencePlainText, Encoding.UTF8.GetString(plainBytes));

        // Перегрузки с Base64-ключом читают ту же константу
        string base64Key = Convert.ToBase64String(key);
        Assert.Equal(ReferencePlainText, CryptoEngine.Decrypt(ReferenceConstantBase64, base64Key));
        Assert.Equal(ReferencePlainText, Encoding.UTF8.GetString(CryptoEngine.Decrypt(payload, base64Key)));
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
        byte[] encrypted = CryptoEngine.Encrypt("данные"u8.ToArray(), key);

        Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(encrypted, otherKey));
    }

    /// <summary>
    /// Подмена байта шифртекста обнаруживается проверкой MAC.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = CryptoEngine.Encrypt(new byte[64], key);
        encrypted[1 + 16] ^= 0xFF; // первый байт шифртекста

        Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(encrypted, key));
    }

    /// <summary>
    /// Подмена последнего байта MAC обнаруживается проверкой целостности.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedMac_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = CryptoEngine.Encrypt(new byte[64], key);
        encrypted[^1] ^= 0xFF; // последний байт MAC

        Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(encrypted, key));
    }

    /// <summary>
    /// Порча последнего байта MAC даёт CryptographicException именно
    /// о целостности (проверка MAC, а не паддинг AES).
    /// </summary>
    [Fact]
    public void Decrypt_TamperedMacLastByte_ThrowsIntegrityException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = CryptoEngine.Encrypt(new byte[64], key);
        encrypted[^1] ^= 0xFF;

        CryptographicException ex = Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(encrypted, key));

        Assert.Contains("целостности", ex.Message);
    }

    /// <summary>
    /// Порядок проверок — контракт безопасности: MAC проверяется ДО расшифровки
    /// AES. Порча последнего байта шифртекста (индекс перед MAC) даёт
    /// CryptographicException о целостности, а не ошибку паддинга.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedCiphertextLastByte_ThrowsIntegrityNotPadding()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = CryptoEngine.Encrypt(new byte[64], key);
        int lastCipherTextIndex = encrypted.Length - 32 - 1; // последний байт ciphertext перед MAC
        encrypted[lastCipherTextIndex] ^= 0xFF;

        CryptographicException ex = Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(encrypted, key));

        // MAC поймал подмену до AES: сообщение о целостности, не о паддинге
        Assert.Contains("целостности", ex.Message);
        Assert.DoesNotContain("Padding", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("паддинг", ex.Message);
    }

    /// <summary>
    /// Порча IV (MAC покрывает и его — от версии до конца шифртекста)
    /// обнаруживается проверкой целостности, а не расшифровкой мусора.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedIv_ThrowsIntegrityException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = CryptoEngine.Encrypt(new byte[64], key);
        encrypted[1] ^= 0xFF; // первый байт IV

        CryptographicException ex = Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(encrypted, key));

        Assert.Contains("целостности", ex.Message);
    }

    /// <summary>
    /// Неверная версия формата в первом байте отклоняется.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedVersion_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = CryptoEngine.Encrypt(new byte[64], key);
        encrypted[0] = 0x99; // неизвестная версия

        Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(encrypted, key));
    }

    /// <summary>
    /// Усечённые данные (короче минимума версия+IV+блок+MAC) отклоняются.
    /// </summary>
    [Fact]
    public void Decrypt_TruncatedData_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = CryptoEngine.Encrypt(new byte[64], key);
        byte[] truncated = encrypted[..40]; // меньше 1+16+16+32 = 65

        Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(truncated, key));
    }

    /// <summary>
    /// Данные с добавленными лишними байтами дают некратную блоку длину
    /// шифртекста и отклоняются.
    /// </summary>
    [Fact]
    public void Decrypt_ExtendedData_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = CryptoEngine.Encrypt(new byte[64], key);
        byte[] extended = new byte[encrypted.Length + 8];
        Buffer.BlockCopy(encrypted, 0, extended, 0, encrypted.Length);

        Assert.ThrowsAny<CryptographicException>(() =>
            CryptoEngine.Decrypt(extended, key));
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
            CryptoEngine.Encrypt((byte[])null!, key));
    }

    /// <summary>
    /// Encrypt с пустым ключом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullKey_ThrowsArgumentNullException()
    {
        byte[] data = new byte[10];

        Assert.Throws<ArgumentNullException>(() =>
            CryptoEngine.Encrypt(data, (byte[])null!));
    }

    /// <summary>
    /// Decrypt с пустыми данными выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Decrypt_NullData_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<ArgumentNullException>(() =>
            CryptoEngine.Decrypt((byte[])null!, key));
    }

    /// <summary>
    /// Encrypt: ключ недопустимой длины (0, 15, 31, 33 байта) отклоняется ArgumentException.
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
            CryptoEngine.Encrypt(data, key));
    }

    /// <summary>
    /// Decrypt: ключ недопустимой длины (0, 15, 31, 33 байта) отклоняется
    /// ArgumentException (зеркало валидации Encrypt).
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(31)]
    [InlineData(33)]
    public void Decrypt_InvalidKeyLength_ThrowsArgumentException(int keyLength)
    {
        byte[] key = new byte[keyLength];
        byte[] encrypted = CryptoEngine.Encrypt(new byte[10], CreateTestKey());

        Assert.Throws<ArgumentException>(() =>
            CryptoEngine.Decrypt(encrypted, key));
    }

    /// <summary>
    /// Некорректная Base64-строка ключа отклоняется FormatException.
    /// </summary>
    [Fact]
    public void Encrypt_InvalidBase64Key_ThrowsFormatException()
    {
        byte[] data = new byte[10];

        Assert.Throws<FormatException>(() =>
            CryptoEngine.Encrypt(data, "это-не-base64!!!"));
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
            CryptoEngine.Encrypt(data, base64Key));
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
            CryptoEngine.Encrypt(data, string.Empty));
    }

    /// <summary>
    /// Encrypt строки с пустым Base64-ключом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullBase64Key_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            CryptoEngine.Encrypt("текст", (string)null!));
    }

    /// <summary>
    /// Encrypt строки с пустым текстом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullPlainText_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<ArgumentNullException>(() =>
            CryptoEngine.Encrypt((string)null!, key));
    }

    /// <summary>
    /// Decrypt строки с некорректной Base64-кодировкой данных отклоняется FormatException.
    /// </summary>
    [Fact]
    public void Decrypt_InvalidBase64Data_ThrowsFormatException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<FormatException>(() =>
            CryptoEngine.Decrypt("некорректные-данные", key));
    }

    /// <summary>
    /// Decrypt с пустым ключом (byte[]) выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Decrypt_NullKey_ThrowsArgumentNullException()
    {
        byte[] encrypted = CryptoEngine.Encrypt(new byte[10], CreateTestKey());

        Assert.Throws<ArgumentNullException>(() =>
            CryptoEngine.Decrypt(encrypted, (byte[])null!));
    }

    /// <summary>
    /// Decrypt с пустым Base64-ключом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Decrypt_NullBase64Key_ThrowsArgumentNullException()
    {
        byte[] encrypted = CryptoEngine.Encrypt(new byte[10], CreateTestKey());

        Assert.Throws<ArgumentNullException>(() =>
            CryptoEngine.Decrypt(encrypted, (string)null!));
    }

    #endregion
}
