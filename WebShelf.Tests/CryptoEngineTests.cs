using System.Security.Cryptography;
using System.Text;
using WebShelf.Classes.Crypto;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты криптографического движка CryptoEngine (AES-256-GCM, AEAD):
/// циклы шифрования/расшифровки всех 8 перегрузок, структура полезной
/// нагрузки, привязка блоба к контексту через AAD (перестановка значений
/// между полями конфигурации невозможна), проверка целостности (тег GCM),
/// эталонная константа совместимости формата, валидация ключей и контекстов.
/// Все тесты используют явно переданный мастер-ключ — реестр и DPAPI
/// не затрагиваются, поэтому выполняются на любой ОС.
/// </summary>
public class CryptoEngineTests
{
    /// <summary>Экземпляр движка под тестом.</summary>
    private readonly CryptoEngine _engine = new();

    /// <summary>Размер валидного мастер-ключа в байтах.</summary>
    private const int MasterKeySizeBytes = 32;

    /// <summary>
    /// Контекст шифрования для циклических тестов: произвольная непустая метка —
    /// движку достаточно, чтобы контекст совпадал при шифровании и расшифровке.
    /// </summary>
    private const string TestContext = "WebShelf.CryptoEngineTests.Test";

    /// <summary>
    /// Эталонная Base64-константа совместимости криптоформата: снята с
    /// реализации CryptoEngine (AES-256-GCM) для фиксированного вектора —
    /// ключ = байты 0x00..0x1F, nonce = байты 0x00..0x0B, открытый текст =
    /// <see cref="ReferencePlainText"/>, контекст =
    /// <see cref="ReferenceContext"/>. Константа фиксирует формат
    /// «версия(1) | nonce(12) | ciphertext(AES-256-GCM) | тег(16)», схему
    /// вывода ключа (HKDF-SHA256 по метке с нулевой солью) и состав AAD
    /// (версия ‖ контекст): если шаг изменит любой из этих элементов,
    /// расшифровка константы сломается.
    /// </summary>
    private const string ReferenceConstantBase64 =
        "AgABAgMEBQYHCAkKC0HtrfwYrvLutdhTMdzfhi6QQ517/fEhs5Y4I50/pu1l1IstoQKo+awGNyZk7/rlQSZ06xAaluk9WqHIiKESlFPleVZHOKqtwHtILim77QzsUKUy55N3BkJnWrP+WwB+kiM1yoz3XnnrDreeXXc=";

    /// <summary>
    /// Открытый текст эталонной константы: латиница и кириллица — фиксирует
    /// и UTF-8-кодирование строковых перегрузок.
    /// </summary>
    private const string ReferencePlainText =
        "WebShelf CryptoEngine: эталонный вектор криптоформата AES-256-GCM";

    /// <summary>Контекст эталонной константы (AAD фиксированного вектора).</summary>
    private const string ReferenceContext = "WebShelf.CryptoEngineTests.Reference";

    /// <summary>Длина полезной нагрузки эталонной константы в байтах.</summary>
    private const int ReferencePayloadLength = 122;

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
    /// (включая пустой массив и границы блоков AES: 15, 16, 17 байт)
    /// возвращает исходные данные: GCM шифрует данные произвольной длины
    /// без выравнивания и паддинга.
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

        byte[] encrypted = _engine.Encrypt(data, key, TestContext);
        byte[] decrypted = _engine.Decrypt(encrypted, key, TestContext);

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

        string encrypted = _engine.Encrypt(plainText, key, TestContext);
        string decrypted = _engine.Decrypt(encrypted, key, TestContext);

        Assert.Equal(plainText, decrypted);
    }

    /// <summary>
    /// Цикл Encrypt → Decrypt для пустой строки возвращает пустую строку:
    /// GCM допускает пустой plaintext (полезная нагрузка — только заголовок и тег).
    /// </summary>
    [Fact]
    public void EncryptDecrypt_EmptyStringRoundTrip_ReturnsEmptyString()
    {
        byte[] key = CreateTestKey();

        string encrypted = _engine.Encrypt(string.Empty, key, TestContext);
        string decrypted = _engine.Decrypt(encrypted, key, TestContext);

        Assert.Equal(string.Empty, decrypted);
    }

    /// <summary>
    /// Шифрование одних и тех же данных дважды даёт разные шифртексты
    /// (случайный nonce при каждом вызове).
    /// </summary>
    [Fact]
    public void Encrypt_SameDataDifferentCalls_ProducesDifferentCiphertexts()
    {
        byte[] key = CreateTestKey();
        byte[] data = "повторяющиеся данные"u8.ToArray();

        byte[] first = _engine.Encrypt(data, key, TestContext);
        byte[] second = _engine.Encrypt(data, key, TestContext);

        Assert.False(CryptographicOperations.FixedTimeEquals(first, second));
    }

    /// <summary>
    /// Полезная нагрузка соответствует формату:
    /// версия (1) | nonce (12) | ciphertext | тег (16); версия формата = 2.
    /// Длина payload = 29 + длина данных (без паддинга).
    /// </summary>
    [Theory]
    [InlineData(0, 29)]
    [InlineData(10, 39)]
    public void Encrypt_BytesPayload_HasValidStructure(int dataSize, int expectedLength)
    {
        byte[] key = CreateTestKey();
        byte[] data = new byte[dataSize];

        byte[] encrypted = _engine.Encrypt(data, key, TestContext);

        Assert.Equal(expectedLength, encrypted.Length);
        Assert.Equal(2, encrypted[0]); // версия формата
    }

    /// <summary>
    /// Перегрузки с Base64-ключом и строковыми данными согласованы
    /// с байтовыми перегрузками: результат любой перегрузки расшифровывается
    /// любой другой (шифртексты не равны из-за случайного nonce).
    /// </summary>
    [Fact]
    public void EncryptDecrypt_Base64AndStringOverloads_MatchByteOverloads()
    {
        byte[] key = CreateTestKey();
        string base64Key = Convert.ToBase64String(key);
        string plainText = "Проверка согласованности перегрузок";

        // Шифрование строки через байтовый ключ и через Base64-ключ:
        // шифртексты различаются (случайный nonce), но оба расшифровываются обоими ключами
        string encryptedByteKey = _engine.Encrypt(plainText, key, TestContext);
        string encryptedBase64Key = _engine.Encrypt(plainText, base64Key, TestContext);
        Assert.NotEqual(encryptedByteKey, encryptedBase64Key);
        Assert.Equal(plainText, _engine.Decrypt(encryptedBase64Key, key, TestContext));
        Assert.Equal(plainText, _engine.Decrypt(encryptedByteKey, base64Key, TestContext));

        // Расшифровка байтового результата через Base64-ключ
        byte[] data = "байтовые данные"u8.ToArray();
        byte[] encryptedBytes = _engine.Encrypt(data, key, TestContext);
        byte[] decryptedViaBase64 = _engine.Decrypt(encryptedBytes, base64Key, TestContext);
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
        byte[] encryptedBytesKey = _engine.Encrypt(data, key, TestContext);
        byte[] encryptedBytesBase64Key = _engine.Encrypt(data, base64Key, TestContext);
        string encryptedTextKey = _engine.Encrypt(plainText, key, TestContext);
        string encryptedTextBase64Key = _engine.Encrypt(plainText, base64Key, TestContext);

        // Decrypt: byte[]+byte[] (5), byte[]+string (6), string+byte[] (7), string+string (8)
        Assert.Equal(data, _engine.Decrypt(encryptedBytesKey, key, TestContext));
        Assert.Equal(data, _engine.Decrypt(encryptedBytesBase64Key, base64Key, TestContext));
        Assert.Equal(plainText, _engine.Decrypt(encryptedTextKey, key, TestContext));
        Assert.Equal(plainText, _engine.Decrypt(encryptedTextBase64Key, base64Key, TestContext));

        // Перекрёстные комбинации форм ключа: результат одной формы читается другой
        Assert.Equal(data, _engine.Decrypt(encryptedBytesKey, base64Key, TestContext));
        Assert.Equal(data, _engine.Decrypt(encryptedBytesBase64Key, key, TestContext));
        Assert.Equal(plainText, _engine.Decrypt(encryptedTextKey, base64Key, TestContext));
        Assert.Equal(plainText, _engine.Decrypt(encryptedTextBase64Key, key, TestContext));
    }

    #endregion

    #region Привязка к контексту (AAD)

    /// <summary>
    /// Расшифровка в чужом контексте не проходит проверку тега:
    /// блоб, созданный для одного назначения, не читается как блоб другого
    /// назначения — перестановка зашифрованных значений между полями
    /// Server.conf невозможна (привязка через AAD).
    /// </summary>
    [Fact]
    public void Decrypt_BlobFromOtherContext_IsRejected()
    {
        byte[] key = CreateTestKey();
        string secret = "общий-секрет-перестановки";

        // Блоб зашифрован для поля sdbpass...
        string dbBlob = _engine.Encrypt(secret, key, CryptoContexts.DatabaseUser);

        // ...и подменён в поле sdomainuser: тег не сходится
        CryptographicException ex = Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(dbBlob, key, CryptoContexts.DomainUser));

        Assert.Contains("целостности", ex.Message);

        // Контроль: в родном контексте блоб читается тем же ключом
        Assert.Equal(secret, _engine.Decrypt(dbBlob, key, CryptoContexts.DatabaseUser));
    }

    /// <summary>
    /// Расшифровка с произвольным другим контекстом (не только боевым)
    /// также отклоняется: контекст — обязательная часть AAD, а не опция.
    /// </summary>
    [Fact]
    public void Decrypt_WrongContext_ThrowsIntegrityException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt("данные"u8.ToArray(), key, TestContext);

        CryptographicException ex = Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(encrypted, key, "другой-контекст"));

        Assert.Contains("целостности", ex.Message);
    }

    /// <summary>
    /// Контексты сравниваются побайтово: отличие в регистре — это другой
    /// контекст, расшифровка отклоняется (контексты не нормализуются).
    /// </summary>
    [Fact]
    public void Decrypt_ContextIsCaseSensitive_ThrowsIntegrityException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt("данные"u8.ToArray(), key, "WebShelf.Context");

        Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(encrypted, key, "webshelf.context"));
    }

    #endregion

    #region Эталон совместимости криптоформата

    /// <summary>
    /// Эталонная константа расшифровывается движком: формат, схема вывода
    /// ключа и состав AAD не изменились. Проверяется и структура полезной
    /// нагрузки.
    /// </summary>
    [Fact]
    public void Decrypt_ReferenceConstant_ReturnsOriginalText()
    {
        byte[] key = CreateReferenceKey();

        byte[] payload = Convert.FromBase64String(ReferenceConstantBase64);

        // Структура замороженного формата: версия(1) | nonce(12) | ciphertext(93) | тег(16)
        // (93 байта UTF-8 открытого текста, GCM без паддинга)
        Assert.Equal(ReferencePayloadLength, payload.Length);
        Assert.Equal(2, payload[0]);

        // Строковая перегрузка (byte[]-ключ)
        Assert.Equal(ReferencePlainText, _engine.Decrypt(ReferenceConstantBase64, key, ReferenceContext));

        // Байтовая перегрузка (byte[]-ключ)
        byte[] plainBytes = _engine.Decrypt(payload, key, ReferenceContext);
        Assert.Equal(ReferencePlainText, Encoding.UTF8.GetString(plainBytes));

        // Перегрузки с Base64-ключом читают ту же константу
        string base64Key = Convert.ToBase64String(key);
        Assert.Equal(ReferencePlainText, _engine.Decrypt(ReferenceConstantBase64, base64Key, ReferenceContext));
        Assert.Equal(ReferencePlainText, Encoding.UTF8.GetString(_engine.Decrypt(payload, base64Key, ReferenceContext)));
    }

    #endregion

    #region Целостность и формат

    /// <summary>
    /// Расшифровка с другим ключом не проходит проверку тега
    /// (шифртекст не подменяется молча).
    /// </summary>
    [Fact]
    public void Decrypt_WrongKey_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] otherKey = CreateTestKey();
        byte[] encrypted = _engine.Encrypt("данные"u8.ToArray(), key, TestContext);

        Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(encrypted, otherKey, TestContext));
    }

    /// <summary>
    /// Подмена байта nonce обнаруживается проверкой тега
    /// (тег GCM покрывает и nonce).
    /// </summary>
    [Fact]
    public void Decrypt_TamperedNonce_ThrowsIntegrityException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[64], key, TestContext);
        encrypted[1] ^= 0xFF; // первый байт nonce

        CryptographicException ex = Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(encrypted, key, TestContext));

        Assert.Contains("целостности", ex.Message);
    }

    /// <summary>
    /// Подмена байта шифртекста обнаруживается проверкой тега.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[64], key, TestContext);
        encrypted[1 + 12] ^= 0xFF; // первый байт шифртекста

        Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(encrypted, key, TestContext));
    }

    /// <summary>
    /// Подмена последнего байта тега обнаруживается проверкой целостности.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedTag_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[64], key, TestContext);
        encrypted[^1] ^= 0xFF; // последний байт тега

        Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(encrypted, key, TestContext));
    }

    /// <summary>
    /// Порча последнего байта тега даёт CryptographicException именно
    /// о целостности — контракт сообщения сохраняется для вызывающего кода.
    /// </summary>
    [Fact]
    public void Decrypt_TamperedTagLastByte_ThrowsIntegrityException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[64], key, TestContext);
        encrypted[^1] ^= 0xFF;

        CryptographicException ex = Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(encrypted, key, TestContext));

        Assert.Contains("целостности", ex.Message);
    }

    /// <summary>
    /// Неверная версия формата в первом байте отклоняется:
    /// неизвестные версии (включая соседние с текущей) не читаются.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x01)]
    [InlineData(0x03)]
    [InlineData(0xFF)]
    public void Decrypt_TamperedVersion_ThrowsCryptographicException(byte version)
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[64], key, TestContext);
        encrypted[0] = version; // неизвестная версия

        Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(encrypted, key, TestContext));
    }

    /// <summary>
    /// Усечённые данные (короче минимума версия+nonce+тег = 29 байт)
    /// отклоняются до какой-либо криптографии.
    /// </summary>
    [Fact]
    public void Decrypt_TruncatedData_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[64], key, TestContext);
        byte[] truncated = encrypted[..28]; // меньше 1+12+16 = 29

        CryptographicException ex = Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(truncated, key, TestContext));

        Assert.Contains("Некорректные", ex.Message);
    }

    /// <summary>
    /// Данные с добавленными лишними байтами не проходят проверку тега
    /// (лишние байты трактуются как часть шифртекста).
    /// </summary>
    [Fact]
    public void Decrypt_ExtendedData_ThrowsCryptographicException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[64], key, TestContext);
        byte[] extended = new byte[encrypted.Length + 8];
        Buffer.BlockCopy(encrypted, 0, extended, 0, encrypted.Length);

        Assert.ThrowsAny<CryptographicException>(() =>
            _engine.Decrypt(extended, key, TestContext));
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
            _engine.Encrypt((byte[])null!, key, TestContext));
    }

    /// <summary>
    /// Encrypt с пустым ключом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullKey_ThrowsArgumentNullException()
    {
        byte[] data = new byte[10];

        Assert.Throws<ArgumentNullException>(() =>
            _engine.Encrypt(data, (byte[])null!, TestContext));
    }

    /// <summary>
    /// Decrypt с пустыми данными выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Decrypt_NullData_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<ArgumentNullException>(() =>
            _engine.Decrypt((byte[])null!, key, TestContext));
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
            _engine.Encrypt(data, key, TestContext));
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
        byte[] encrypted = _engine.Encrypt(new byte[10], CreateTestKey(), TestContext);

        Assert.Throws<ArgumentException>(() =>
            _engine.Decrypt(encrypted, key, TestContext));
    }

    /// <summary>
    /// Некорректная Base64-строка ключа отклоняется FormatException.
    /// </summary>
    [Fact]
    public void Encrypt_InvalidBase64Key_ThrowsFormatException()
    {
        byte[] data = new byte[10];

        Assert.Throws<FormatException>(() =>
            _engine.Encrypt(data, "это-не-base64!!!", TestContext));
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
            _engine.Encrypt(data, base64Key, TestContext));
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
            _engine.Encrypt(data, string.Empty, TestContext));
    }

    /// <summary>
    /// Encrypt строки с пустым Base64-ключом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullBase64Key_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _engine.Encrypt("текст", (string)null!, TestContext));
    }

    /// <summary>
    /// Encrypt строки с пустым текстом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Encrypt_NullPlainText_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<ArgumentNullException>(() =>
            _engine.Encrypt((string)null!, key, TestContext));
    }

    /// <summary>
    /// Decrypt строки с некорректной Base64-кодировкой данных отклоняется FormatException.
    /// </summary>
    [Fact]
    public void Decrypt_InvalidBase64Data_ThrowsFormatException()
    {
        byte[] key = CreateTestKey();

        Assert.Throws<FormatException>(() =>
            _engine.Decrypt("некорректные-данные", key, TestContext));
    }

    /// <summary>
    /// Decrypt с пустым ключом (byte[]) выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Decrypt_NullKey_ThrowsArgumentNullException()
    {
        byte[] encrypted = _engine.Encrypt(new byte[10], CreateTestKey(), TestContext);

        Assert.Throws<ArgumentNullException>(() =>
            _engine.Decrypt(encrypted, (byte[])null!, TestContext));
    }

    /// <summary>
    /// Decrypt с пустым Base64-ключом выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Decrypt_NullBase64Key_ThrowsArgumentNullException()
    {
        byte[] encrypted = _engine.Encrypt(new byte[10], CreateTestKey(), TestContext);

        Assert.Throws<ArgumentNullException>(() =>
            _engine.Decrypt(encrypted, (string)null!, TestContext));
    }

    /// <summary>
    /// Encrypt с нулевым контекстом выбрасывает ArgumentNullException:
    /// контекст обязателен — он привязывает блоб к назначению через AAD.
    /// </summary>
    [Fact]
    public void Encrypt_NullContext_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();
        byte[] data = new byte[10];

        Assert.Throws<ArgumentNullException>(() =>
            _engine.Encrypt(data, key, null!));
    }

    /// <summary>
    /// Encrypt с пустым контекстом выбрасывает ArgumentException.
    /// </summary>
    [Fact]
    public void Encrypt_EmptyContext_ThrowsArgumentException()
    {
        byte[] key = CreateTestKey();
        byte[] data = new byte[10];

        Assert.Throws<ArgumentException>(() =>
            _engine.Encrypt(data, key, string.Empty));
    }

    /// <summary>
    /// Encrypt с контекстом из одних пробелов выбрасывает ArgumentException.
    /// </summary>
    [Fact]
    public void Encrypt_WhitespaceContext_ThrowsArgumentException()
    {
        byte[] key = CreateTestKey();
        byte[] data = new byte[10];

        Assert.Throws<ArgumentException>(() =>
            _engine.Encrypt(data, key, "   "));
    }

    /// <summary>
    /// Decrypt с нулевым контекстом выбрасывает ArgumentNullException
    /// (зеркало валидации Encrypt).
    /// </summary>
    [Fact]
    public void Decrypt_NullContext_ThrowsArgumentNullException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[10], key, TestContext);

        Assert.Throws<ArgumentNullException>(() =>
            _engine.Decrypt(encrypted, key, null!));
    }

    /// <summary>
    /// Decrypt с пустым контекстом выбрасывает ArgumentException
    /// (зеркало валидации Encrypt).
    /// </summary>
    [Fact]
    public void Decrypt_EmptyContext_ThrowsArgumentException()
    {
        byte[] key = CreateTestKey();
        byte[] encrypted = _engine.Encrypt(new byte[10], key, TestContext);

        Assert.Throws<ArgumentException>(() =>
            _engine.Decrypt(encrypted, key, string.Empty));
    }

    #endregion
}
