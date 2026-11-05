using System.Security.Cryptography;
using WebShelf.Classes.Crypto;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты переходного фасада EncryptionService (шаги 3–4 декомпозиции):
/// делегаты маршрутизируют вызовы в KeyStore (хранение ключей) и CryptoEngine
/// (шифрование) без изменения контракта — созданные ключи имеют прежний
/// размер, валидация ключа выполняется до обращения к реестру, эталонная
/// константа замороженного криптоформата читается через фасад, все 8
/// перегрузок Encrypt/Decrypt согласованы с движком. Реестр и DPAPI
/// не затрагиваются — тесты выполняются на любой ОС.
/// Тесты самого криптоядра после шага 4 вынесены в <see cref="CryptoEngineTests"/>,
/// тесты хранилища ключей — в <see cref="KeyStoreTests"/>.
/// </summary>
public class EncryptionServiceTests
{
    /// <summary>Размер валидного мастер-ключа в байтах.</summary>
    private const int MasterKeySizeBytes = 32;

    /// <summary>
    /// Эталонная Base64-константа замороженного криптоформата (та же, что в
    /// <see cref="CryptoEngineTests"/>): снята с реализации EncryptionService
    /// ДО выноса криптоядра (HEAD 6cfccdd); ключ — байты 0x00..0x1F.
    /// </summary>
    private const string ReferenceConstantBase64 =
        "ARcBw/pyuK9yABemGH8lmP9CMk6poaka4CyP4KDYa3hEpGNYRnSV+ifKrb/6EXTrrcC/UHHqySXXU5Tv48yl/pjdfg8fMRvfM/9wO6iEiE0hjNx5RdhHUVGCEgcyzdFSdrxICadzi4/CYyXk+oP5j92gp3zV3iQGlC3VcQvlDDspJpOC8rOtkXRjtMMi7/WbJQ==";

    /// <summary>
    /// Открытый текст эталонной константы (латиница и кириллица).
    /// </summary>
    private const string ReferencePlainText =
        "WebShelf CryptoEngine: эталон совместимости криптоформата v1";

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

    #region Фасад хранилища ключей (переходный, до шага 8)

    /// <summary>
    /// Переходный фасад хранилища ключей (шаг 3 декомпозиции): делегаты
    /// EncryptionService маршрутизируют вызовы в KeyStore без изменения
    /// контракта — созданные ключи имеют прежний размер, валидация
    /// переданного ключа выполняется до обращения к реестру (выполняется
    /// на любой ОС), очистка кэша не выбрасывает исключений. Реестр и DPAPI
    /// не затрагиваются.
    /// </summary>
    [Fact]
    public void KeyStoreFacade_DelegatesPreserveContract()
    {
        byte[] key = EncryptionService.CreateKey();
        Assert.NotNull(key);
        Assert.Equal(MasterKeySizeBytes, key.Length);

        byte[] decoded = Convert.FromBase64String(EncryptionService.CreateKeyBase64());
        Assert.Equal(MasterKeySizeBytes, decoded.Length);

        // Валидация некорректного по длине ключа — до обращения к реестру, на любой ОС
        Assert.Null(EncryptionService.EnsureMasterKey(new byte[16]));

        // Очистка кэша безопасна при пустом кэше
        EncryptionService.ClearMasterKeyCache();
    }

    #endregion

    #region Фасад криптографического движка (переходный, до шага 8)

    /// <summary>
    /// Все 8 перегрузок Encrypt/Decrypt фасада согласованы с CryptoEngine:
    /// данные, зашифрованные через фасад, расшифровываются движком напрямую,
    /// и наоборот (фасад делегирует тому же движку, а не собственной копии).
    /// </summary>
    [Fact]
    public void CryptoFacade_EightOverloads_PreserveEngineContract()
    {
        byte[] key = CreateTestKey();
        string base64Key = Convert.ToBase64String(key);
        byte[] data = "данные через фасад"u8.ToArray();
        string plainText = "Строка через фасад";

        // Через фасад шифруем — движком напрямую расшифровываем
        byte[] encryptedBytes = EncryptionService.Encrypt(data, key);
        Assert.Equal(data, CryptoEngine.Decrypt(encryptedBytes, key));
        Assert.Equal(data, CryptoEngine.Decrypt(
            EncryptionService.Encrypt(data, base64Key), base64Key));
        Assert.Equal(plainText, CryptoEngine.Decrypt(
            EncryptionService.Encrypt(plainText, key), key));
        Assert.Equal(plainText, CryptoEngine.Decrypt(
            EncryptionService.Encrypt(plainText, base64Key), base64Key));

        // Движком напрямую шифруем — через фасад расшифровываем
        Assert.Equal(data, EncryptionService.Decrypt(CryptoEngine.Encrypt(data, key), key));
        Assert.Equal(data, EncryptionService.Decrypt(
            CryptoEngine.Encrypt(data, base64Key), base64Key));
        Assert.Equal(plainText, EncryptionService.Decrypt(
            CryptoEngine.Encrypt(plainText, key), key));
        Assert.Equal(plainText, EncryptionService.Decrypt(
            CryptoEngine.Encrypt(plainText, base64Key), base64Key));
    }

    /// <summary>
    /// Эталонная константа замороженного криптоформата (снятая с реализации
    /// до шага 4) читается через фасад — публичный контракт фасада
    /// не изменился при выносе криптоядра.
    /// </summary>
    [Fact]
    public void CryptoFacade_ReferenceVector_DecryptsThroughFacade()
    {
        byte[] key = CreateReferenceKey();

        Assert.Equal(ReferencePlainText, EncryptionService.Decrypt(ReferenceConstantBase64, key));
        Assert.Equal(ReferencePlainText, EncryptionService.Decrypt(
            ReferenceConstantBase64, Convert.ToBase64String(key)));
    }

    /// <summary>
    /// Валидация ключа в фасаде делегируется движку: ключ неверной длины
    /// отклоняется ArgumentException до какой-либо криптографии.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    public void CryptoFacade_InvalidKeyLength_ThrowsArgumentException(int keyLength)
    {
        byte[] invalidKey = new byte[keyLength];
        byte[] data = new byte[10];

        Assert.Throws<ArgumentException>(() =>
            EncryptionService.Encrypt(data, invalidKey));
        Assert.Throws<ArgumentException>(() =>
            EncryptionService.Decrypt(data, invalidKey));
    }

    #endregion
}
