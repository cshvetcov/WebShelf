using System.Security.Cryptography;
using WebShelf.Classes.Crypto;

namespace WebShelf.Classes.Service;

/// <summary>
/// Статический фасад криптографии приложения (до шага 8 дорожной карты
/// декомпозиции): маршрутизирует вызовы в <see cref="KeyStore"/> (хранение
/// ключей) и <see cref="CryptoEngine"/> (шифрование). Собственной логики
/// и состояния не содержит.
/// </summary>
/// <remarks>
/// Шаг 3: хранилище ключей (создание ключей, InstanceId и мастер-ключ в HKCU
/// под защитой DPAPI, кэширование) вынесено в <see cref="KeyStore"/>.
/// Шаг 4: криптографическое ядро (AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC,
/// формат «версия | IV | ciphertext | MAC», 8 перегрузок Encrypt/Decrypt)
/// вынесено в <see cref="CryptoEngine"/> — перенесено механически, криптоформат
/// не изменился. Делегаты сохранены, чтобы существующие точки вызова
/// (<c>Data</c>, <c>Domain</c>, <c>Database</c>, <c>Program</c>, тесты)
/// продолжали работать без правок. Удаление фасада — шаг 8.
/// </remarks>
internal static class EncryptionService
{
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

    #region Фасад криптографического движка (CryptoEngine, до шага 8)

    /// <summary>
    /// Шифрует массив байтов (AES-256-CBC, Encrypt-then-MAC). Делегирует
    /// <see cref="CryptoEngine.Encrypt(byte[], byte[])"/>; контракт и исключения — в нём.
    /// </summary>
    /// <param name="data">Открытые данные.</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <returns>Зашифрованные данные (версия | IV | ciphertext | MAC).</returns>
    internal static byte[] Encrypt(byte[] data, byte[] key)
    {
        return CryptoEngine.Encrypt(data, key);
    }

    /// <summary>
    /// Шифрует массив байтов, используя ключ в Base64-формате. Делегирует
    /// <see cref="CryptoEngine.Encrypt(byte[], string)"/>; контракт и исключения — в нём.
    /// </summary>
    /// <param name="data">Открытые данные.</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <returns>Зашифрованные данные (версия | IV | ciphertext | MAC).</returns>
    internal static byte[] Encrypt(byte[] data, string base64Key)
    {
        return CryptoEngine.Encrypt(data, base64Key);
    }

    /// <summary>
    /// Шифрует строку (UTF-8), результат — в Base64. Делегирует
    /// <see cref="CryptoEngine.Encrypt(string, byte[])"/>; контракт и исключения — в нём.
    /// </summary>
    /// <param name="plainText">Открытый текст.</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <returns>Зашифрованные данные в Base64.</returns>
    internal static string Encrypt(string plainText, byte[] key)
    {
        return CryptoEngine.Encrypt(plainText, key);
    }

    /// <summary>
    /// Шифрует строку, используя ключ в Base64-формате, результат — в Base64.
    /// Делегирует <see cref="CryptoEngine.Encrypt(string, string)"/>;
    /// контракт и исключения — в нём.
    /// </summary>
    /// <param name="plainText">Открытый текст.</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <returns>Зашифрованные данные в Base64.</returns>
    internal static string Encrypt(string plainText, string base64Key)
    {
        return CryptoEngine.Encrypt(plainText, base64Key);
    }

    /// <summary>
    /// Расшифровывает массив байтов, ранее зашифрованный методом
    /// <see cref="Encrypt(byte[], byte[])"/>. Делегирует
    /// <see cref="CryptoEngine.Decrypt(byte[], byte[])"/>; контракт и исключения — в нём.
    /// </summary>
    /// <param name="encryptedData">Зашифрованные данные (версия | IV | ciphertext | MAC).</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <returns>Открытые данные.</returns>
    internal static byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        return CryptoEngine.Decrypt(encryptedData, key);
    }

    /// <summary>
    /// Расшифровывает массив байтов, используя ключ в Base64-формате. Делегирует
    /// <see cref="CryptoEngine.Decrypt(byte[], string)"/>; контракт и исключения — в нём.
    /// </summary>
    /// <param name="encryptedData">Зашифрованные данные.</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <returns>Открытые данные.</returns>
    internal static byte[] Decrypt(byte[] encryptedData, string base64Key)
    {
        return CryptoEngine.Decrypt(encryptedData, base64Key);
    }

    /// <summary>
    /// Расшифровывает строку в Base64-формате (UTF-8). Делегирует
    /// <see cref="CryptoEngine.Decrypt(string, byte[])"/>; контракт и исключения — в нём.
    /// </summary>
    /// <param name="encryptedBase64">Зашифрованные данные в Base64.</param>
    /// <param name="key">Мастер-ключ длиной 32 байта.</param>
    /// <returns>Открытый текст.</returns>
    internal static string Decrypt(string encryptedBase64, byte[] key)
    {
        return CryptoEngine.Decrypt(encryptedBase64, key);
    }

    /// <summary>
    /// Расшифровывает строку в Base64-формате, используя ключ в Base64-формате.
    /// Делегирует <see cref="CryptoEngine.Decrypt(string, string)"/>;
    /// контракт и исключения — в нём.
    /// </summary>
    /// <param name="encryptedBase64">Зашифрованные данные в Base64.</param>
    /// <param name="base64Key">Мастер-ключ в Base64.</param>
    /// <returns>Открытый текст.</returns>
    internal static string Decrypt(string encryptedBase64, string base64Key)
    {
        return CryptoEngine.Decrypt(encryptedBase64, base64Key);
    }

    #endregion
}