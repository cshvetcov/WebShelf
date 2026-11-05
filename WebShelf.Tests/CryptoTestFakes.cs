using System.Security.Cryptography;
using WebShelf.Classes.Crypto;

namespace WebShelf.Tests;

/// <summary>
/// Подмены криптографических сервисов для юнит-тестов (шаг 8 декомпозиции,
/// улучшение У3): изоляция тестов от реестра HKCU и DPAPI. Настоящее хранилище
/// ключей требует Windows (мастер-ключ в HKCU под защитой DPAPI), поэтому
/// тесты, которым нужен произвольный валидный ключ, используют подмену
/// и выполняются на любой платформе; реальные сценарии хранилища остаются
/// в <see cref="KeyStoreTests"/> (Windows-прогон).
/// </summary>
public static class CryptoTestFakes
{
    /// <summary>Размер синтетического мастер-ключа в байтах (как у настоящего).</summary>
    private const int MasterKeySizeBytes = 32;

    /// <summary>
    /// Подмена хранилища ключей: <see cref="KeyStore.EnsureMasterKey"/> возвращает
    /// синтетический ключ, сгенерированный один раз на экземпляр, — реестр
    /// и DPAPI не затрагиваются. Остальные методы наследуются от
    /// <see cref="KeyStore"/> без изменений (создание ключей и очистка кэша
    /// не зависят от платформы).
    /// </summary>
    internal sealed class FakeKeyStore : KeyStore
    {
        /// <summary>Синтетический мастер-ключ экземпляра (32 байта).</summary>
        private readonly byte[] _masterKey;

        /// <summary>
        /// Создаёт подмену с новым случайным синтетическим мастер-ключом (32 байта).
        /// Ключ стабилен на весь срок жизни экземпляра: повторные вызовы
        /// <see cref="EnsureMasterKey"/> возвращают одно и то же значение.
        /// </summary>
        public FakeKeyStore()
        {
            byte[] key = new byte[MasterKeySizeBytes];
            RandomNumberGenerator.Fill(key);
            _masterKey = key;
        }

        /// <summary>
        /// Возвращает синтетический ключ вместо чтения реестра HKCU/DPAPI.
        /// Контракт совпадает с <see cref="KeyStore.EnsureMasterKey"/>:
        /// переданный ключ неверной длины отклоняется значением
        /// <see langword="null"/>, валидный (или отсутствующий) — ключом
        /// экземпляра без изменения сохранённого значения.
        /// </summary>
        /// <param name="key">Готовый ключ (32 байта) или <see langword="null"/>.</param>
        /// <returns>Копия синтетического ключа (32 байта).</returns>
        internal override byte[]? EnsureMasterKey(byte[]? key = null)
        {
            if (key is not null && key.Length != MasterKeySizeBytes)
            {
                return null;
            }

            return (byte[])_masterKey.Clone();
        }
    }
}
