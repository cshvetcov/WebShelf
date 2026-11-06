using System.Security.Cryptography;
using System.Text;

namespace WebShelf.Classes.DB;

/// <summary>
/// Загруженный файл-каркас: исходный SQL, хеш содержимого (SHA-256) и разобранный манифест.
/// </summary>
/// <param name="Path">Полный путь к файлу каркаса.</param>
/// <param name="SqlText">Текст файла (без изменений).</param>
/// <param name="Sha256Hash">Хеш содержимого SHA-256 в нижнем шестнадцатеричном регистре.</param>
/// <param name="Manifest">Манифест ожидаемой структуры, разобранный из этого же текста.</param>
internal sealed record SchemaSkeleton(
    string Path,
    string SqlText,
    string Sha256Hash,
    SchemaManifest Manifest);

/// <summary>
/// Загрузка файла-каркаса БД: проверка существования и читаемости, вычисление
/// SHA-256 и разбор в манифест. Каркас — доверенный файл поставки приложения,
/// а не пользовательский ввод.
/// </summary>
internal static class SchemaSkeletonLoader
{
    private const string ClassName = "WebShelf.Classes.DB.SchemaSkeletonLoader";

    /// <summary>
    /// Асинхронно загружает файл-каркас и разбирает его в манифест.
    /// </summary>
    /// <param name="skeletonPath">Полный путь к SQL-файлу каркаса.</param>
    /// <param name="schemaName">Имя схемы, к которой относится каркас.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Загруженный каркас.</returns>
    /// <exception cref="SchemaSkeletonException">Файл отсутствует, не читается или не разбирается.</exception>
    internal static async Task<SchemaSkeleton> LoadAsync(string skeletonPath, string schemaName, CancellationToken cancellationToken)
    {
        const string method = nameof(LoadAsync);

        ArgumentException.ThrowIfNullOrWhiteSpace(skeletonPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaName);

        if (!File.Exists(skeletonPath))
        {
            throw new SchemaSkeletonException($"Файл-каркас БД не найден: «{skeletonPath}».");
        }

        string sqlText;

        try
        {
            sqlText = await File.ReadAllTextAsync(skeletonPath, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка чтения файла-каркаса БД. SkeletonPath={SkeletonPath}. Class={Class}, Method={Method}",
                skeletonPath, ClassName, method);
            throw new SchemaSkeletonException($"Не удалось прочитать файл-каркас БД: «{skeletonPath}».", ex);
        }

        byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(sqlText));
        string sha256Hash = Convert.ToHexString(hashBytes).ToLowerInvariant();

        SchemaManifest manifest;

        try
        {
            manifest = SchemaSkeletonParser.Parse(sqlText, schemaName);
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка разбора файла-каркаса БД. SkeletonPath={SkeletonPath}. Class={Class}, Method={Method}",
                skeletonPath, ClassName, method);
            throw;
        }

        return new SchemaSkeleton(skeletonPath, sqlText, sha256Hash, manifest);
    }
}
