using System.Text.RegularExpressions;

namespace WebShelf.Classes.DB;

/// <summary>
/// Имена файлов дампов БД: формат <c>webshelf_dump_yyyyMMdd_HHmmss_fff.sql</c>
/// (UTC, безопасные для файловой системы символы) и их разбор.
/// </summary>
internal static partial class DbDumpFile
{
    /// <summary>Префикс имени файла дампа.</summary>
    internal const string FileNamePrefix = "webshelf_dump_";

    /// <summary>
    /// Формирует имя файла дампа по метке времени UTC.
    /// </summary>
    /// <param name="utcTimestamp">Метка времени создания (UTC).</param>
    /// <returns>Имя файла вида <c>webshelf_dump_20261105_120000_123.sql</c>.</returns>
    internal static string BuildFileName(DateTime utcTimestamp)
    {
        return $"{FileNamePrefix}{utcTimestamp:yyyyMMdd_HHmmss_fff}.sql";
    }

    /// <summary>
    /// Разбирает имя файла дампа и извлекает метку времени UTC.
    /// </summary>
    /// <param name="fileName">Имя файла (без каталога).</param>
    /// <param name="utcTimestamp">Разобранная метка времени UTC.</param>
    /// <returns><see langword="true"/>, если имя соответствует формату дампа.</returns>
    internal static bool TryParseName(string fileName, out DateTime utcTimestamp)
    {
        utcTimestamp = DateTime.MinValue;
        Match match = DumpFileNameRegex.Match(fileName);

        if (!match.Success)
        {
            return false;
        }

        return DateTime.TryParseExact(
            $"{match.Groups[1].Value}{match.Groups[2].Value}{match.Groups[3].Value}",
            "yyyyMMddHHmmssfff",
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out utcTimestamp);
    }

    /// <summary>Имя файла дампа: webshelf_dump_yyyyMMdd_HHmmss_fff.sql.</summary>
    [GeneratedRegex("""^webshelf_dump_(\d{8})_(\d{6})_(\d{3})\.sql$""", RegexOptions.CultureInvariant)]
    private static partial Regex DumpFileNameRegex { get; }
}
