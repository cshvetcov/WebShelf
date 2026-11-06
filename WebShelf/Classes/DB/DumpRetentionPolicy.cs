namespace WebShelf.Classes.DB;

/// <summary>
/// Очистка каталога дампов по правилам retention: удаляются файлы дампов старше
/// заданного числа дней; файл с максимальной меткой времени в имени (последний дамп)
/// не удаляется никогда — даже если он старше срока хранения.
/// </summary>
/// <remarks>
/// Дата определяется по имени файла (парсинг), а не по времени записи — имя
/// контролируется приложением и содержит UTC-метку создания. Посторонние файлы,
/// не соответствующие формату дампа, не затрагиваются. Перебор каталога выполняется
/// синхронно: набор файлов мал, а асинхронного перебора каталогов в BCL нет.
/// </remarks>
internal static class DumpRetentionPolicy
{
    private const string ClassName = "WebShelf.Classes.DB.DumpRetentionPolicy";

    /// <summary>
    /// Применяет правила retention к каталогу дампов.
    /// </summary>
    /// <param name="dumpsDirectory">Каталог дампов (может не существовать — тогда очистка не требуется).</param>
    /// <param name="retentionDays">Срок хранения дампов в днях.</param>
    /// <param name="timeProvider">Поставщик времени (тестируемость).</param>
    internal static void Apply(string dumpsDirectory, int retentionDays, TimeProvider timeProvider)
    {
        const string method = nameof(Apply);

        ArgumentException.ThrowIfNullOrWhiteSpace(dumpsDirectory);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentOutOfRangeException.ThrowIfLessThan(retentionDays, 1);

        try
        {
            if (!Directory.Exists(dumpsDirectory))
            {
                Log.Debug(
                    "Каталог дампов не существует — очистка не требуется. DumpsPath={DumpsPath}. Class={Class}, Method={Method}",
                    dumpsDirectory, ClassName, method);
                return;
            }

            DateTimeOffset now = timeProvider.GetUtcNow();
            DateTimeOffset cutoff = now.AddDays(-retentionDays);

            List<(string Path, DateTime UtcTimestamp)> dumps = [];
            List<string> staleTempFiles = [];

            foreach (string filePath in Directory.EnumerateFiles(dumpsDirectory))
            {
                string fileName = Path.GetFileName(filePath);

                if (DbDumpFile.TryParseName(fileName, out DateTime utcTimestamp))
                {
                    dumps.Add((filePath, utcTimestamp));
                }
                else if (IsTempDumpFileName(fileName) &&
                         File.GetLastWriteTimeUtc(filePath) < cutoff)
                {
                    // Незавершённые временные файлы дампов (…sql.tmp) удаляются по тому же правилу
                    staleTempFiles.Add(filePath);
                }
            }

            // Последний дамп (максимальная метка времени в имени) защищён от удаления всегда
            string? latestPath = dumps
                .OrderByDescending(dump => dump.UtcTimestamp)
                .FirstOrDefault().Path;

            int deletedCount = 0;

            foreach ((string filePath, DateTime utcTimestamp) in dumps)
            {
                if (utcTimestamp >= cutoff || string.Equals(filePath, latestPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                try
                {
                    File.Delete(filePath);
                    deletedCount++;
                    Log.Debug(
                        "Удалён устаревший дамп. Path={Path}, UtcCreated={UtcCreated}, RetentionDays={RetentionDays}. Class={Class}, Method={Method}",
                        filePath, utcTimestamp.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture), retentionDays, ClassName, method);
                }
                catch (Exception ex)
                {
                    Log.Warning(
                        ex,
                        "Не удалось удалить устаревший дамп. Path={Path}. Class={Class}, Method={Method}",
                        filePath, ClassName, method);
                }
            }

            foreach (string tempPath in staleTempFiles)
            {
                try
                {
                    File.Delete(tempPath);
                    deletedCount++;
                    Log.Debug(
                        "Удалён незавершённый временный файл дампа. Path={Path}. Class={Class}, Method={Method}",
                        tempPath, ClassName, method);
                }
                catch (Exception ex)
                {
                    Log.Warning(
                        ex,
                        "Не удалось удалить незавершённый временный файл дампа. Path={Path}. Class={Class}, Method={Method}",
                        tempPath, ClassName, method);
                }
            }

            Log.Information(
                "Очистка каталога дампов выполнена. DumpsPath={DumpsPath}, TotalDumps={TotalDumps}, Deleted={Deleted}, RetentionDays={RetentionDays}, LatestProtected={LatestProtected}. Class={Class}, Method={Method}",
                dumpsDirectory, dumps.Count, deletedCount, retentionDays, latestPath ?? "нет", ClassName, method);
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка очистки каталога дампов. DumpsPath={DumpsPath}. Class={Class}, Method={Method}",
                dumpsDirectory, ClassName, method);
        }
    }

    /// <summary>Проверяет, является ли файл незавершённым временным файлом дампа (…sql.tmp).</summary>
    private static bool IsTempDumpFileName(string fileName)
    {
        return fileName.StartsWith(DbDumpFile.FileNamePrefix, StringComparison.Ordinal) &&
               fileName.EndsWith(".sql.tmp", StringComparison.OrdinalIgnoreCase);
    }
}
