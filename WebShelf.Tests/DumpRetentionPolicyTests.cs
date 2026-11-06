using WebShelf.Classes.DB;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты имён файлов дампов <see cref="DbDumpFile"/> и политики retention
/// <see cref="DumpRetentionPolicy"/> (включая правило «никогда не удалять последний дамп»).
/// Работа с временными каталогами.
/// </summary>
public class DumpRetentionPolicyTests
{
    /// <summary>Поставщик времени с фиксированным «сейчас» (тестируемость).</summary>
    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    /// <summary>Имя файла дампа строится по метке UTC и разбирается обратно.</summary>
    [Fact]
    public void BuildFileName_RoundTripsWithTryParse()
    {
        DateTime utcCreated = new(2026, 11, 5, 12, 34, 56, 789, DateTimeKind.Utc);

        string fileName = DbDumpFile.BuildFileName(utcCreated);

        Assert.Equal("webshelf_dump_20261105_123456_789.sql", fileName);
        Assert.True(DbDumpFile.TryParseName(fileName, out DateTime parsed));
        Assert.Equal(utcCreated, parsed);
    }

    /// <summary>Посторонние имена не распознаются как дампы.</summary>
    [Theory]
    [InlineData("webshelf_dump_20261105_123456.sql")]
    [InlineData("webshelf_dump_20261105_123456_789.tmp")]
    [InlineData("webshelf_dump_20261105_123456_789.sql.bak")]
    [InlineData("other_dump_20261105_123456_789.sql")]
    [InlineData("webshelf_dump_20261305_123456_789.sql")]
    [InlineData("notes.txt")]
    public void TryParseName_InvalidNames_ReturnsFalse(string fileName)
    {
        Assert.False(DbDumpFile.TryParseName(fileName, out _));
    }

    /// <summary>
    /// Устаревшие дампы удаляются; последний дамп (максимальная метка в имени)
    /// не удаляется никогда — даже если он старше срока хранения.
    /// </summary>
    [Fact]
    public void Apply_OldFilesDeleted_LatestAlwaysKept()
    {
        string directory = CreateTempDirectory();
        DateTimeOffset now = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);

        // Все дампы старше срока (90 дней); максимум среди них — файл -92 дня
        string oldest = CreateDumpFile(directory, now.AddDays(-100));
        string old = CreateDumpFile(directory, now.AddDays(-95));
        string latestButStale = CreateDumpFile(directory, now.AddDays(-92));
        string foreign = Path.Combine(directory, "notes.txt");
        File.WriteAllText(foreign, "посторонний файл");

        try
        {
            DumpRetentionPolicy.Apply(directory, retentionDays: 90, new FixedTimeProvider(now));

            Assert.False(File.Exists(oldest));
            Assert.False(File.Exists(old));
            Assert.True(File.Exists(latestButStale), "Последний дамп должен быть защищён от удаления");
            Assert.True(File.Exists(foreign), "Посторонние файлы не затрагиваются");
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Свежий дамп не удаляется, устаревшие — удаляются.</summary>
    [Fact]
    public void Apply_MixedAges_OnlyOldDeleted()
    {
        string directory = CreateTempDirectory();
        DateTimeOffset now = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);

        string stale = CreateDumpFile(directory, now.AddDays(-100));
        string fresh = CreateDumpFile(directory, now.AddDays(-1));

        try
        {
            DumpRetentionPolicy.Apply(directory, retentionDays: 90, new FixedTimeProvider(now));

            Assert.False(File.Exists(stale));
            Assert.True(File.Exists(fresh));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Единственный дамп старше срока хранения не удаляется.</summary>
    [Fact]
    public void Apply_SingleAncientDump_Kept()
    {
        string directory = CreateTempDirectory();
        DateTimeOffset now = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);
        string only = CreateDumpFile(directory, now.AddDays(-365));

        try
        {
            DumpRetentionPolicy.Apply(directory, retentionDays: 90, new FixedTimeProvider(now));

            Assert.True(File.Exists(only));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Незавершённые временные файлы (…sql.tmp) старше срока удаляются.</summary>
    [Fact]
    public void Apply_StaleTempFile_Deleted()
    {
        string directory = CreateTempDirectory();
        DateTimeOffset now = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);
        string staleTemp = Path.Combine(directory, "webshelf_dump_20260101_000000_000.sql.tmp");
        File.WriteAllText(staleTemp, "partial");
        File.SetLastWriteTimeUtc(staleTemp, now.AddDays(-100).UtcDateTime);

        try
        {
            DumpRetentionPolicy.Apply(directory, retentionDays: 90, new FixedTimeProvider(now));

            Assert.False(File.Exists(staleTemp));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Отсутствующий каталог — не ошибка.</summary>
    [Fact]
    public void Apply_MissingDirectory_NoThrow()
    {
        string missing = Path.Combine(Path.GetTempPath(), $"ws_missing_{Guid.NewGuid():N}");

        DumpRetentionPolicy.Apply(missing, retentionDays: 90, TimeProvider.System);
    }

    /// <summary>Создаёт временный каталог.</summary>
    private static string CreateTempDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(), $"ws_retention_{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }

    /// <summary>Создаёт файл дампа с именем по метке времени.</summary>
    private static string CreateDumpFile(string directory, DateTimeOffset utcTimestamp)
    {
        string path = Path.Combine(directory, DbDumpFile.BuildFileName(utcTimestamp.UtcDateTime));
        File.WriteAllText(path, "-- dump");
        return path;
    }
}
