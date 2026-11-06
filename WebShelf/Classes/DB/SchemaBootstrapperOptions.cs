using System.Text.RegularExpressions;

namespace WebShelf.Classes.DB;

/// <summary>
/// Параметры сервисной инфраструктуры БД из Server.conf: имя схемы, пути
/// к файлу-каркасу и каталогу дампов, срок хранения дампов и разрешение
/// автоматического сброса/обновления структуры при старте.
/// </summary>
/// <param name="SchemaName">Имя схемы PostgreSQL (по умолчанию <c>webshelf</c>).</param>
/// <param name="SkeletonPath">Полный путь к SQL-файлу каркаса.</param>
/// <param name="DumpsDirectory">Полный путь к каталогу дампов (вне wwwroot).</param>
/// <param name="DumpRetentionDays">Срок хранения дампов в днях.</param>
/// <param name="AutoSchemaReset">Разрешение автоматического сброса/обновления структуры
/// при несовпадении на старте; безопасное значение по умолчанию — <see langword="false"/>.</param>
internal sealed partial record SchemaBootstrapperOptions(
    string SchemaName,
    string SkeletonPath,
    string DumpsDirectory,
    int DumpRetentionDays,
    bool AutoSchemaReset)
{
    private const string ClassName = "WebShelf.Classes.DB.SchemaBootstrapperOptions";

    /// <summary>Имя схемы по умолчанию.</summary>
    internal const string DefaultSchemaName = "webshelf";

    /// <summary>Относительный путь к файлу-каркасу по умолчанию (от каталога приложения).</summary>
    internal const string DefaultSkeletonRelativePath = "db/webshelf_skeleton.sql";

    /// <summary>Относительный путь к каталогу дампов по умолчанию.</summary>
    internal const string DefaultDumpsRelativeDirectory = "Data/DbDumps";

    /// <summary>Срок хранения дампов по умолчанию, дней.</summary>
    internal const int DefaultDumpRetentionDays = 90;

    /// <summary>Максимальный допустимый срок хранения дампов, дней.</summary>
    internal const int MaxDumpRetentionDays = 3650;

    /// <summary>
    /// Разбирает параметры из словаря конфигурации Server.conf.
    /// Все ключи опциональны; значения по умолчанию — безопасные.
    /// </summary>
    /// <param name="config">Словарь конфигурации (ключи без учёта регистра).</param>
    /// <returns>Параметры или <see langword="null"/> при некорректных критичных значениях
    /// (имя схемы, путь дампов внутри wwwroot): конфигурация считается незагруженной.</returns>
    internal static SchemaBootstrapperOptions? TryCreate(Dictionary<string, string> config)
    {
        const string method = nameof(TryCreate);

        ArgumentNullException.ThrowIfNull(config);

        try
        {
            string schemaName = DefaultSchemaName;

            if (config.TryGetValue("dbschema", out string? schemaValue) && !string.IsNullOrWhiteSpace(schemaValue))
            {
                string candidate = schemaValue.Trim();

                if (!SchemaNameRegex.IsMatch(candidate))
                {
                    Log.Error(
                        "Некорректное значение dbschema={SchemaValue}: допускаются строчные латинские буквы, цифры и подчёркивания; первый символ — буква или подчёркивание. Class={Class}, Method={Method}",
                        schemaValue, ClassName, method);
                    return null;
                }

                schemaName = candidate;
            }

            string skeletonPath = ResolvePath(
                ReadOptionalValue(config, "dbskeletonpath"), DefaultSkeletonRelativePath);
            string dumpsDirectory = ResolvePath(
                ReadOptionalValue(config, "dbdumpspath"), DefaultDumpsRelativeDirectory);

            // Дампы недоступны по web (риск R14): каталог не должен находиться внутри wwwroot
            string wwwRoot = Path.Combine(AppContext.BaseDirectory, "wwwroot");

            if (string.Equals(dumpsDirectory, wwwRoot, StringComparison.OrdinalIgnoreCase) ||
                dumpsDirectory.StartsWith(wwwRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                Log.Error(
                    "Каталог дампов (dbdumpspath={DumpsPath}) не должен находиться внутри wwwroot — дампы недоступны по web. Class={Class}, Method={Method}",
                    dumpsDirectory, ClassName, method);
                return null;
            }

            int dumpRetentionDays = DefaultDumpRetentionDays;

            if (config.TryGetValue("dbdumpretentiondays", out string? retentionValue) && !string.IsNullOrWhiteSpace(retentionValue))
            {
                if (!int.TryParse(retentionValue.Trim(), out int parsed) ||
                    parsed is < 1 or > MaxDumpRetentionDays)
                {
                    Log.Warning(
                        "Некорректное значение dbdumpretentiondays={RetentionValue}: используется значение по умолчанию {DefaultDays}. Class={Class}, Method={Method}",
                        retentionValue, DefaultDumpRetentionDays, ClassName, method);
                }
                else
                {
                    dumpRetentionDays = parsed;
                }
            }

            bool autoSchemaReset = false;

            if (config.TryGetValue("dbautoschemareset", out string? autoResetValue) && !string.IsNullOrWhiteSpace(autoResetValue))
            {
                if (!bool.TryParse(autoResetValue.Trim(), out autoSchemaReset))
                {
                    Log.Warning(
                        "Некорректное значение dbautoschemareset={AutoResetValue}: используется безопасное значение false. Class={Class}, Method={Method}",
                        autoResetValue, ClassName, method);
                    autoSchemaReset = false;
                }
            }

            Log.Information(
                "Параметры сервисной инфраструктуры БД установлены. Schema={Schema}, SkeletonPath={SkeletonPath}, DumpsPath={DumpsPath}, RetentionDays={RetentionDays}, AutoSchemaReset={AutoSchemaReset}. Class={Class}, Method={Method}",
                schemaName, skeletonPath, dumpsDirectory, dumpRetentionDays, autoSchemaReset, ClassName, method);

            return new SchemaBootstrapperOptions(
                schemaName, skeletonPath, dumpsDirectory, dumpRetentionDays, autoSchemaReset);
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка разбора параметров сервисной инфраструктуры БД. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }
    }

    /// <summary>Читает необязательное строковое значение ключа.</summary>
    private static string? ReadOptionalValue(Dictionary<string, string> config, string key)
    {
        return config.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : null;
    }

    /// <summary>
    /// Разрешает путь: относительные пути отсчитываются от каталога приложения
    /// (<see cref="AppContext.BaseDirectory"/>), абсолютные используются как есть.
    /// </summary>
    private static string ResolvePath(string? configuredValue, string defaultRelativePath)
    {
        string relative = configuredValue ?? defaultRelativePath;
        return Path.IsPathRooted(relative)
            ? Path.GetFullPath(relative)
            : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, relative));
    }

    /// <summary>Допустимое имя схемы: строчные латинские буквы, цифры, подчёркивания.</summary>
    [GeneratedRegex("""^[a-z_][a-z0-9_]*$""", RegexOptions.CultureInvariant)]
    private static partial Regex SchemaNameRegex { get; }
}
