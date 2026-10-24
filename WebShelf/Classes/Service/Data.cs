using System.Text;
using WebShelf.Classes.DC;

namespace WebShelf.Classes.Service;

/// <summary>
/// Центральное хранилище системных данных приложения WebShelf.
/// Отвечает за чтение конфигурации (Server.conf) и предоставление
/// экземпляра домена Active Directory и GUID системы.
/// </summary>
internal static class Data
{
    private const string ClassName = "WebShelf.Classes.Service.Data";

    /// <summary>
    /// Полный путь к файлу конфигурации Server.conf.
    /// </summary>
    internal static string ConfigFile { get; } =
        Path.Combine(AppContext.BaseDirectory, "Server.conf");

    /// <summary>
    /// Экземпляр домена Active Directory.
    /// <see langword="null"/>, если конфигурация не загружена или неполная.
    /// </summary>
    internal static Domain? Domain { get; private set; }

    /// <summary>
    /// GUID системы WebShelf (хранится в атрибуте info пользователей AD).
    /// <see langword="null"/>, если не задан в конфигурации.
    /// </summary>
    internal static string? GUID { get; private set; }

    /// <summary>
    /// Обязательные ключи конфигурации по группам.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string[]> RequiredKeys =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["Domain"] = ["domainname", "domainuser", "domainpass"],
            ["GUID"] = ["guid"]
        };

    /// <summary>
    /// Читает файл Server.conf и инициализирует <see cref="Domain"/> и <see cref="GUID"/>.
    /// </summary>
    /// <returns>
    /// <see langword="true"/>, если конфигурация прочитана успешно
    /// (файл существует, ключи найдены, объекты созданы);
    /// <see langword="false"/> — при любой ошибке.
    /// </returns>
    internal static bool ReadConfig()
    {
        const string method = nameof(ReadConfig);

        try
        {
            Log.Information(
                "Начало чтения конфигурации. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                ClassName, method, ConfigFile);

            Domain = null;
            GUID = null;

            if (!File.Exists(ConfigFile))
            {
                Log.Error(
                    "Файл конфигурации не найден. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                    ClassName, method, ConfigFile);
                return false;
            }

            Dictionary<string, string> config = ReadConfigFile(ConfigFile);

            if (config.Count == 0)
            {
                Log.Warning(
                    "Файл конфигурации пуст или не содержит валидных записей. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            bool domainOk = TryInitDomain(config);
            bool guidOk = TryInitGuid(config);

            if (!domainOk || !guidOk)
            {
                Log.Error(
                    "Конфигурация загружена частично. DomainOk={DomainOk}, GuidOk={GuidOk}. Class={Class}, Method={Method}",
                    domainOk, guidOk, ClassName, method);
                return false;
            }

            Log.Information(
                "Конфигурация успешно загружена. Domain={Domain}, GuidSet={GuidSet}. Class={Class}, Method={Method}",
                Domain!.Name, !string.IsNullOrWhiteSpace(GUID), ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Исключение при чтении конфигурации. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                ClassName, method, ConfigFile);

            Domain = null;
            GUID = null;
            return false;
        }
    }

    /// <summary>
    /// Читает файл конфигурации в словарь ключ=значение.
    /// Строки-комментарии (начинающиеся с #) и пустые строки игнорируются.
    /// </summary>
    private static Dictionary<string, string> ReadConfigFile(string path)
    {
        const string method = nameof(ReadConfigFile);
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase);

        try
        {
            using StreamReader reader = new(path, Encoding.UTF8);

            string? line;
            int lineNumber = 0;

            while ((line = reader.ReadLine()) is not null)
            {
                lineNumber++;
                string trimmed = line.Trim();

                // Пустые строки и комментарии
                if (trimmed.Length == 0 || trimmed[0] == '#')
                    continue;

                int eqIndex = trimmed.IndexOf('=');
                if (eqIndex <= 0)
                {
                    Log.Debug(
                        "Пропущена некорректная строка конфигурации. Line={LineNumber}, Value={Value}. Class={Class}, Method={Method}",
                        lineNumber, trimmed, ClassName, method);
                    continue;
                }

                string key = trimmed[..eqIndex].Trim();
                string value = trimmed[(eqIndex + 1)..].Trim();

                if (key.Length == 0)
                {
                    Log.Debug(
                        "Пропущена строка с пустым ключом. Line={LineNumber}. Class={Class}, Method={Method}",
                        lineNumber, ClassName, method);
                    continue;
                }

                // При дубликатах — последнее значение побеждает
                config[key] = value;
            }

            Log.Debug(
                "Файл конфигурации прочитан. Keys={KeyCount}. Class={Class}, Method={Method}",
                config.Count, ClassName, method);

            return config;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка чтения файла конфигурации. Class={Class}, Method={Method}, Path={Path}",
                ClassName, method, path);
            throw;
        }
    }

    /// <summary>
    /// Инициализирует <see cref="Domain"/> из словаря конфигурации.
    /// </summary>
    private static bool TryInitDomain(Dictionary<string, string> config)
    {
        const string method = nameof(TryInitDomain);

        try
        {
            string[] keys = RequiredKeys["Domain"];

            if (!keys.All(config.ContainsKey))
            {
                IEnumerable<string> missing = keys.Where(k => !config.ContainsKey(k));
                Log.Error(
                    "Отсутствуют обязательные ключи домена: {MissingKeys}. Class={Class}, Method={Method}",
                    string.Join(", ", missing), ClassName, method);
                return false;
            }

            string domainName = config["domainname"];
            string domainUser = config["domainuser"];
            string domainPass = config["domainpass"];

            if (string.IsNullOrWhiteSpace(domainName) ||
                string.IsNullOrWhiteSpace(domainUser) ||
                string.IsNullOrWhiteSpace(domainPass))
            {
                Log.Error(
                    "Одно или несколько значений домена пустые. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            Domain = new Domain(domainName, domainUser, domainPass);

            Log.Information(
                "Домен инициализирован. Domain={Domain}, User={User}. Class={Class}, Method={Method}",
                Domain.Name, Domain.User, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка инициализации домена. Class={Class}, Method={Method}",
                ClassName, method);
            Domain = null;
            return false;
        }
    }

    /// <summary>
    /// Инициализирует <see cref="GUID"/> из словаря конфигурации.
    /// </summary>
    private static bool TryInitGuid(Dictionary<string, string> config)
    {
        const string method = nameof(TryInitGuid);

        try
        {
            string[] keys = RequiredKeys["GUID"];

            if (!keys.All(config.ContainsKey))
            {
                IEnumerable<string> missing = keys.Where(k => !config.ContainsKey(k));
                Log.Error(
                    "Отсутствуют обязательные ключи GUID: {MissingKeys}. Class={Class}, Method={Method}",
                    string.Join(", ", missing), ClassName, method);
                return false;
            }

            string guid = config["guid"];

            if (string.IsNullOrWhiteSpace(guid))
            {
                Log.Error(
                    "Значение GUID пустое. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            GUID = guid.Trim();

            Log.Information(
                "GUID системы установлен. Class={Class}, Method={Method}",
                ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка инициализации GUID. Class={Class}, Method={Method}",
                ClassName, method);
            GUID = null;
            return false;
        }
    }
}