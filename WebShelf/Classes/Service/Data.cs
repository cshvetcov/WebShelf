using System.Text;
using Serilog;
using WebShelf.Classes.DC;

namespace WebShelf.Classes.Service;

/// <summary>
/// Центральное хранилище системных данных приложения WebShelf.
/// Отвечает за чтение конфигурации (Server.conf) и предоставление
/// экземпляра домена Active Directory, GUID системы, порта и схемы (http/https).
/// </summary>
internal static class Data
{
    private const string ClassName = "WebShelf.Classes.Service.Data";

    /// <summary>
    /// Порт, на котором слушает HTTP(S)-сервер.
    /// <see langword="null"/>, если не задан или некорректен.
    /// </summary>
    internal static int? Port { get; private set; }

    /// <summary>
    /// Схема прослушивания: <c>http</c> или <c>https</c>.
    /// <see langword="null"/>, если не задана или некорректна.
    /// </summary>
    internal static string? Scheme { get; private set; }

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
    private static readonly Dictionary<string, string[]> RequiredKeys =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["Domain"] = ["domainname", "domainuser", "domainpass"],
            ["GUID"] = ["guid"],
            ["Port"] = ["port"],
            ["Scheme"] = ["scheme"]
        };

    /// <summary>
    /// Читает файл Server.conf и инициализирует <see cref="Domain"/>, <see cref="GUID"/>,
    /// <see cref="Port"/> и <see cref="Scheme"/>.
    /// </summary>
    /// <returns>
    /// <see langword="true"/>, если конфигурация прочитана успешно
    /// (файл существует, ключи найдены, объекты созданы, домен доступен);
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
            Port = null;
            Scheme = null;

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
            bool portOk = TryInitPort(config);
            bool schemeOk = TryInitScheme(config);

            if (!domainOk || !guidOk || !portOk || !schemeOk)
            {
                Log.Error(
                    "Конфигурация загружена частично. DomainOk={DomainOk}, GuidOk={GuidOk}, PortOk={PortOk}, SchemeOk={SchemeOk}. Class={Class}, Method={Method}",
                    domainOk, guidOk, portOk, schemeOk, ClassName, method);
                return false;
            }

            Log.Information(
                "Конфигурация успешно загружена. Domain={Domain}, GuidSet={GuidSet}, Scheme={Scheme}, Port={Port}. Class={Class}, Method={Method}",
                Domain!.Name, !string.IsNullOrWhiteSpace(GUID), Scheme, Port, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Исключение при чтении конфигурации. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                ClassName, method, ConfigFile);

            Domain = null;
            GUID = null;
            Port = null;
            Scheme = null;
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
    /// Инициализирует <see cref="Domain"/> из словаря конфигурации
    /// и проверяет доступность контроллера домена через сервисную учётную запись
    /// (без проверки GUID).
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

            // Проверка доступности AD: валидация сервисной учётки без учёта GUID
            bool isAvailable = Domain.ValidateAdCredentials(domainUser, domainPass, guid: false);
            if (!isAvailable)
            {
                Log.Error(
                    "Домен недоступен или сервисная учётная запись невалидна. Domain={Domain}, User={User}. Class={Class}, Method={Method}",
                    Domain.Name, Domain.User, ClassName, method);
                Domain = null;
                return false;
            }

            Log.Information(
                "Доступность домена подтверждена. Domain={Domain}. Class={Class}, Method={Method}",
                Domain.Name, ClassName, method);

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

    /// <summary>
    /// Читает и проверяет порт из конфигурации.
    /// </summary>
    private static bool TryInitPort(Dictionary<string, string> config)
    {
        const string method = nameof(TryInitPort);

        try
        {
            if (!config.TryGetValue("port", out string? portStr) || string.IsNullOrWhiteSpace(portStr))
            {
                Log.Error("Отсутствует или пустой ключ port. Class={Class}, Method={Method}", ClassName, method);
                return false;
            }

            if (!int.TryParse(portStr.Trim(), out int port) || port < 1 || port > 65535)
            {
                Log.Error("Некорректное значение port={PortValue}. Class={Class}, Method={Method}", portStr, ClassName, method);
                return false;
            }

            Port = port;

            Log.Information("Порт сервера установлен. Port={Port}. Class={Class}, Method={Method}", Port, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Ошибка инициализации порта. Class={Class}, Method={Method}", ClassName, method);
            Port = null;
            return false;
        }
    }

    /// <summary>
    /// Читает и проверяет схему (http/https) из конфигурации.
    /// </summary>
    private static bool TryInitScheme(Dictionary<string, string> config)
    {
        const string method = nameof(TryInitScheme);

        try
        {
            if (!config.TryGetValue("scheme", out string? schemeStr) || string.IsNullOrWhiteSpace(schemeStr))
            {
                Log.Error("Отсутствует или пустой ключ scheme. Class={Class}, Method={Method}", ClassName, method);
                return false;
            }

            string scheme = schemeStr.Trim().ToLowerInvariant();

            if (scheme is not ("http" or "https"))
            {
                Log.Error(
                    "Некорректное значение scheme={SchemeValue}. Допустимо: http, https. Class={Class}, Method={Method}",
                    schemeStr, ClassName, method);
                return false;
            }

            Scheme = scheme;

            Log.Information("Схема сервера установлена. Scheme={Scheme}. Class={Class}, Method={Method}", Scheme, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Ошибка инициализации схемы. Class={Class}, Method={Method}", ClassName, method);
            Scheme = null;
            return false;
        }
    }
}