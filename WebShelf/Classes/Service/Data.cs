using System.Security.Cryptography.X509Certificates;
using WebShelf.Classes.Crypto;
using WebShelf.Classes.DC;
using WebShelf.Classes.DB;
using WebShelf.Classes.Security;
using WebShelf.Classes.Service.Configuration;
using WebShelf.Classes.Service.Configuration.Sections;

namespace WebShelf.Classes.Service;

/// <summary>
/// Центральное хранилище системных данных приложения WebShelf.
/// Отвечает за чтение конфигурации (Server.conf) и предоставление
/// экземпляра домена Active Directory, подключения к PostgreSQL,
/// InstanceId, порта и схемы (http/https).
/// </summary>
/// <remarks>
/// Ранее класс был статическим (глобальное изменяемое состояние), переведён на DI.
/// Единственный экземпляр создаётся в Program.Main до сборки хоста — схема и порт
/// из Server.conf нужны при конфигурации хоста (UseUrls, политика cookie) —
/// и регистрируется в DI как singleton.
/// <para>
/// Разбор файла на словарь ключ=значение выполняет <see cref="ServerConfigParser"/>,
/// запись защищённых учётных данных — <see cref="SecureCredentialsWriter"/>
/// (вынесены из Data шагами 5 и 6 дорожной карты декомпозиции);
/// инициализацию секций домена, БД и TLS-сертификата — классы
/// <see cref="DomainSection"/>, <see cref="DatabaseSection"/>,
/// <see cref="CertificateSection"/> (шаг 6, точка решения о секциях:
/// Data после выноса записи остаётся больше ~550 строк). Data остаётся
/// оркестратором: получает словарь у парсера, передаёт его инициализаторам
/// секций, присваивает готовые экземпляры своим свойствам и агрегирует
/// признаки успеха; скалярные секции (порт, схема, параметры ролевой модели)
/// инициализирует самостоятельно.
/// </para>
/// <para>
/// Шаг 8 дорожной карты (улучшение У3): криптографические сервисы
/// <see cref="KeyStore"/> и <see cref="CryptoEngine"/> поступают через
/// конструктор как инстансные зависимости (в Production — singleton'ы,
/// созданные в <c>Program.Main</c> до сборки хоста и зарегистрированные
/// в DI готовыми экземплярами) и передаются инициализаторам секций;
/// статический фасад <c>EncryptionService</c> удалён.
/// </para>
/// </remarks>
internal sealed class Data
{
    private const string ClassName = "WebShelf.Classes.Service.Data";

    /// <summary>
    /// Порт, на котором слушает HTTP(S)-сервер.
    /// <see langword="null"/>, если не задан или некорректен.
    /// </summary>
    internal int? Port { get; private set; }

    /// <summary>
    /// Схема прослушивания: <c>http</c> или <c>https</c>.
    /// <see langword="null"/>, если не задана или некорректна.
    /// </summary>
    internal string? Scheme { get; private set; }

    /// <summary>
    /// Полный путь к файлу конфигурации Server.conf.
    /// По умолчанию — <c>AppContext.BaseDirectory/Server.conf</c>;
    /// может быть переопределён конструктором (тестовая точка, улучшение У2
    /// дорожной карты декомпозиции). Путь передаётся парсеру
    /// <see cref="ConfigParser"/> и писателю <see cref="CredentialsWriter"/>.
    /// </summary>
    private string ConfigFile { get; }

    /// <summary>
    /// Парсер файла Server.conf (вынесен из Data шагом 5 дорожной карты
    /// декомпозиции): превращает файл в словарь ключ=значение.
    /// Создаётся один раз на путь <see cref="ConfigFile"/>.
    /// </summary>
    private ServerConfigParser ConfigParser { get; }

    /// <summary>
    /// Писатель защищённых учётных данных в Server.conf (вынесен из Data
    /// шагом 6 дорожной карты декомпозиции): управляемая перезапись с
    /// сохранением комментариев и порядка строк. Создаётся один раз
    /// на путь <see cref="ConfigFile"/> и передаётся инициализаторам секций.
    /// </summary>
    private SecureCredentialsWriter CredentialsWriter { get; }

    /// <summary>
    /// Хранилище ключей (в Production — singleton из DI, созданный в
    /// <c>Program.Main</c> до сборки хоста): источник мастер-ключа для
    /// инициализаторов секций (улучшение У3 дорожной карты декомпозиции).
    /// </summary>
    private readonly KeyStore _keyStore;

    /// <summary>
    /// Криптографический движок (в Production — singleton из DI):
    /// шифрование и расшифровка учётных данных при миграции конфигурации,
    /// передаётся инициализаторам секций (улучшение У3 дорожной карты
    /// декомпозиции).
    /// </summary>
    private readonly CryptoEngine _cryptoEngine;

    /// <summary>
    /// Экземпляр домена Active Directory.
    /// <see langword="null"/>, если конфигурация не загружена или неполная.
    /// </summary>
    internal Domain? Domain { get; private set; }

    /// <summary>
    /// Подключение к базе данных PostgreSQL.
    /// <see langword="null"/>, если конфигурация не загружена или неполная.
    /// </summary>
    internal Database? Database { get; private set; }

    /// <summary>
    /// X.509-сертификат TLS для прослушивания по https.
    /// Загружается из файла (ключ <c>certpath</c>) при схеме https;
    /// <see langword="null"/> при схеме http или ошибке загрузки.
    /// </summary>
    internal X509Certificate2? TlsCertificate { get; private set; }

    /// <summary>
    /// Параметры ролевой модели: TTL кэша роли и интервал фонового опроса
    /// (ключи <c>rolettl</c> / <c>rolepoll</c>).
    /// <see langword="null"/> до чтения конфигурации или при ошибке.
    /// </summary>
    internal RoleCacheOptions? RoleCacheOptions { get; private set; }

    /// <summary>
    /// Полный InstanceId (ULID, 26 символов). Write-once на весь срок жизни процесса.
    /// </summary>
    private string? _instanceId;

    /// <summary>
    /// Полный InstanceId. Бросает <see cref="InvalidOperationException"/>, если ещё не инициализирован.
    /// </summary>
    internal string InstanceId =>
        _instanceId ?? throw new InvalidOperationException("InstanceId ещё не инициализирован.");

    /// <summary>
    /// 12-символьный префикс InstanceId (нижний регистр) для имён AD-групп WebShelf-{id}-*.
    /// </summary>
    internal string InstanceIdShort
    {
        get
        {
            string id = InstanceId;
            return id.Length >= 12 ? id[..12].ToLowerInvariant() : id.ToLowerInvariant();
        }
    }

    /// <summary>
    /// Создаёт экземпляр <see cref="Data"/>.
    /// </summary>
    /// <param name="keyStore">Хранилище ключей — источник мастер-ключа для
    /// инициализаторов секций (в Production — singleton из DI; улучшение У3
    /// дорожной карты декомпозиции).</param>
    /// <param name="cryptoEngine">Криптографический движок — шифрование и
    /// расшифровка учётных данных при миграции конфигурации (в Production —
    /// singleton из DI).</param>
    /// <param name="configFile">
    /// Полный путь к файлу конфигурации Server.conf.
    /// <see langword="null"/> или пустая строка — путь по умолчанию:
    /// <c>AppContext.BaseDirectory/Server.conf</c>.
    /// Тестовая точка внедрения (улучшение У2 дорожной карты декомпозиции):
    /// позволяет юнит-тестам работать с временными файлами, не затрагивая
    /// каталог приложения. Производственный код путь не передаёт —
    /// поведение по сравнению с прежней инициализацией свойства не меняется.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="keyStore"/> или <paramref name="cryptoEngine"/> равен <see langword="null"/>.
    /// </exception>
    internal Data(KeyStore keyStore, CryptoEngine cryptoEngine, string? configFile = null)
    {
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentNullException.ThrowIfNull(cryptoEngine);

        _keyStore = keyStore;
        _cryptoEngine = cryptoEngine;

        ConfigFile = string.IsNullOrWhiteSpace(configFile)
            ? Path.Combine(AppContext.BaseDirectory, "Server.conf")
            : configFile;

        ConfigParser = new ServerConfigParser(ConfigFile);
        CredentialsWriter = new SecureCredentialsWriter(ConfigFile);
    }

    /// <summary>
    /// Устанавливает InstanceId один раз на весь срок жизни процесса.
    /// Повторный вызов вызывает <see cref="InvalidOperationException"/>.
    /// </summary>
    /// <param name="value">Полный ULID (26 символов).</param>
    internal void SetInstanceId(string value)
    {
        const string method = nameof(SetInstanceId);

        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("InstanceId не может быть пустым.", nameof(value));

        if (_instanceId is not null)
            throw new InvalidOperationException("InstanceId уже установлен.");

        _instanceId = value.Trim();
        Log.Information(
            "InstanceId установлен в Data. Short={Short}. Class={Class}, Method={Method}",
            InstanceIdShort, ClassName, method);
    }

    /// <summary>
    /// Тестовая точка внедрения домена: создаёт экземпляр <see cref="Data"/>,
    /// у которого <see cref="Domain"/> уже установлен, минуя чтение Server.conf
    /// (InstanceId, реестр HKCU, DPAPI и файл конфигурации). Используется
    /// юнит-тестами обработчиков входа/выхода (<c>AccountEndpoints</c>);
    /// производственный код создаёт <see cref="Data"/> конструктором с
    /// криптографическими зависимостями и заполняет домен только через
    /// <see cref="ReadConfigAsync"/>. Поведение производственных сценариев не меняется.
    /// </summary>
    /// <param name="domain">Готовый экземпляр домена Active Directory.</param>
    /// <param name="keyStore">Хранилище ключей — как для конструктора
    /// (в тестах — фейк из <c>CryptoTestFakes</c>).</param>
    /// <param name="cryptoEngine">Криптографический движок — как для конструктора.</param>
    /// <returns>Новый экземпляр <see cref="Data"/> с установленным доменом.</returns>
    internal static Data CreateWithDomain(Domain domain, KeyStore keyStore, CryptoEngine cryptoEngine)
    {
        const string method = nameof(CreateWithDomain);

        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentNullException.ThrowIfNull(cryptoEngine);

        Data data = new(keyStore, cryptoEngine);
        data.Domain = domain;

        Log.Debug(
            "Создан экземпляр Data с готовым доменом (тестовая точка). Domain={Domain}. Class={Class}, Method={Method}",
            domain.Name, ClassName, method);

        return data;
    }

    /// <summary>
    /// Асинхронно читает файл Server.conf и инициализирует <see cref="Domain"/>,
    /// <see cref="Port"/> и <see cref="Scheme"/>.
    /// InstanceId должен быть установлен через <see cref="SetInstanceId"/> до вызова.
    /// </summary>
    /// <remarks>
    /// Инициализация БД включает сетевую проверку доступности PostgreSQL,
    /// поэтому выполняется асинхронно из Program.Main — без sync-over-async блокировок.
    /// </remarks>
    /// <returns>
    /// <see langword="true"/>, если конфигурация прочитана успешно
    /// (файл существует, ключи найдены, объекты созданы, домен доступен);
    /// <see langword="false"/> — при любой ошибке.
    /// </returns>
    internal async Task<bool> ReadConfigAsync()
    {
        const string method = nameof(ReadConfigAsync);

        try
        {
            Log.Information(
                "Начало чтения конфигурации. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                ClassName, method, ConfigFile);

            Domain = null;
            Database?.Dispose();
            Database = null;
            TlsCertificate?.Dispose();
            TlsCertificate = null;
            Port = null;
            Scheme = null;

            if (_instanceId is null)
            {
                Log.Error(
                    "InstanceId не установлен до чтения конфигурации. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            if (!File.Exists(ConfigFile))
            {
                Log.Error(
                    "Файл конфигурации не найден. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                    ClassName, method, ConfigFile);
                return false;
            }

            Dictionary<string, string> config = ConfigParser.ReadConfigFile();

            if (config.Count == 0)
            {
                Log.Warning(
                    "Файл конфигурации пуст или не содержит валидных записей. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            // Секции домена, БД и TLS-сертификата инициализируются вынесенными
            // инициализаторами (шаг 6 дорожной карты): они возвращают готовые
            // экземпляры, Data присваивает их своим свойствам в прежнем порядке
            // и агрегирует признаки успеха; инициализаторы секций не мутируют
            // состояние Data.
            Domain = DomainSection.TryInitDomain(config, InstanceIdShort, CredentialsWriter, _keyStore, _cryptoEngine);
            bool domainOk = Domain is not null;

            Database = await DatabaseSection.TryInitDatabaseAsync(config, CredentialsWriter, _keyStore, _cryptoEngine).ConfigureAwait(false);
            bool databaseOk = Database is not null;

            bool portOk = TryInitPort(config);
            bool schemeOk = TryInitScheme(config);

            // Параметры ролевой модели (TTL кэша, интервал опроса)
            bool roleCacheOk = InitRoleCacheOptions(config);

            // Сертификат инициализируется после схемы: нужен только при https
            bool certificateOk = CertificateSection.TryInitCertificate(
                config, Scheme, CredentialsWriter, _keyStore, _cryptoEngine, out X509Certificate2? certificate);
            TlsCertificate = certificate;

            if (!domainOk || !databaseOk || !portOk || !schemeOk || !roleCacheOk || !certificateOk)
            {
                Log.Error(
                    "Конфигурация загружена частично. DomainOk={DomainOk}, DatabaseOk={DatabaseOk}, PortOk={PortOk}, SchemeOk={SchemeOk}, RoleCacheOk={RoleCacheOk}, CertificateOk={CertificateOk}. Class={Class}, Method={Method}",
                    domainOk, databaseOk, portOk, schemeOk, roleCacheOk, certificateOk, ClassName, method);
                return false;
            }

            Log.Information(
                "Конфигурация успешно загружена. Domain={Domain}, Database={Database}, InstanceShort={InstanceShort}, Scheme={Scheme}, Port={Port}. Class={Class}, Method={Method}",
                Domain!.Name, Database!.DatabaseName, InstanceIdShort, Scheme, Port, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Исключение при чтении конфигурации. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                ClassName, method, ConfigFile);

            Domain = null;
            Database?.Dispose();
            Database = null;
            TlsCertificate?.Dispose();
            TlsCertificate = null;
            Port = null;
            Scheme = null;
            RoleCacheOptions = null;
            return false;
        }
    }

    /// <summary>
    /// Читает и проверяет порт из конфигурации.
    /// </summary>
    private bool TryInitPort(Dictionary<string, string> config)
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
    private bool TryInitScheme(Dictionary<string, string> config)
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

    /// <summary>
    /// Читает параметры ролевой модели из конфигурации:
    /// <c>rolettl</c> — TTL кэша роли (10–300 с, по умолчанию 60 с),
    /// <c>rolepoll</c> — интервал фонового опроса ролевых групп (10–300 с, по умолчанию 30 с).
    /// Значение вне диапазона или нечисловое — заменяется значением по умолчанию
    /// (TTL из конфигурации: в пределах min/max выбранных значений; вне пределов — 60 с).
    /// Ключи опциональны: их отсутствие — не ошибка конфигурации.
    /// </summary>
    /// <param name="config">Словарь конфигурации.</param>
    /// <returns>
    /// <see langword="true"/> при успешной инициализации (ключи опциональны —
    /// их отсутствие не ошибка); <see langword="false"/> — только при исключении:
    /// конфигурация считается не загруженной (fail-secure).
    /// </returns>
    private bool InitRoleCacheOptions(Dictionary<string, string> config)
    {
        const string method = nameof(InitRoleCacheOptions);

        try
        {
            int? rolettl = TryReadInt(config, "rolettl");
            int? rolepoll = TryReadInt(config, "rolepoll");

            RoleCacheOptions options = RoleCacheOptions.Create(rolettl, rolepoll, out string ttlSource, out string pollSource);
            RoleCacheOptions = options;

            Log.Information(
                "TTL кэша роли установлен. TtlSec={Ttl} ({TtlSource}); интервал опроса {PollSec} с ({PollSource}). Class={Class}, Method={Method}",
                (int)options.CacheTtl.TotalSeconds, ttlSource,
                (int)options.PollInterval.TotalSeconds, pollSource,
                ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Ошибка инициализации параметров ролевой модели. Class={Class}, Method={Method}", ClassName, method);
            RoleCacheOptions = null;
            return false;
        }
    }

    /// <summary>
    /// Читает целочисленный ключ конфигурации. Возвращает <see langword="null"/>
    /// при отсутствии ключа или нечисловом значении.
    /// </summary>
    /// <param name="config">Словарь конфигурации.</param>
    /// <param name="key">Имя ключа.</param>
    private static int? TryReadInt(Dictionary<string, string> config, string key)
    {
        if (!config.TryGetValue(key, out string? value) || string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return int.TryParse(value.Trim(), out int parsed) ? parsed : null;
    }
}
