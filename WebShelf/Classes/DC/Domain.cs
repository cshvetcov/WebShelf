using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using WebShelf.Classes.Service;

namespace WebShelf.Classes.DC;

/// <summary>
/// Краткая информация о пользователе Active Directory,
/// необходимая для отображения в WebShelf.
/// </summary>
/// <param name="SamAccountName">Логин (sAMAccountName).</param>
/// <param name="DisplayName">Отображаемое имя.</param>
/// <param name="Email">Адрес электронной почты (атрибут mail).</param>
internal sealed record AdUserInfo(string SamAccountName, string DisplayName, string Email);

/// <summary>
/// Представляет домен Active Directory и предоставляет методы
/// для получения пользователей системы и проверки учётных данных.
/// Используется в браузерном приложении WebShelf для работы
/// с документацией в проектной организации промышленного и гражданского строительства.
/// </summary>
internal class Domain
{
    private const string ClassName = "WebShelf.Classes.DC.Domain";

    /// <summary>
    /// Имя домена (FQDN), например: "company.local".
    /// </summary>
    internal string Name { get; }

    /// <summary>
    /// Имя сервисной учётной записи для подключения к Active Directory.
    /// </summary>
    internal string User { get; }

    /// <summary>
    /// LDAP-путь к корню домена (используется при поиске объектов).
    /// </summary>
    internal string Path { get; }

    /// <summary>
    /// Пароль сервисной учётной записи.
    /// Хранится в приватном поле для обеспечения безопасности.
    /// </summary>
    private readonly string _password;

    /// <summary>
    /// Создаёт экземпляр класса <see cref="Domain"/>.
    /// </summary>
    /// <param name="domain">Имя домена (FQDN).</param>
    /// <param name="user">Имя сервисной учётной записи.</param>
    /// <param name="password">Пароль сервисной учётной записи.</param>
    /// <exception cref="ArgumentException">
    /// Возникает, если имя домена, имя пользователя или пароль пустые или содержат только пробелы.
    /// </exception>
    internal Domain(string domain, string user, string password)
    {
        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Имя домена не может быть пустым.", nameof(domain));
        if (string.IsNullOrWhiteSpace(user))
            throw new ArgumentException("Имя пользователя не может быть пустым.", nameof(user));
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Пароль не может быть пустым.", nameof(password));

        string? userName = NormalizeUserName(user, domain);
        if (string.IsNullOrWhiteSpace(userName))
            throw new ArgumentException($"Имя пользователя '{user}' не удалось привести к формату username@domain.", nameof(user));

        Name = domain.Trim();
        User = userName?.Trim() ?? string.Empty;
        _password = password;

        // Формируем LDAP-путь к корню домена (DC=...)
        IEnumerable<string> dcParts = Name
            .Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => $"DC={p}");
        Path = $"LDAP://{string.Join(",", dcParts)}";

        Log.Debug("Создан экземпляр Domain. Domain={Domain}, User={User}, Path={Path}", Name, User, Path);
    }

    /// <summary>
    /// Возвращает список пользователей Active Directory, разрешённых для работы в WebShelf.
    /// Пользователь считается разрешённым, если:
    /// - учётная запись включена;
    /// - в атрибуте <c>info</c> указан GUID системы (<see cref="Service.Data.GUID"/>).
    /// Поиск выполняется на стороне контроллера домена с постраничной выборкой.
    /// Загружаются только атрибуты sAMAccountName, displayName и mail.
    /// </summary>
    /// <returns>Список <see cref="AdUserInfo"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Возникает при ошибках подключения к Active Directory или выполнения поиска.
    /// </exception>
    internal IReadOnlyList<AdUserInfo> GetAllUsers()
    {
        const string method = nameof(GetAllUsers);
        List<AdUserInfo> users = [];

        try
        {
            Log.Information("Начало получения списка пользователей AD. Domain={Domain}", Name);

            using DirectoryEntry searchRoot = new(Path, User, _password);
            using DirectorySearcher searcher = new(searchRoot)
            {
                // Фильтр: пользователь, включённая учётная запись, нужный GUID в поле info
                Filter = $"(&(objectCategory=person)(objectClass=user)" +
                         $"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                         $"(info=*GUID|{Service.Data.GUID}*))",
                PageSize = 1000,
                SearchScope = SearchScope.Subtree
            };

            searcher.PropertiesToLoad.Add("sAMAccountName");
            searcher.PropertiesToLoad.Add("displayName");
            searcher.PropertiesToLoad.Add("mail");

            using SearchResultCollection results = searcher.FindAll();

            foreach (SearchResult result in results)
            {
                string? sam = GetProperty(result, "sAMAccountName");
                if (string.IsNullOrWhiteSpace(sam))
                {
                    Log.Debug("Пропущена запись без sAMAccountName. Domain={Domain}", Name);
                    continue;
                }

                string displayName = GetProperty(result, "displayName") ?? sam;
                string email = GetProperty(result, "mail") ?? string.Empty;

                users.Add(new AdUserInfo(sam, displayName, email));
            }

            Log.Information(
                "Список пользователей AD успешно получен. Domain={Domain}, Count={Count}",
                Name, users.Count);

            return users.AsReadOnly();
        }
        catch (PrincipalServerDownException ex)
        {
            Log.Error(ex,
                "Контроллер домена недоступен при получении пользователей. Class={Class}, Method={Method}, Domain={Domain}",
                ClassName, method, Name);

            throw new InvalidOperationException(
                "Не удалось подключиться к Active Directory.",
                new InvalidOperationException($"Сервер: {Name}", ex));
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            Log.Error(ex,
                "Ошибка при получении списка пользователей из Active Directory. Class={Class}, Method={Method}, Domain={Domain}",
                ClassName, method, Name);

            throw new InvalidOperationException(
                "Ошибка при получении списка пользователей из Active Directory.", ex);
        }
    }

    /// <summary>
    /// Проверяет учётные данные пользователя в Active Directory.
    /// При <paramref name="guid"/> = <see langword="true"/> дополнительно проверяет,
    /// что в атрибуте <c>info</c> пользователя указан GUID системы (<see cref="Service.Data.GUID"/>).
    /// </summary>
    /// <param name="username">Имя пользователя (логин).</param>
    /// <param name="password">Пароль пользователя.</param>
    /// <param name="guid">
    /// Если <see langword="true"/> (по умолчанию), проверяется соответствие пользователя GUID системы.
    /// Если <see langword="false"/>, выполняется только проверка логина и пароля.
    /// </param>
    /// <returns>
    /// <see langword="true"/>, если учётные данные корректны
    /// (и, при <paramref name="guid"/> = <see langword="true"/>, пользователь разрешён для WebShelf);
    /// <see langword="false"/> — в противном случае.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Возникает, если не удалось установить соединение с контроллером домена.
    /// </exception>
    internal bool ValidateAdCredentials(string username, string password, bool guid = true)
    {
        const string method = nameof(ValidateAdCredentials);

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            Log.Warning(
                "Пустые учётные данные при проверке. Class={Class}, Method={Method}, UsernameEmpty={UsernameEmpty}, PasswordEmpty={PasswordEmpty}",
                ClassName, method,
                string.IsNullOrWhiteSpace(username),
                string.IsNullOrEmpty(password));
            return false;
        }

        string normalizedUser = (NormalizeUserName(username) ?? string.Empty).Trim();

        try
        {
            Log.Debug("Начало проверки учётных данных. Domain={Domain}, Username={Username}, CheckGuid={CheckGuid}", Name, normalizedUser, guid);

            // Проверка логина/пароля (контекст без сервисной учётки)
            using (PrincipalContext authContext = new(ContextType.Domain, Name))
            {
                if (!authContext.ValidateCredentials(normalizedUser, password, ContextOptions.Negotiate))
                {
                    Log.Warning("Неверные учётные данные. Domain={Domain}, Username={Username}", Name, normalizedUser); 
                    return false;
                }
            }

            // Без проверки GUID — достаточно валидных учётных данных
            if (!guid)
            {
                Log.Information("Учётные данные подтверждены (без проверки GUID). Domain={Domain}, Username={Username}",Name, normalizedUser);
                return true;
            }

            // GUID системы должен быть задан
            if (string.IsNullOrWhiteSpace(Service.Data.GUID))
            {
                Log.Error("GUID системы не задан. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",ClassName, method, Name, normalizedUser);
                return false;
            }

            // Для чтения атрибута info используем сервисную учётную запись
            using PrincipalContext context = new(ContextType.Domain, Name, User, _password);

            int atIndex = normalizedUser.IndexOf('@');
            string samAccountName = (atIndex > 0) ? normalizedUser[..atIndex] : normalizedUser;

            using UserPrincipal? user = 
                UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName) ??
                UserPrincipal.FindByIdentity(context, IdentityType.UserPrincipalName, normalizedUser);

            if (user is null)
            {
                Log.Warning("Пользователь не найден в AD после успешной аутентификации. Domain={Domain}, Username={Username}", Name, normalizedUser);
                return false;
            }

            // DirectoryEntry принадлежит UserPrincipal — отдельно не освобождаем
            if (user.GetUnderlyingObject() is not DirectoryEntry entry)
            {
                Log.Warning("Не удалось получить DirectoryEntry для пользователя. Domain={Domain}, Username={Username}", Name, normalizedUser);
                return false;
            }

            entry.RefreshCache(["info"]);
            object? infoValue = entry.Properties["info"]?.Value;
            string info = infoValue?.ToString() ?? string.Empty;

            bool allowed = info.Contains($"GUID|{Service.Data.GUID}", StringComparison.OrdinalIgnoreCase);

            if (allowed)
            {
                Log.Information("Учётные данные и GUID подтверждены. Domain={Domain}, Username={Username}", Name, normalizedUser);
            }
            else
            {
                Log.Warning("Пользователь не разрешён для WebShelf (GUID не найден в info). Domain={Domain}, Username={Username}", Name, normalizedUser);
            }

            return allowed;
        }
        catch (PrincipalServerDownException ex)
        {
            Log.Error(ex,"Контроллер домена недоступен при проверке учётных данных. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}", ClassName, method, Name, normalizedUser);

            throw new InvalidOperationException("Не удалось подключиться к Active Directory.", new InvalidOperationException($"Сервер: {Name}", ex));
        }
        catch (Exception ex)
        {
            // Остальные исключения считаем неверными учётными данными / временной ошибкой
            Log.Error(ex,"Ошибка при проверке учётных данных. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}", ClassName, method, Name, normalizedUser);
            return false;
        }
    }

    /// <summary>
    /// Извлекает строковое значение указанного атрибута из <see cref="SearchResult"/>.
    /// </summary>
    private static string? GetProperty(SearchResult result, string propertyName)
    {
        if (result.Properties[propertyName] is { Count: > 0 } props)
            return props[0]?.ToString();
        return null;
    }

    /// <summary>
    /// Приводит имя пользователя к формату <c>username@domainname</c>.
    /// </summary>
    /// <remarks>
    /// Домен берётся из <c>Data.Domain.Name</c> или из параметра <c>domainName</c> если указан явно. Поддерживаются три входных формата:
    /// <list type="bullet">
    ///   <item><description>короткое имя без домена (<c>ivanov</c>) — домен добавляется;</description></item>
    ///   <item><description>UPN (<c>ivanov@contoso.com</c>) — возвращается без изменений,
    ///     если домен совпадает с <c>Data.Domain.Name</c> (без учёта регистра);</description></item>
    ///   <item><description>down-level logon (<c>CONTOSO\ivanov</c>) — левая часть отбрасывается,
    ///     к правой добавляется домен.</description></item>
    /// </list>
    /// Если имя пустое, домен не задан, формат некорректен или домен во входном UPN
    /// не совпадает с <c>Data.Domain.Name</c>, метод записывает предупреждение в лог
    /// и возвращает <see langword="null"/>. Исключения не выбрасываются —
    /// любая ошибка логируется и приводит к возврату <see langword="null"/>.
    /// </remarks>
    /// <param name="userName">Имя пользователя, введённое в форме входа.
    /// Может содержать ведущие и хвостовые пробелы — они отбрасываются.</param>
    /// <returns>
    /// Имя пользователя в формате <c>username@domainname</c> либо
    /// <see langword="null"/>, если нормализация невозможна.
    /// </returns>
    /// <example>
    /// <code>
    /// // Data.Domain.Name == "contoso.com"
    /// NormalizeUserName("ivanov")              // "ivanov@contoso.com"
    /// NormalizeUserName("ivanov@contoso.com")  // "ivanov@contoso.com"
    /// NormalizeUserName(@"CONTOSO\ivanov")     // "ivanov@contoso.com"
    /// NormalizeUserName("ivanov@other.com")    // null
    /// NormalizeUserName("")                    // null
    /// </code>
    /// </example>
    public static string? NormalizeUserName(string userName, string? domainName = null)
    {
        const string methodName = nameof(NormalizeUserName);

        try
        {
            if (string.IsNullOrWhiteSpace(userName))
            {
                WarnInvalid("Не задано имя пользователя.");
                return null;
            }

            string domain = (domainName ?? Data.Domain?.Name ?? string.Empty).Trim();
            if (domain.Length == 0)
            {
                WarnInvalid("Не задано имя домена.");
                return null;
            }

            string user = userName.Trim();

            // Нет разделителей — просто добавляем домен.
            if (user.IndexOfAny(['@', '\\']) < 0) return $"{user}@{domain}";

            // Формат UPN: user@domain
            if (user.Contains('@'))
            {
                if (user.IndexOf('@') == user.LastIndexOf('@') &&                           // ровно один '@'
                    user.EndsWith($"@{domain}", StringComparison.OrdinalIgnoreCase) &&      // заканчивается на @{domain}
                    user.IndexOf('@') > 0 &&                                                // не начинается с '@'
                    user.IndexOf('@') < user.Length - 1)                                    // не заканчивается '@'
                {
                    return user;
                }
                WarnInvalid("Некорректное имя пользователя.");
                return null;
            }

            // Формат DOMAIN\user
            int slashIndex = user.IndexOf('\\');
            if (slashIndex <= 0 || slashIndex >= user.Length - 1)
            {
                WarnInvalid("Некорректное имя пользователя.");
                return null;
            }

            string bareUser = user[(slashIndex + 1)..].Trim();
            if (bareUser.Length == 0)
            {
                WarnInvalid("Некорректное имя пользователя.");
                return null;
            }

            return $"{bareUser}@{domain}";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Класс: {Class}, Метод: {Method}. Ошибка при нормализации имени пользователя: {UserName}.", typeof(Domain).FullName, methodName, userName);
            return null;
        }

        void WarnInvalid(string reason) => Log.Warning("Класс: {Class}, Метод: {Method}. {Reason} Имя: {UserName}.", typeof(Domain).FullName, methodName, reason, userName);
    }
}