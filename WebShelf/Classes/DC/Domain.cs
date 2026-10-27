using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using Serilog;
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
/// <remarks>
/// Сервисный логин и пароль хранятся только в зашифрованном виде (мастер-ключ).
/// Перед использованием для AD-операций значения расшифровываются.
/// </remarks>
internal class Domain
{
    private const string ClassName = "WebShelf.Classes.DC.Domain";

    /// <summary>
    /// Имя домена (FQDN), например: "company.local".
    /// </summary>
    internal string Name { get; }

    /// <summary>
    /// Имя сервисной учётной записи для подключения к Active Directory
    /// в открытом виде (расшифровывается при каждом обращении).
    /// </summary>
    internal string User => GetDecryptedUser();

    /// <summary>
    /// LDAP-путь к корню домена (используется при поиске объектов).
    /// </summary>
    internal string Path { get; }

    /// <summary>
    /// Зашифрованное имя сервисной учётной записи (мастер-ключ).
    /// </summary>
    private readonly string _encryptedUser;

    /// <summary>
    /// Зашифрованный пароль сервисной учётной записи (мастер-ключ).
    /// </summary>
    private readonly string _encryptedPassword;

    /// <summary>
    /// Создаёт экземпляр класса <see cref="Domain"/>.
    /// Параметры <paramref name="encryptedUser"/> и <paramref name="encryptedPassword"/>
    /// должны быть уже зашифрованы мастер-ключом (<see cref="EncryptionService"/>).
    /// Перед проверками значения расшифровываются; в поля сохраняются зашифрованные данные.
    /// </summary>
    /// <param name="domain">Имя домена (FQDN).</param>
    /// <param name="encryptedUser">Зашифрованное имя сервисной учётной записи (Base64).</param>
    /// <param name="encryptedPassword">Зашифрованный пароль сервисной учётной записи (Base64).</param>
    /// <exception cref="ArgumentException">
    /// Возникает, если имя домена пустое, либо после расшифровки логин/пароль пустые
    /// или логин не удаётся привести к формату username@domain.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Возникает, если мастер-ключ недоступен или расшифровка не удалась.
    /// </exception>
    internal Domain(string domain, string encryptedUser, string encryptedPassword)
    {
        const string method = ".ctor";

        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Имя домена не может быть пустым.", nameof(domain));
        if (string.IsNullOrWhiteSpace(encryptedUser))
            throw new ArgumentException("Зашифрованное имя пользователя не может быть пустым.", nameof(encryptedUser));
        if (string.IsNullOrWhiteSpace(encryptedPassword))
            throw new ArgumentException("Зашифрованный пароль не может быть пустым.", nameof(encryptedPassword));

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        if (masterKey is null)
        {
            Log.Error(
                "Мастер-ключ недоступен в конструкторе Domain. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Мастер-ключ шифрования недоступен.");
        }

        // Перед проверками расшифровываем
        string plainUser;
        string plainPassword;
        try
        {
            plainUser = EncryptionService.Decrypt(encryptedUser.Trim(), masterKey);
            plainPassword = EncryptionService.Decrypt(encryptedPassword.Trim(), masterKey);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Не удалось расшифровать учётные данные в конструкторе Domain. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Не удалось расшифровать учётные данные сервисной записи.", ex);
        }

        if (string.IsNullOrWhiteSpace(plainUser))
            throw new ArgumentException("Имя пользователя после расшифровки пустое.", nameof(encryptedUser));
        if (string.IsNullOrWhiteSpace(plainPassword))
            throw new ArgumentException("Пароль после расшифровки пустой.", nameof(encryptedPassword));

        string? userName = NormalizeUserName(plainUser, domain);
        if (string.IsNullOrWhiteSpace(userName))
            throw new ArgumentException($"Имя пользователя '{plainUser}' не удалось привести к формату username@domain.", nameof(encryptedUser));

        Name = domain.Trim();

        // Перед записью в поля — шифруем (нормализованный логин и пароль)
        try
        {
            _encryptedUser = EncryptionService.Encrypt(userName.Trim(), masterKey);
            _encryptedPassword = EncryptionService.Encrypt(plainPassword, masterKey);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Не удалось зашифровать учётные данные перед сохранением. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Не удалось зашифровать учётные данные сервисной записи.", ex);
        }

        // LDAP-путь: DNS-имя домена + DN корня.
        // Формат LDAP://domain/DC=... надёжнее serverless-привязки LDAP://DC=...
        // (иначе ADSI часто возвращает 0x8007054B — «домен не существует»).
        IEnumerable<string> dcParts = Name
            .Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => $"DC={p}");
        Path = $"LDAP://{Name}/{string.Join(",", dcParts)}";

        Log.Debug(
            "Создан экземпляр Domain. Class={Class}, Method={Method}, Domain={Domain}, User={User}, Path={Path}",
            ClassName, method, Name, userName, Path);
    }

    /// <summary>
    /// Возвращает расшифрованное имя сервисной учётной записи.
    /// </summary>
    /// <returns>Логин в формате username@domain.</returns>
    /// <exception cref="InvalidOperationException">Если мастер-ключ недоступен или расшифровка не удалась.</exception>
    internal string GetDecryptedUser()
    {
        const string method = nameof(GetDecryptedUser);

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        if (masterKey is null)
        {
            Log.Error(
                "Мастер-ключ недоступен при расшифровке User. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Мастер-ключ шифрования недоступен.");
        }

        try
        {
            return EncryptionService.Decrypt(_encryptedUser, masterKey);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка расшифровки User. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Не удалось расшифровать имя сервисной учётной записи.", ex);
        }
    }

    /// <summary>
    /// Возвращает расшифрованный пароль сервисной учётной записи.
    /// </summary>
    /// <returns>Пароль в открытом виде.</returns>
    /// <exception cref="InvalidOperationException">Если мастер-ключ недоступен или расшифровка не удалась.</exception>
    internal string GetDecryptedPassword()
    {
        const string method = nameof(GetDecryptedPassword);

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        if (masterKey is null)
        {
            Log.Error(
                "Мастер-ключ недоступен при расшифровке Password. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Мастер-ключ шифрования недоступен.");
        }

        try
        {
            return EncryptionService.Decrypt(_encryptedPassword, masterKey);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка расшифровки Password. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Не удалось расшифровать пароль сервисной учётной записи.", ex);
        }
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
            Log.Information(
                "Начало получения списка пользователей AD. Class={Class}, Method={Method}, Domain={Domain}",
                ClassName, method, Name);

            string serviceUser = GetDecryptedUser();
            string servicePassword = GetDecryptedPassword();

            Log.Debug(
                "Подключение к AD для списка пользователей. Class={Class}, Method={Method}, Domain={Domain}, Path={Path}, User={User}",
                ClassName, method, Name, Path, serviceUser);

            // AuthenticationTypes.Secure — negotiate/Kerberos или NTLM; без serverless-сбоев 0x8007054B
            using DirectoryEntry searchRoot = new(
                Path,
                serviceUser,
                servicePassword,
                AuthenticationTypes.Secure);
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
                    Log.Debug(
                        "Пропущена запись без sAMAccountName. Class={Class}, Method={Method}, Domain={Domain}",
                        ClassName, method, Name);
                    continue;
                }

                string displayName = GetProperty(result, "displayName") ?? sam;
                string email = GetProperty(result, "mail") ?? string.Empty;

                users.Add(new AdUserInfo(sam, displayName, email));
            }

            Log.Information(
                "Список пользователей AD успешно получен. Class={Class}, Method={Method}, Domain={Domain}, Count={Count}",
                ClassName, method, Name, users.Count);

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
        catch (System.Runtime.InteropServices.COMException ex)
        {
            Log.Error(ex,
                "COM-ошибка AD при получении пользователей. Class={Class}, Method={Method}, Domain={Domain}, Path={Path}, HResult=0x{HResult:X8}",
                ClassName, method, Name, Path, ex.HResult);

            throw new InvalidOperationException(
                "Не удалось подключиться к Active Directory (LDAP).",
                new InvalidOperationException($"Сервер: {Name}, Path: {Path}", ex));
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            Log.Error(ex,
                "Ошибка при получении списка пользователей из Active Directory. Class={Class}, Method={Method}, Domain={Domain}, Path={Path}",
                ClassName, method, Name, Path);

            throw new InvalidOperationException(
                "Ошибка при получении списка пользователей из Active Directory.", ex);
        }
    }

    /// <summary>
    /// Проверяет учётные данные пользователя в Active Directory.
    /// При <paramref name="guid"/> = <see langword="true"/> дополнительно проверяет,
    /// что в атрибуте <c>info</c> пользователя указан GUID системы (<see cref="Service.Data.GUID"/>).
    /// Параметры <paramref name="username"/> и <paramref name="password"/> передаются в открытом виде
    /// (как ввёл пользователь или как подготовлены при старте сервиса).
    /// </summary>
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
            Log.Debug(
                "Начало проверки учётных данных. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}, CheckGuid={CheckGuid}",
                ClassName, method, Name, normalizedUser, guid);

            // Проверка логина/пароля (контекст без сервисной учётки)
            using (PrincipalContext authContext = new(ContextType.Domain, Name))
            {
                if (!authContext.ValidateCredentials(normalizedUser, password, ContextOptions.Negotiate))
                {
                    Log.Warning(
                        "Неверные учётные данные. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                        ClassName, method, Name, normalizedUser);
                    return false;
                }
            }

            // Без проверки GUID — достаточно валидных учётных данных
            if (!guid)
            {
                Log.Information(
                    "Учётные данные подтверждены (без проверки GUID). Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, normalizedUser);
                return true;
            }

            // GUID системы должен быть задан
            if (string.IsNullOrWhiteSpace(Service.Data.GUID))
            {
                Log.Error(
                    "GUID системы не задан. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, normalizedUser);
                return false;
            }

            // Для чтения атрибута info используем сервисную учётную запись (расшифрованную)
            string serviceUser = GetDecryptedUser();
            string servicePassword = GetDecryptedPassword();

            using PrincipalContext context = new(ContextType.Domain, Name, serviceUser, servicePassword);

            int atIndex = normalizedUser.IndexOf('@');
            string samAccountName = (atIndex > 0) ? normalizedUser[..atIndex] : normalizedUser;

            using UserPrincipal? user =
                UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName) ??
                UserPrincipal.FindByIdentity(context, IdentityType.UserPrincipalName, normalizedUser);

            if (user is null)
            {
                Log.Warning(
                    "Пользователь не найден в AD после успешной аутентификации. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, normalizedUser);
                return false;
            }

            // DirectoryEntry принадлежит UserPrincipal — отдельно не освобождаем
            if (user.GetUnderlyingObject() is not DirectoryEntry entry)
            {
                Log.Warning(
                    "Не удалось получить DirectoryEntry для пользователя. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, normalizedUser);
                return false;
            }

            entry.RefreshCache(["info"]);
            object? infoValue = entry.Properties["info"]?.Value;
            string info = infoValue?.ToString() ?? string.Empty;

            bool allowed = info.Contains($"GUID|{Service.Data.GUID}", StringComparison.OrdinalIgnoreCase);

            if (allowed)
            {
                Log.Information(
                    "Учётные данные и GUID подтверждены. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, normalizedUser);
            }
            else
            {
                Log.Warning(
                    "Пользователь не разрешён для WebShelf (GUID не найден в info). Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, normalizedUser);
            }

            return allowed;
        }
        catch (PrincipalServerDownException ex)
        {
            Log.Error(ex,
                "Контроллер домена недоступен при проверке учётных данных. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                ClassName, method, Name, normalizedUser);

            throw new InvalidOperationException(
                "Не удалось подключиться к Active Directory.",
                new InvalidOperationException($"Сервер: {Name}", ex));
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка при проверке учётных данных. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                ClassName, method, Name, normalizedUser);

            throw new InvalidOperationException(
                "Ошибка при проверке учётных данных в Active Directory.", ex);
        }
    }

    /// <summary>
    /// Извлекает первое строковое значение свойства из результата поиска AD.
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
    public static string? NormalizeUserName(string userName, string? domainName = null)
    {
        const string method = nameof(NormalizeUserName);

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
                if (user.IndexOf('@') == user.LastIndexOf('@') &&
                    user.EndsWith($"@{domain}", StringComparison.OrdinalIgnoreCase) &&
                    user.IndexOf('@') > 0 &&
                    user.IndexOf('@') < user.Length - 1)
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
            Log.Error(ex,
                "Ошибка при нормализации имени пользователя. Class={Class}, Method={Method}, UserName={UserName}",
                ClassName, method, userName);
            return null;
        }

        void WarnInvalid(string reason) =>
            Log.Warning(
                "{Reason} Class={Class}, Method={Method}, UserName={UserName}",
                reason, ClassName, method, userName);
    }
}
