using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace WebShelf.Classes.DC;

/// <summary>
/// Представляет домен Active Directory и предоставляет методы
/// для получения пользователей системы и проверки учётных данных.
/// Используется в браузерном приложении WebShelf для работы
/// с документацией в проектной организации промышленного и гражданского строительства.
/// </summary>
internal class Domain
{
    /// <summary>
    /// Имя домена (FQDN), например: "company.local".
    /// </summary>
    internal string Name { get; }

    /// <summary>
    /// Имя сервисной учётной записи для подключения к Active Directory.
    /// </summary>
    internal string User { get; }

    /// <summary>
    /// Пароль сервисной учётной записи.
    /// </summary>
    internal string Password { get; }

    /// <summary>
    /// LDAP-путь к корню домена (используется при поиске объектов).
    /// </summary>
    internal string Path { get; }

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
        if (password is null)
            throw new ArgumentNullException(nameof(password));

        Name = domain.Trim();
        User = user.Trim();
        Password = password;

        // Формируем LDAP-путь к корню домена (DC=...)
        IEnumerable<string> dcParts = Name.Split('.', StringSplitOptions.RemoveEmptyEntries).Select(p => $"DC={p}");
        Path = $"LDAP://{string.Join(",", dcParts)}";
    }

    /// <summary>
    /// Возвращает список пользователей Active Directory, которые разрешены
    /// для работы в системе WebShelf.
    /// Пользователь считается разрешённым, если:
    /// - учётная запись включена;
    /// - в атрибуте <c>info</c> указан GUID системы (<see cref="Service.Data.GUID"/>).
    /// Поиск выполняется на стороне контроллера домена с постраничной выборкой.
    /// </summary>
    /// <returns>Список объектов <see cref="UserPrincipal"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Возникает при ошибках подключения к Active Directory или выполнения поиска.
    /// </exception>
    internal List<UserPrincipal> GetAllUsers()
    {
        List<UserPrincipal> users = [];

        try
        {
            using PrincipalContext context = new(ContextType.Domain, Name, User, Password);
            using DirectoryEntry searchRoot = new(Path, User, Password);
            using DirectorySearcher searcher = new(searchRoot)
            {
                // Фильтр: пользователь, включённая учётная запись, нужный GUID в поле info
                Filter = $"(&(objectCategory=person)(objectClass=user)" +
                         $"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                         $"(info={Service.Data.GUID}))",
                PageSize = 1000,               // поддержка больших доменов
                SearchScope = SearchScope.Subtree
            };

            // Загружаем только необходимые атрибуты
            searcher.PropertiesToLoad.Add("sAMAccountName");

            using SearchResultCollection results = searcher.FindAll();

            foreach (SearchResult result in results)
            {
                string? samAccountName = result.Properties["sAMAccountName"] is { Count: > 0 } props
                    ? props[0]?.ToString()
                    : null;

                if (string.IsNullOrWhiteSpace(samAccountName))
                    continue;

                UserPrincipal? user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName);

                if (user is not null) users.Add(user);
            }
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException(
                "Ошибка при получении списка пользователей из Active Directory.", ex);
        }

        return users;
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
        if (string.IsNullOrWhiteSpace(username) || password is null) return false;

        try
        {
            // Проверка логина/пароля (контекст без сервисной учётки)
            using (PrincipalContext authContext = new(ContextType.Domain, Name))
            {
                if (!authContext.ValidateCredentials(username, password, ContextOptions.Negotiate)) return false;
            }

            // Без проверки GUID — достаточно валидных учётных данных
            if (!guid) return true;

            // GUID системы должен быть задан
            if (string.IsNullOrWhiteSpace(Service.Data.GUID)) return false;

            // Для чтения атрибута info используем сервисную учётную запись
            using PrincipalContext context = new(ContextType.Domain, Name, User, Password);
            using UserPrincipal? user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username.Trim());

            if (user is null) return false;

            // DirectoryEntry принадлежит UserPrincipal — отдельно не освобождаем
            if (user.GetUnderlyingObject() is not DirectoryEntry entry) return false;

            entry.RefreshCache(["info"]);
            object? infoValue = entry.Properties["info"]?.Value;
            string? info = infoValue?.ToString();

            return !string.IsNullOrWhiteSpace(info) && string.Equals(info.Trim(), Service.Data.GUID.Trim(), StringComparison.OrdinalIgnoreCase);
        }
        catch (PrincipalServerDownException ex)
        {
            throw new InvalidOperationException(
                "Не удалось подключиться к Active Directory.",
                new InvalidOperationException($"Сервер: {Name}", ex));
        }
        catch (Exception) when (true) // все остальные исключения считаем неверными учётными данными
        {
            return false;
        }
    }
}

