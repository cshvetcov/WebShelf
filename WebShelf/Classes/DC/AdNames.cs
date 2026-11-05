namespace WebShelf.Classes.DC;

/// <summary>
/// Чистые функции имён Active Directory: нормализация имени пользователя
/// к формату <c>username@domain</c> и подстановка короткого префикса
/// InstanceId в шаблон имени группы. Методы не обращаются к AD, конфигурации
/// и состоянию приложения: все входные данные передаются параметрами.
/// Используются <see cref="Domain"/>, менеджером групп
/// (<see cref="AdGroupManager"/>), эндпоинтами входа (<c>AccountEndpoints</c>)
/// и каталогом ролей (<c>RoleCatalog</c>).
/// </summary>
internal static class AdNames
{
    private const string ClassName = "WebShelf.Classes.DC.AdNames";

    /// <summary>
    /// Заполнитель короткого префикса InstanceId в шаблонах имён групп.
    /// </summary>
    internal const string InstanceIdShortPlaceholder = "{InstanceIdShort}";

    /// <summary>
    /// Приводит имя пользователя к формату <c>username@domain</c>.
    /// Имя домена передаётся явно — класс не зависит от хранилища Data.
    /// </summary>
    internal static string? NormalizeUserName(string userName, string domainName)
    {
        const string method = nameof(NormalizeUserName);

        try
        {
            if (string.IsNullOrWhiteSpace(userName))
            {
                WarnInvalid("Не задано имя пользователя.");
                return null;
            }

            string domain = domainName.Trim();
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
                ClassName, method, "UserAccount");
            return null;
        }

        void WarnInvalid(string reason) =>
            Log.Warning(
                "{Reason} Class={Class}, Method={Method}, UserName={UserName}",
                reason, ClassName, method, "UserAccount");
    }

    /// <summary>
    /// Подставляет в шаблон имени группы короткий префикс InstanceId вместо
    /// заполнителя <see cref="InstanceIdShortPlaceholder"/>. Замена выполняется
    /// для всех вхождений заполнителя и без учёта его регистра; шаблон без
    /// заполнителя возвращается без изменений (пробелы по краям обрезаются).
    /// Метод выполняет только подстановку: обнаружение опечаток в заполнителе
    /// выполняет <see cref="AdGroupManager.FillRequiredGroupsFromTemplates"/>.
    /// </summary>
    /// <param name="template">Шаблон имени группы, например WebShelf-{InstanceIdShort}-Administrator.</param>
    /// <param name="instanceIdShort">Короткий префикс InstanceId (12 символов, нижний регистр).</param>
    /// <returns>Имя группы с выполненной подстановкой.</returns>
    /// <exception cref="ArgumentException">Если шаблон или префикс пустые.</exception>
    internal static string ExpandGroupTemplate(string template, string instanceIdShort)
    {
        if (string.IsNullOrWhiteSpace(template))
            throw new ArgumentException("Шаблон имени группы не может быть пустым.", nameof(template));
        if (string.IsNullOrWhiteSpace(instanceIdShort))
            throw new ArgumentException("Короткий префикс InstanceId не может быть пустым.", nameof(instanceIdShort));

        return template.Trim().Replace(InstanceIdShortPlaceholder, instanceIdShort, StringComparison.OrdinalIgnoreCase);
    }
}
