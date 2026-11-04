using System.Security.Claims;

namespace WebShelf.Classes.Security;

/// <summary>
/// Расширения <see cref="ClaimsPrincipal"/> для работы с ролями WebShelf.
/// Компоненты интерфейса не читают ролевые утверждения напрямую и не сравнивают
/// строки — только через эти методы и <see cref="RoleCatalog"/>. Утверждение роли
/// в cookie — транспорт (роль на момент входа); для критичных операций используется
/// свежая проверка через <see cref="RoleResolver"/>.
/// </summary>
internal static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Тип утверждения со списком всех назначенных ролей (системные имена через запятую).
    /// Используется для диагностики и отображения; авторизация по нему не выполняется.
    /// </summary>
    internal const string MatchedRolesClaimType = "WebShelf:MatchedRoles";

    /// <summary>
    /// Возвращает роль пользователя из утверждения роли. Анонимному пользователю
    /// и пользователю без утверждения (или с неизвестным именем роли) возвращает
    /// <see langword="null"/>.
    /// </summary>
    /// <param name="user">Текущий пользователь.</param>
    /// <returns>Роль каталога либо <see langword="null"/>.</returns>
    internal static AppRole? GetAppRole(this ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);

        string? systemName = user.FindFirst(ClaimTypes.Role)?.Value;
        return RoleCatalog.TryGetBySystemName(systemName);
    }

    /// <summary>
    /// Проверяет, назначена ли пользователю указанная роль (по утверждению роли).
    /// </summary>
    /// <param name="user">Текущий пользователь.</param>
    /// <param name="roleId">Идентификатор роли.</param>
    /// <returns><see langword="true"/>, если действующая роль совпадает с указанной.</returns>
    internal static bool IsInRole(this ClaimsPrincipal user, AppRoleId roleId)
    {
        ArgumentNullException.ThrowIfNull(user);

        AppRole? role = user.GetAppRole();
        return role is not null && role.Id == roleId;
    }

    /// <summary>
    /// Проверяет, что действующая роль пользователя не ниже указанной по старшинству
    /// (индекс старшинства действующей роли меньше или равен указанной).
    /// У анонимного пользователя и Гостя проверка всегда даёт <see langword="false"/>
    /// для любой роли, кроме проверки «не ниже Гостя».
    /// </summary>
    /// <param name="user">Текущий пользователь.</param>
    /// <param name="minimumRoleId">Минимально допустимая роль (например, <see cref="AppRoleId.Manager"/>).</param>
    /// <returns><see langword="true"/>, если роль пользователя не ниже указанной.</returns>
    internal static bool IsAtLeast(this ClaimsPrincipal user, AppRoleId minimumRoleId)
    {
        ArgumentNullException.ThrowIfNull(user);

        AppRole? role = user.GetAppRole();
        if (role is null)
        {
            return false;
        }

        AppRole minimumRole = RoleCatalog.AllRoles.First(candidate => candidate.Id == minimumRoleId);
        return role.SeniorityIndex <= minimumRole.SeniorityIndex;
    }
}
