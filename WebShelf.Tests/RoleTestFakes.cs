using WebShelf.Classes.DC;

namespace WebShelf.Tests;

/// <summary>
/// Подмены для тестов ролевой модели: источник групп AD и тайм-провайдер.
/// Настоящий Domain не тестируется (требует живого AD).
/// </summary>
public static class RoleTestFakes
{
    /// <summary>
    /// Короткий префикс InstanceId, используемый подменой: как в Debug-сборке.
    /// </summary>
    public const string InstanceShort = "000000000000";

    /// <summary>
    /// Подмена IAdGroupSource: состав групп настраивается по пользователю,
    /// ведёт счётчик обращений и умеет имитировать недоступность AD.
    /// </summary>
    public sealed class FakeAdGroupSource : IAdGroupSource
    {
        private readonly Dictionary<string, List<string>> _groupsByUser =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Число обращений GetUserGroupNames (промахи кэша и свежие вычисления).</summary>
        public int GetUserGroupNamesCalls { get; private set; }

        /// <summary>Когда true, GetUserGroupNames возвращает null — имитация сбоя AD.</summary>
        public bool AdUnavailable { get; set; }

        public string? GetExpandedGroupName(string suffix)
        {
            if (string.IsNullOrWhiteSpace(suffix))
            {
                return null;
            }

            return $"WebShelf-{InstanceShort}-{suffix.Trim()}";
        }

        public IReadOnlyList<string>? GetUserGroupNames(string samAccountName)
        {
            if (AdUnavailable)
            {
                return null;
            }

            GetUserGroupNamesCalls++;

            return _groupsByUser.TryGetValue(samAccountName, out List<string>? groups)
                ? groups
                : [];
        }

        /// <summary>Задаёт прямые группы пользователя.</summary>
        public void SetUserGroups(string samAccountName, params string[] groupNames)
        {
            _groupsByUser[samAccountName] = [.. groupNames];
        }
    }

    /// <summary>
    /// Подмена TimeProvider: время двигается вручную — для проверки истечения TTL
    /// без реального ожидания.
    /// </summary>
    public sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow()
        {
            return _utcNow;
        }

        /// <summary>Сдвигает время вперёд.</summary>
        public void Advance(TimeSpan delta)
        {
            _utcNow += delta;
        }
    }
}
