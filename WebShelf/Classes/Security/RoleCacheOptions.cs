namespace WebShelf.Classes.Security;

/// <summary>
/// Параметры ролевой модели, читаемые из Server.conf: TTL кэша роли
/// и интервал фонового опроса ролевых групп AD. Создаётся в
/// <c>Data.InitRoleCacheOptions</c> при чтении конфигурации и регистрируется
/// в DI как singleton.
/// </summary>
internal sealed class RoleCacheOptions
{
    /// <summary>
    /// TTL по умолчанию, с: согласованное окно устаревания для обычных операций.
    /// </summary>
    internal const int DefaultTtlSeconds = 60;

    /// <summary>
    /// Интервал опроса по умолчанию, с: вдвое меньше TTL — смена роли доезжает
    /// до открытых цепочек не позже ~30 с после правки групп в AD.
    /// </summary>
    internal const int DefaultPollIntervalSeconds = 30;

    /// <summary>
    /// Нижняя граница диапазона, с: чаще — LDAP-нагрузка без выигрыша в свежести
    /// (свежесть закрывает фоновый опрос и push).
    /// </summary>
    internal const int MinSeconds = 10;

    /// <summary>
    /// Верхняя граница диапазона, с: дольше — окно устаревания неприемлемо велико.
    /// </summary>
    internal const int MaxSeconds = 300;

    private RoleCacheOptions(TimeSpan cacheTtl, TimeSpan pollInterval)
    {
        CacheTtl = cacheTtl;
        PollInterval = pollInterval;
    }

    /// <summary>
    /// TTL кэша роли: в пределах TTL роль берётся из кэша без обращения к AD.
    /// </summary>
    internal TimeSpan CacheTtl { get; }

    /// <summary>
    /// Интервал фонового опроса ролевых групп (вариант 2 — push смены роли в цепочки).
    /// </summary>
    internal TimeSpan PollInterval { get; }

    /// <summary>
    /// Создаёт параметры из значений в секундах. Значение в диапазоне
    /// [MinSeconds; MaxSeconds] используется как задано; отсутствующее, нечисловое
    /// или вне диапазона — заменяется значением по умолчанию (TTL — 60 с,
    /// интервал опроса — 30 с).
    /// </summary>
    /// <param name="ttlSeconds">TTL из конфигурации (ключ <c>rolettl</c>); <see langword="null"/> — не задан.</param>
    /// <param name="pollIntervalSeconds">Интервал из конфигурации (ключ <c>rolepoll</c>); <see langword="null"/> — не задан.</param>
    /// <param name="ttlSource">Описание источника значения TTL — для записи в лог.</param>
    /// <param name="pollSource">Описание источника интервала — для записи в лог.</param>
    internal static RoleCacheOptions Create(
        int? ttlSeconds,
        int? pollIntervalSeconds,
        out string ttlSource,
        out string pollSource)
    {
        TimeSpan cacheTtl = Normalize(ttlSeconds, DefaultTtlSeconds, out ttlSource);
        TimeSpan pollInterval = Normalize(pollIntervalSeconds, DefaultPollIntervalSeconds, out pollSource);

        return new RoleCacheOptions(cacheTtl, pollInterval);
    }

    /// <summary>
    /// Создаёт параметры из готовых интервалов. Используется юнит-тестами
    /// (интервалы меньше секунды) — производственный код идёт через <see cref="Create"/>.
    /// </summary>
    /// <param name="cacheTtl">TTL кэша роли.</param>
    /// <param name="pollInterval">Интервал фонового опроса.</param>
    internal static RoleCacheOptions FromTimeSpans(TimeSpan cacheTtl, TimeSpan pollInterval)
    {
        return new RoleCacheOptions(cacheTtl, pollInterval);
    }

    /// <summary>
    /// Приводит значение из конфигурации к TimeSpan с применением значения
    /// по умолчанию вне диапазона; заодно описывает источник значения.
    /// </summary>
    private static TimeSpan Normalize(int? seconds, int defaultSeconds, out string source)
    {
        if (seconds is null)
        {
            source = "не задано или не число, принято по умолчанию";
            return TimeSpan.FromSeconds(defaultSeconds);
        }

        if (seconds.Value < MinSeconds || seconds.Value > MaxSeconds)
        {
            source = $"вне диапазона {MinSeconds}–{MaxSeconds}, принято по умолчанию";
            return TimeSpan.FromSeconds(defaultSeconds);
        }

        source = "из конфигурации";
        return TimeSpan.FromSeconds(seconds.Value);
    }
}
