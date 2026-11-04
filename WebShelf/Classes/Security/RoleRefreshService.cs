using Microsoft.Extensions.Hosting;

namespace WebShelf.Classes.Security;

/// <summary>
/// Фоновая служба опроса ролевых групп AD (вариант 2): с заданным интервалом
/// пересчитывает роль каждого отслеживаемого пользователя свежим запросом
/// (в обход TTL) и рассылает изменения в активные цепочки через
/// <see cref="RoleChangeNotifier"/>. Потеря группы Users — принудительный выход.
/// При недоступности AD пользователи пропускаются: массовый выход не выполняется.
/// </summary>
internal sealed class RoleRefreshService : BackgroundService
{
    private const string ClassName = "WebShelf.Classes.Security.RoleRefreshService";

    private readonly RoleResolver _resolver;
    private readonly RoleChangeNotifier _notifier;
    private readonly RoleCacheOptions _options;

    /// <summary>
    /// Конструктор объявлен <see langword="public"/> (сам класс остаётся internal):
    /// контейнер DI находит только public-конструкторы.
    /// </summary>
    public RoleRefreshService(RoleResolver roleResolver, RoleChangeNotifier changeNotifier, RoleCacheOptions options)
    {
        _resolver = roleResolver;
        _notifier = changeNotifier;
        _options = options;
    }

    /// <summary>
    /// Цикл опроса: первый опрос через интервал после старта (состояние на момент
    /// входа и так свежее — его посчитал резолвер при входе), далее — с периодичностью
    /// <see cref="RoleCacheOptions.PollInterval"/>.
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        const string method = nameof(ExecuteAsync);

        Log.Information(
            "Фоновый опрос ролевых групп запущен. IntervalSec={Interval}. Class={Class}, Method={Method}",
            (int)_options.PollInterval.TotalSeconds, ClassName, method);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(_options.PollInterval, stoppingToken);
                PollOnce();
            }
        }
        catch (OperationCanceledException)
        {
            // Остановка по запросу завершения — штатный путь
        }
        catch (Exception ex)
        {
            // Сбой цикла не должен приводить к тихой смерти службы
            Log.Error(ex, "Фоновый опрос ролевых групп остановлен из-за ошибки. Class={Class}, Method={Method}", ClassName, method);
        }

        Log.Information(
            "Фоновый опрос ролевых групп остановлен. Class={Class}, Method={Method}",
            ClassName, method);
    }

    /// <summary>
    /// Один цикл опроса. Вынесен в отдельный internal-метод для юнит-тестов:
    /// тесты вызывают его напрямую, без задержек.
    /// </summary>
    internal void PollOnce()
    {
        const string method = nameof(PollOnce);

        try
        {
            List<string> usernames = _resolver.GetTrackedUsernames().ToList();

            foreach (string username in usernames)
            {
                // Значение из кэша до запроса = «предыдущее»: ResolveFresh
                // перезапишет кэш, сравнение будет с состоянием «до»
                RoleResolution? before = _resolver.Peek(username);
                RoleResolution? fresh = _resolver.ResolveFresh(username);

                if (fresh is null)
                {
                    // AD недоступен: пользователь пропускается в этом цикле
                    Log.Warning(
                        "AD недоступен: пользователь пропущен в этом цикле опроса. Username={User}. Class={Class}, Method={Method}",
                        "UserAccount", ClassName, method);
                    continue;
                }

                if (!fresh.HasUsersGroup)
                {
                    // Потеря группы Users — принудительный выход из цепочек.
                    // Событие поднимается один раз на переход: дальше кэш уже
                    // хранит HasUsersGroup=false и повторных рассылок нет
                    if (before is null || before.HasUsersGroup)
                    {
                        _notifier.Raise(new RoleChange(username, null, RoleChange.ReasonUsersGroupLost));
                    }

                    continue;
                }

                // Смена роли (или возврат Users после принудительного выхода):
                // сравнение и по роли, и по членству в Users
                if (before is not null &&
                    (before.Role.SystemName != fresh.Role.SystemName || before.HasUsersGroup != fresh.HasUsersGroup))
                {
                    _notifier.Raise(new RoleChange(username, fresh, RoleChange.ReasonRoleChanged));
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в цикле опроса. Class={Class}, Method={Method}", ClassName, method);
        }
    }
}
