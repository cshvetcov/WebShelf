using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты фонового опроса ролевых групп (вариант 2): PollOnce вызывается напрямую,
/// без задержек ExecuteAsync. Проверяются рассылка событий смены роли
/// подписчику конкретного пользователя, принудительный выход при потере группы
/// Users (событие без группы доступа) и поведение при сбое AD.
/// </summary>
public class RoleRefreshServiceTests
{
    /// <summary>Фиксированный InstanceIdShort, как в подмене источника групп.</summary>
    private const string Id = RoleTestFakes.InstanceShort;

    /// <summary>Собирает события нотификатора для проверок.</summary>
    private sealed class EventRecorder
    {
        public List<RoleResolution> Events { get; } = [];

        public void OnRoleChanged(RoleResolution resolution)
        {
            Events.Add(resolution);
        }
    }

    private static RoleTestFakes.FakeAdGroupSource SetupUser(
        RoleTestFakes.FakeAdGroupSource ad,
        string username,
        string roleSuffix)
    {
        ad.SetUserGroups(username, $"WebShelf-{Id}-Users", $"WebShelf-{Id}-{roleSuffix}");
        return ad;
    }

    private static (RoleResolver Resolver, RoleRefreshService Service, EventRecorder Recorder) CreateStack(
        RoleTestFakes.FakeAdGroupSource ad)
    {
        RoleCacheOptions options = RoleCacheOptions.FromTimeSpans(
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(10));
        RoleResolver resolver = new(ad, options, new RoleTestFakes.FakeTimeProvider());

        RoleChangeNotifier notifier = new();
        EventRecorder recorder = new();
        // Подписка на события конкретного пользователя — как это делает
        // провайдер состояния аутентификации активной цепочки
        notifier.Subscribe("ivanov", recorder.OnRoleChanged);

        RoleRefreshService service = new(resolver, notifier, options);

        return (resolver, service, recorder);
    }

    /// <summary>
    /// Смена роли между опросами — событие с новым состоянием ролей.
    /// </summary>
    [Fact]
    public void PollOnce_RoleChanged_RaisesEvent()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        SetupUser(ad, "ivanov", "Executor");
        (RoleResolver resolver, RoleRefreshService service, EventRecorder recorder) = CreateStack(ad);

        resolver.Resolve("ivanov");

        // Меняем состав групп: повышение до GIP
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-GIP");
        service.PollOnce();

        RoleResolution change = Assert.Single(recorder.Events);
        Assert.Same(RoleCatalog.Gip, change.EffectiveRole);
        Assert.True(change.HasUsersGroup);
    }

    /// <summary>
    /// Роль не изменилась — событий нет (штатный цикл без спама).
    /// </summary>
    [Fact]
    public void PollOnce_NoChange_NoEvents()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        SetupUser(ad, "ivanov", "Manager");
        (RoleResolver resolver, RoleRefreshService service, EventRecorder recorder) = CreateStack(ad);

        resolver.Resolve("ivanov");
        service.PollOnce();

        Assert.Empty(recorder.Events);
    }

    /// <summary>
    /// Потеря группы Users — принудительный выход: событие с состоянием без группы
    /// доступа (провайдер цепочки переводит пользователя в анонимное состояние);
    /// повторный цикл не дублирует событие.
    /// </summary>
    [Fact]
    public void PollOnce_UsersGroupLost_ForcedLogoutOnce()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        SetupUser(ad, "ivanov", "Manager");
        (RoleResolver resolver, RoleRefreshService service, EventRecorder recorder) = CreateStack(ad);

        resolver.Resolve("ivanov");

        // Пользователь исключён из всех групп (удалён из AD или снят с Users)
        ad.SetUserGroups("ivanov");
        service.PollOnce();
        service.PollOnce();

        RoleResolution change = Assert.Single(recorder.Events);
        Assert.False(change.HasUsersGroup);
        Assert.True(change.IsGuest);
    }

    /// <summary>
    /// Смена роли без Users (пользователь вне группы доступа) — событие без группы
    /// доступа: провайдер выполнит принудительный выход, а не «смену роли».
    /// </summary>
    [Fact]
    public void PollOnce_RoleChangedButNoUsers_ForcedLogout()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        SetupUser(ad, "ivanov", "Manager");
        (RoleResolver resolver, RoleRefreshService service, EventRecorder recorder) = CreateStack(ad);

        resolver.Resolve("ivanov");

        // Пользователь выпал из Users, но остался в ролевой группе
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Manager");
        service.PollOnce();

        RoleResolution change = Assert.Single(recorder.Events);
        Assert.False(change.HasUsersGroup);
        Assert.Equal(AppRoleId.Manager, change.EffectiveRole.Id);
    }

    /// <summary>
    /// Возврат группы Users после принудительного выхода — событие role-changed
    /// (провайдер вернёт пользователя в систему).
    /// </summary>
    [Fact]
    public void PollOnce_UsersGroupRestored_RaisesRoleChanged()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        SetupUser(ad, "ivanov", "Manager");
        (RoleResolver resolver, RoleRefreshService service, EventRecorder recorder) = CreateStack(ad);

        resolver.Resolve("ivanov");

        ad.SetUserGroups("ivanov");
        service.PollOnce();

        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Manager");
        service.PollOnce();

        Assert.Equal(2, recorder.Events.Count);
        // Первое событие — потеря Users (принудительный выход),
        // второе — возврат Users (провайдер вернёт пользователя в систему)
        Assert.False(recorder.Events[0].HasUsersGroup);
        Assert.True(recorder.Events[1].HasUsersGroup);
    }

    /// <summary>
    /// Сбой AD в цикле опроса: пользователи пропускаются, событий нет, служба не падает.
    /// </summary>
    [Fact]
    public void PollOnce_AdUnavailable_NoEventsNoCrash()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        SetupUser(ad, "ivanov", "Manager");
        (RoleResolver resolver, RoleRefreshService service, EventRecorder recorder) = CreateStack(ad);

        resolver.Resolve("ivanov");

        ad.AdUnavailable = true;
        service.PollOnce();

        Assert.Empty(recorder.Events);
    }

    /// <summary>
    /// Пользователи без кэша (не входили и не разрешались) опросом не затрагиваются.
    /// </summary>
    [Fact]
    public void PollOnce_NoTrackedUsers_NoAdCalls()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        (RoleResolver resolver, RoleRefreshService service, EventRecorder recorder) = CreateStack(ad);

        service.PollOnce();

        Assert.Empty(recorder.Events);
        Assert.Equal(0, ad.GetUserGroupNamesCalls);
    }
}
