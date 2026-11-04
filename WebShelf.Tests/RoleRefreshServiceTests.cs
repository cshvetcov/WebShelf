using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты фонового опроса ролевых групп (вариант 2): PollOnce вызывается напрямую,
/// без задержек ExecuteAsync. Проверяются рассылка событий смены роли,
/// принудительный выход при потере группы Users и поведение при сбое AD.
/// </summary>
public class RoleRefreshServiceTests
{
    /// <summary>Фиксированный InstanceIdShort, как в подмене источника групп.</summary>
    private const string Id = RoleTestFakes.InstanceShort;

    /// <summary>Собирает события нотификатора для проверок.</summary>
    private sealed class EventRecorder
    {
        public List<RoleChange> Events { get; } = [];

        public void OnRoleChanged(object? sender, RoleChange change)
        {
            Events.Add(change);
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
        notifier.RoleChanged += recorder.OnRoleChanged;

        RoleRefreshService service = new(resolver, notifier, options);

        return (resolver, service, recorder);
    }

    /// <summary>
    /// Смена роли между опросами — событие role-changed с новой ролью.
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

        RoleChange change = Assert.Single(recorder.Events);
        Assert.Equal("ivanov", change.Username);
        Assert.Equal(RoleChange.ReasonRoleChanged, change.Reason);
        Assert.NotNull(change.Resolution);
        Assert.Same(AppRoleCatalog.GIP, change.Resolution.Role);
        Assert.True(change.Resolution.HasUsersGroup);
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
    /// Потеря группы Users — принудительный выход: событие users-group-lost
    /// с null-резолюцией; повторный цикл не дублирует событие.
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

        RoleChange change = Assert.Single(recorder.Events);
        Assert.Equal(RoleChange.ReasonUsersGroupLost, change.Reason);
        Assert.Null(change.Resolution);
    }

    /// <summary>
    /// Смена роли без Users (пользователь вне группы доступа) — принудительный выход,
    /// а не «смена роли на Гостя».
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

        RoleChange change = Assert.Single(recorder.Events);
        Assert.Equal(RoleChange.ReasonUsersGroupLost, change.Reason);
        Assert.Null(change.Resolution);
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
        Assert.Equal(RoleChange.ReasonUsersGroupLost, recorder.Events[0].Reason);
        Assert.Equal(RoleChange.ReasonRoleChanged, recorder.Events[1].Reason);
        Assert.NotNull(recorder.Events[1].Resolution);
        Assert.True(recorder.Events[1].Resolution.HasUsersGroup);
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
