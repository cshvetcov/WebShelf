using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты центра уведомлений об изменении роли RoleChangeNotifier: доставка
/// уведомлений подписчикам конкретного пользователя, изоляция пользователей,
/// отмена подписки и устойчивость к исключениям в отдельных обработчиках.
/// </summary>
public class RoleChangeNotifierTests
{
    [Fact]
    public void Notify_SubscribedUser_HandlerReceivesResolution()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();
        List<RoleResolution> received = [];

        using (notifier.Subscribe("ivanov", received.Add))
        {
            RoleResolution resolution = RoleCatalog.ResolveFromRoles([RoleCatalog.Manager]);
            notifier.Notify("ivanov", resolution);

            Assert.Single(received);
            Assert.Equal(resolution, received[0]);
        }
    }

    [Fact]
    public void Notify_TwoHandlersSameUser_BothInvoked()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();
        int firstCalls = 0;
        int secondCalls = 0;

        using (notifier.Subscribe("ivanov", _ => firstCalls++))
        using (notifier.Subscribe("ivanov", _ => secondCalls++))
        {
            notifier.Notify("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Guest]));

            Assert.Equal(1, firstCalls);
            Assert.Equal(1, secondCalls);
        }
    }

    [Fact]
    public void Notify_DifferentUser_HandlerNotInvoked()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();
        int calls = 0;

        using (notifier.Subscribe("ivanov", _ => calls++))
        {
            notifier.Notify("petrov", RoleCatalog.ResolveFromRoles([RoleCatalog.Manager]));

            Assert.Equal(0, calls);
        }
    }

    [Fact]
    public void Notify_AfterDispose_HandlerNotInvoked()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();
        int calls = 0;

        IDisposable subscription = notifier.Subscribe("ivanov", _ => calls++);
        subscription.Dispose();

        notifier.Notify("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Director]));

        Assert.Equal(0, calls);
    }

    [Fact]
    public void Notify_UserNameIsCaseInsensitive()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();
        int calls = 0;

        using (notifier.Subscribe("IVANOV", _ => calls++))
        {
            notifier.Notify("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Guest]));

            Assert.Equal(1, calls);
        }
    }

    [Fact]
    public void Notify_HandlerThrows_OtherHandlersStillInvoked()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();
        int secondCalls = 0;

        using (notifier.Subscribe("ivanov", _ => throw new InvalidOperationException("Сбой обработчика")))
        using (notifier.Subscribe("ivanov", _ => secondCalls++))
        {
            notifier.Notify("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Executor]));

            Assert.Equal(1, secondCalls);
        }
    }

    [Fact]
    public void Subscribe_EmptyUserName_ThrowsArgumentException()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();

        Assert.Throws<ArgumentException>(() => notifier.Subscribe("", _ => { }));
        Assert.Throws<ArgumentException>(() => notifier.Subscribe("  ", _ => { }));
    }

    [Fact]
    public void Subscribe_NullHandler_ThrowsArgumentNullException()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();

        Assert.Throws<ArgumentNullException>(() => notifier.Subscribe("ivanov", null!));
    }

    [Fact]
    public void Notify_EmptyUserOrNullResolution_IsIgnored()
    {
        RoleChangeNotifier notifier = new RoleChangeNotifier();
        int calls = 0;

        using (notifier.Subscribe("ivanov", _ => calls++))
        {
            notifier.Notify("", RoleCatalog.ResolveFromRoles([]));
            notifier.Notify("ivanov", null!);

            Assert.Equal(0, calls);
        }
    }
}
