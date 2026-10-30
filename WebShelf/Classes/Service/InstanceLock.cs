using System.Security.Principal;
using Serilog;

namespace WebShelf.Classes.Service;

/// <summary>
/// Обеспечивает единственный экземпляр WebShelf под одной учётной записью Windows.
/// Использует именованный Mutex в пространстве Global.
/// </summary>
internal static class InstanceLock
{
    private const string ClassName = "WebShelf.Classes.Service.InstanceLock";

    private static Mutex? _mutex;

    /// <summary>
    /// Пытается захватить глобальный мьютекс для текущей учётной записи.
    /// При неудаче (уже запущен другой экземпляр) возвращает <see langword="false"/>.
    /// </summary>
    /// <returns>
    /// <see langword="true"/>, если мьютекс захвачен; иначе <see langword="false"/>.
    /// </returns>
    internal static bool TryAcquire()
    {
        const string method = nameof(TryAcquire);

        try
        {
            string account = WindowsIdentity.GetCurrent()?.User?.Value
                             ?? Environment.UserName
                             ?? "unknown";

            // Один экземпляр на учётную запись (SID), независимо от InstanceId.
            string mutexName = $@"Global\WebShelf_{account}";

            _mutex = new Mutex(initiallyOwned: true, name: mutexName, createdNew: out bool createdNew);

            if (!createdNew)
            {
                Log.Fatal(
                    "Обнаружен уже запущенный экземпляр WebShelf под этой учётной записью. Запуск прерван. Class={Class}, Method={Method}",
                    ClassName, method);

                try { _mutex.Dispose(); } catch { /* ignore */ }
                _mutex = null;
                return false;
            }

            Log.Information(
                "Мьютекс экземпляра захвачен. Class={Class}, Method={Method}",
                ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex,
                "Не удалось захватить мьютекс экземпляра. Class={Class}, Method={Method}",
                ClassName, method);
            return false;
        }
    }

    /// <summary>
    /// Освобождает мьютекс (вызывается при завершении процесса).
    /// </summary>
    internal static void Release()
    {
        const string method = nameof(Release);

        try
        {
            if (_mutex is not null)
            {
                try
                {
                    _mutex.ReleaseMutex();
                }
                catch (ApplicationException)
                {
                    // Мьютекс уже не принадлежит текущему потоку — нормально при аварийном выходе.
                }

                _mutex.Dispose();
                _mutex = null;

                Log.Debug(
                    "Мьютекс экземпляра освобождён. Class={Class}, Method={Method}",
                    ClassName, method);
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex,
                "Ошибка при освобождении мьютекса. Class={Class}, Method={Method}",
                ClassName, method);
        }
    }
}
