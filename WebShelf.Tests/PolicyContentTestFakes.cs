using WebShelf.Classes.Service;

namespace WebShelf.Tests;

/// <summary>
/// Подделка источника текстов политик (IPolicyContentSource) для рендер-тестов
/// страниц политик и MainLayout: актуальная, архивная редакции и история —
/// предустановленные значения без обращений к журналу в БД.
/// </summary>
internal sealed class FakePolicyContentSource(
    PolicyVersion? current = null,
    PolicyVersion? archived = null,
    IReadOnlyList<PolicyVersionSummary>? history = null) : IPolicyContentSource
{
    private readonly PolicyVersion? _current = current;
    private readonly PolicyVersion? _archived = archived;
    private readonly IReadOnlyList<PolicyVersionSummary> _history = history ?? [];

    /// <summary>Актуальная редакция для GetCurrentAsync.</summary>
    public Task<PolicyVersion?> GetCurrentAsync(string policyCode, CancellationToken cancellationToken = default)
        => Task.FromResult(_current);

    /// <summary>Архивная редакция для GetVersionAsync (при совпадении номера).</summary>
    public Task<PolicyVersion?> GetVersionAsync(string policyCode, int version, CancellationToken cancellationToken = default)
        => Task.FromResult(_archived is not null && _archived.Version == version ? _archived : null);

    /// <summary>История редакций для GetHistoryAsync.</summary>
    public Task<IReadOnlyList<PolicyVersionSummary>> GetHistoryAsync(string policyCode, CancellationToken cancellationToken = default)
        => Task.FromResult(_history);
}
