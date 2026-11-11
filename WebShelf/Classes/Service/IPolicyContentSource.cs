namespace WebShelf.Classes.Service;

/// <summary>
/// Источник текстов политик обработки данных для страниц и компонентов:
/// актуальные и архивные редакции из журнала <c>webshelf.policy_versions</c>.
/// Реализация — <see cref="PolicyContentService"/> (singleton из Program.Main);
/// страницы и баннер согласия зависят только от интерфейса, тесты подменяют
/// его фейком (по образцу IAdGroupSource для доменных групп).
/// </summary>
internal interface IPolicyContentSource
{
    /// <summary>
    /// Возвращает актуальную редакцию политики (строка с MAX(version)).
    /// Значение кэшируется сервисом после синхронизации при старте — вызов
    /// в цепочке страницы не обращается к БД. <see langword="null"/> — журнал
    /// не содержит ни одной редакции политики.
    /// </summary>
    /// <param name="policyCode">Код политики (<see cref="PolicyCatalog"/>).</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Актуальная редакция или <see langword="null"/>.</returns>
    /// <exception cref="PolicyContentIntegrityException">
    /// Возникает при несовпадении контрольной суммы читаемой строки журнала.
    /// </exception>
    Task<PolicyVersion?> GetCurrentAsync(string policyCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// Возвращает конкретную редакцию политики (архивная страница
    /// /policy/{code}/{version}). Читается из БД напрямую, без кэша.
    /// <see langword="null"/> — редакция с таким номером не найдена.
    /// </summary>
    /// <param name="policyCode">Код политики (<see cref="PolicyCatalog"/>).</param>
    /// <param name="version">Номер редакции (от 1).</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Редакция или <see langword="null"/>.</returns>
    /// <exception cref="PolicyContentIntegrityException">
    /// Возникает при несовпадении контрольной суммы читаемой строки журнала.
    /// </exception>
    Task<PolicyVersion?> GetVersionAsync(string policyCode, int version, CancellationToken cancellationToken = default);

    /// <summary>
    /// Возвращает сводки всех редакций политики — от актуальной к первой
    /// (блок «История редакций»). Значение кэшируется сервисом после старта.
    /// </summary>
    /// <param name="policyCode">Код политики (<see cref="PolicyCatalog"/>).</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Сводки редакций; пустой список — редакций нет.</returns>
    Task<IReadOnlyList<PolicyVersionSummary>> GetHistoryAsync(string policyCode, CancellationToken cancellationToken = default);
}
