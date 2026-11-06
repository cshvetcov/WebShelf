namespace WebShelf.Classes.DB;

/// <summary>
/// Ошибка файла-каркаса: файл отсутствует, не читается, содержит неподдерживаемые
/// операторы или не разбирается. Старт приложения при этой ошибке прерывается (fail-fast).
/// </summary>
internal sealed class SchemaSkeletonException : Exception
{
    /// <summary>Инициализирует исключение с описанием.</summary>
    internal SchemaSkeletonException(string message) : base(message)
    {
    }

    /// <summary>Инициализирует исключение с описанием и вложенной причиной.</summary>
    internal SchemaSkeletonException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Ошибка создания дампа БД. Изменения структуры после этой ошибки не выполняются —
/// жёсткое правило: сначала полностью успешный дамп, потом изменения.
/// </summary>
internal sealed class DbDumpException : Exception
{
    /// <summary>Инициализирует исключение с описанием.</summary>
    internal DbDumpException(string message) : base(message)
    {
    }

    /// <summary>Инициализирует исключение с описанием и вложенной причиной.</summary>
    internal DbDumpException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
