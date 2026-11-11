namespace WebShelf.Classes.Service;

/// <summary>
/// Нарушение целостности редакции политики: контрольная сумма SHA-256 текста
/// в журнале <c>webshelf.policy_versions</c> не совпадает со значением
/// <c>content_sha256</c> строки — текст изменён вне журнала. Такая редакция
/// не может показываться как юридический документ: страница политики
/// прерывает рендер (fail-fast), исключение фиксируется в лог.
/// </summary>
internal sealed class PolicyContentIntegrityException(string message) : Exception(message);
