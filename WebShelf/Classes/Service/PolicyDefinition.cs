namespace WebShelf.Classes.Service;

/// <summary>
/// Описание известной системе политики обработки данных: код журнала редакций,
/// файл поставки с текстом и заголовки страницы. Экземпляры описаний — в
/// <see cref="PolicyCatalog"/>; строки <c>webshelf.policy_versions.policy</c>
/// обязаны совпадать со значениями <see cref="Code"/> (домен закреплён
/// CHECK-ограничением каркаса БД).
/// </summary>
/// <param name="Code">
/// Код политики в журнале редакций (столбец <c>webshelf.policy_versions.policy</c>).
/// </param>
/// <param name="FileName">
/// Имя файла текста политики в поставке — каталог <c>Content/Policies</c>.
/// </param>
/// <param name="DocumentTitle">Заголовок документа (h1 страницы политики).</param>
/// <param name="TitlebarText">Текст заголовка окна (titlebar) страницы политики.</param>
/// <remarks>
/// Record объявлен public (при общем internal-стиле проекта): объект передаётся
/// в публичный параметр Razor-компонента PolicyDocument — публичные параметры
/// компонента не могут принимать internal-типы.
/// </remarks>
public sealed record PolicyDefinition(string Code, string FileName, string DocumentTitle, string TitlebarText);
