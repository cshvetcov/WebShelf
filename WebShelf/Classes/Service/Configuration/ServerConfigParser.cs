using System.Text;
using Serilog;

namespace WebShelf.Classes.Service.Configuration;

/// <summary>
/// Парсер файла конфигурации Server.conf: превращает содержимое файла
/// в словарь ключ=значение. Ключи сравниваются без учёта регистра
/// (<see cref="StringComparer.OrdinalIgnoreCase"/>); строки-комментарии
/// (первый символ <c>#</c>) и пустые строки игнорируются; при дубликатах
/// ключей побеждает последнее значение.
/// </summary>
/// <remarks>
/// Класс выделен из <c>Data</c> механическим переносом (шаг 5 дорожной
/// карты декомпозиции); правки при переносе — только константа
/// <c>Class=</c> в логах перенесённого кода (принцип 6 дорожной карты)
/// и перенос пути из параметра метода в конструктор (продолжение
/// улучшения У2 шага 0: путь внедряется, как в <see cref="Data"/>).
/// <para>
/// Парсер отвечает только за чтение файла; управляемая перезапись
/// конфигурации (защищённые учётные данные с сохранением комментариев
/// и порядка строк) — зона записи, выносимой шагом 6 дорожной карты.
/// Оркестрация чтения (последовательность инициализации секций, сброс
/// состояния при отказе) остаётся в <see cref="Data.ReadConfigAsync"/>.
/// </para>
/// </remarks>
internal sealed class ServerConfigParser
{
    private const string ClassName = "WebShelf.Classes.Service.Configuration.ServerConfigParser";

    /// <summary>
    /// Полный путь к разбираемому файлу конфигурации Server.conf.
    /// Внедряется конструктором и не меняется после создания парсера.
    /// </summary>
    private string ConfigFile { get; }

    /// <summary>
    /// Создаёт парсер для указанного файла конфигурации.
    /// </summary>
    /// <param name="configFile">
    /// Полный путь к файлу Server.conf. Производственный путь передаёт
    /// <see cref="Data"/> (своё свойство ConfigFile), юнит-тесты — пути
    /// временных файлов.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Путь равен <see langword="null"/>.
    /// </exception>
    internal ServerConfigParser(string configFile)
    {
        ArgumentNullException.ThrowIfNull(configFile);

        ConfigFile = configFile;
    }

    /// <summary>
    /// Читает файл конфигурации в словарь ключ=значение.
    /// Строки-комментарии (начинающиеся с #) и пустые строки игнорируются.
    /// </summary>
    /// <remarks>
    /// Пустой словарь — фактический признак «файл не содержит валидных
    /// записей» для вызывающего <see cref="Data.ReadConfigAsync"/>:
    /// оркестратор трактует его как ошибку чтения конфигурации.
    /// Исключения чтения (в том числе отсутствие файла) журналируются
    /// и пробрасываются вызывающему.
    /// </remarks>
    /// <returns>
    /// Словарь конфигурации; ключи — без учёта регистра. При дубликатах
    /// ключей в файле значением становится последнее прочитанное.
    /// </returns>
    internal Dictionary<string, string> ReadConfigFile()
    {
        const string method = nameof(ReadConfigFile);
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase);

        try
        {
            using StreamReader reader = new(ConfigFile, Encoding.UTF8);

            string? line;
            int lineNumber = 0;

            while ((line = reader.ReadLine()) is not null)
            {
                lineNumber++;
                string trimmed = line.Trim();

                // Пустые строки и комментарии
                if (trimmed.Length == 0 || trimmed[0] == '#')
                    continue;

                int eqIndex = trimmed.IndexOf('=');
                if (eqIndex <= 0)
                {
                    Log.Debug(
                        "Пропущена некорректная строка конфигурации. Line={LineNumber}, Value={Value}. Class={Class}, Method={Method}",
                        lineNumber, trimmed, ClassName, method);
                    continue;
                }

                string key = trimmed[..eqIndex].Trim();
                string value = trimmed[(eqIndex + 1)..].Trim();

                if (key.Length == 0)
                {
                    Log.Debug(
                        "Пропущена строка с пустым ключом. Line={LineNumber}. Class={Class}, Method={Method}",
                        lineNumber, ClassName, method);
                    continue;
                }

                // При дубликатах — последнее значение побеждает
                config[key] = value;
            }

            Log.Debug(
                "Файл конфигурации прочитан. Keys={KeyCount}. Class={Class}, Method={Method}",
                config.Count, ClassName, method);

            return config;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка чтения файла конфигурации. Class={Class}, Method={Method}, Path={Path}",
                ClassName, method, ConfigFile);
            throw;
        }
    }
}
