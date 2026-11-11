using System.Globalization;
using Npgsql;
using WebShelf.Classes.DB;

namespace WebShelf.Classes.Service;

/// <summary>
/// Запись заявок на регистрацию в базу данных (таблица
/// <c>webshelf.registration_requests</c>) и проверка уникальности контактных
/// данных. Подача выполняется одной транзакцией: повторная проверка пермита
/// с блокировкой строки, вставка заявки (идентификатор УЗ AD — NULL),
/// уменьшение счётчика пермита — только после успешной вставки. Вместе
/// с заявкой фиксируются номера действующих редакций политик обработки
/// персональных данных и cookie (журнал <c>webshelf.policy_versions</c>) и
/// время подачи по UTC с точностью до секунды.
/// </summary>
/// <remarks>
/// <para>
/// Публикуется потребителям через <see cref="IRegistrationRequestService"/>;
/// экземпляр создаётся в Program.Main рядом с Database (готовый singleton,
/// как RegistrationPermitChecker и PolicyContentService).
/// </para>
/// <para>
/// Значение пермита — секретный код: в логи не попадает ни при каких условиях
/// (правило маскировки, Логирование.md). Персональные данные заявки (ФИО,
/// e-mail, телефон) в логи также не пишутся — только служебный идентификатор
/// записанной заявки.
/// </para>
/// </remarks>
internal sealed class RegistrationRequestService(Database database, IPolicyContentSource policies)
    : IRegistrationRequestService
{
    private const string ClassName = "WebShelf.Classes.Service.RegistrationRequestService";

    /// <summary>Подключение к БД приложения.</summary>
    private readonly Database _database = database;

    /// <summary>Журнал версий политик (действующие редакции для фиксации в заявке).</summary>
    private readonly IPolicyContentSource _policies = policies;

    /// <inheritdoc cref="IRegistrationRequestService.CheckContactsAsync" />
    public async Task<RegistrationContactCheckResult> CheckContactsAsync(
        string email,
        string phone,
        CancellationToken cancellationToken = default)
    {
        // E-mail нормализуется так же, как при вставке (нижний регистр):
        // проверка и запись сравнивают контакты одинаково. Исключения не
        // ловятся: вызывающий код (форма) обрабатывает их сам — как при
        // проверке пермита (RegistrationPermitChecker)
        string normalizedEmail = email.Trim().ToLowerInvariant();
        string normalizedPhone = phone.Trim();

        await using NpgsqlConnection connection = await _database.OpenConnectionAsync(cancellationToken);
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT EXISTS(SELECT 1 FROM webshelf.registration_requests WHERE email = @email),
                   EXISTS(SELECT 1 FROM webshelf.registration_requests WHERE phone = @phone)
            """;
        command.Parameters.AddWithValue("email", normalizedEmail);
        command.Parameters.AddWithValue("phone", normalizedPhone);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            // Запрос без строк невозможен (EXISTS всегда возвращает строку) — защитная ветка
            return RegistrationContactCheckResult.None;
        }

        return new RegistrationContactCheckResult(reader.GetBoolean(0), reader.GetBoolean(1));
    }

    /// <inheritdoc cref="IRegistrationRequestService.SubmitAsync" />
    public async Task<RegistrationSubmitResult> SubmitAsync(
        RegistrationApplication application,
        CancellationToken cancellationToken = default)
    {
        const string method = nameof(SubmitAsync);

        try
        {
            // Действующие редакции политик читаются до транзакции — из кэша
            // журнала (обращений к БД нет; журнал не пуст — гарантируется
            // fail-fast при старте, но защита от null остаётся)
            PolicyVersion? personalDataPolicy =
                await _policies.GetCurrentAsync(PolicyCatalog.PersonalDataPolicyCode, cancellationToken);
            PolicyVersion? cookiePolicy =
                await _policies.GetCurrentAsync(PolicyCatalog.CookiePolicyCode, cancellationToken);

            if (personalDataPolicy is null || cookiePolicy is null)
            {
                Log.Error(
                    "Действующая редакция политики недоступна при подаче заявки. PersonalDataPolicy={PersonalDataPolicy}, CookiePolicy={CookiePolicy}. Class={Class}, Method={Method}",
                    personalDataPolicy is not null, cookiePolicy is not null, ClassName, method);
                return RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.ServerError);
            }

            await using NpgsqlConnection connection = await _database.OpenConnectionAsync(cancellationToken);
            await using NpgsqlTransaction transaction =
                await connection.BeginTransactionAsync(cancellationToken);

            // --- Повторная проверка пермита с блокировкой строки ---
            // Между проверкой в окне активации и подачей заявки пермит могли
            // исчерпать (другой кандидат). FOR UPDATE исключает гонку двух
            // одновременных подач по одному пермиту: вторая транзакция ждёт
            // фиксации первой и видит уже уменьшенный счётчик
            int? counter = null;

            await using (NpgsqlCommand permitCommand = connection.CreateCommand())
            {
                permitCommand.Transaction = transaction;
                permitCommand.CommandText =
                    "SELECT counter FROM webshelf.registration_permits WHERE permit = @permit FOR UPDATE";
                permitCommand.Parameters.AddWithValue("permit", application.Permit.Trim());

                object? rawCounter = await permitCommand.ExecuteScalarAsync(cancellationToken);
                counter = rawCounter is null
                    ? null
                    : Convert.ToInt32(rawCounter, CultureInfo.InvariantCulture);
            }

            if (counter is not > 0)
            {
                await transaction.RollbackAsync(cancellationToken);

                Log.Warning(
                    "Подача заявки отклонена: пермит недействителен или исчерпан. Counter={Counter}. Class={Class}, Method={Method}",
                    counter ?? 0, ClassName, method);
                return RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.PermitNotUsable);
            }

            // --- Уникальность контактов: дружелюбная диагностика ---
            // Ограничения UNIQUE(email)/UNIQUE(phone) — окончательная
            // страховка от гонки (нарушение ловится ниже по коду ограничения).
            // Результат читается в локальные переменные ДО отката: читатель
            // обязан закрыться раньше выполнения ROLLBACK (Npgsql запрещает
            // новые команды при открытом DataReader)
            string normalizedEmail = application.Email.Trim().ToLowerInvariant();
            string normalizedPhone = application.Phone.Trim();
            bool emailTaken = false;
            bool phoneTaken = false;

            await using (NpgsqlCommand contactCommand = connection.CreateCommand())
            {
                contactCommand.Transaction = transaction;
                contactCommand.CommandText = """
                    SELECT EXISTS(SELECT 1 FROM webshelf.registration_requests WHERE email = @email),
                           EXISTS(SELECT 1 FROM webshelf.registration_requests WHERE phone = @phone)
                    """;
                contactCommand.Parameters.AddWithValue("email", normalizedEmail);
                contactCommand.Parameters.AddWithValue("phone", normalizedPhone);

                await using NpgsqlDataReader reader =
                    await contactCommand.ExecuteReaderAsync(cancellationToken);

                if (await reader.ReadAsync(cancellationToken))
                {
                    emailTaken = reader.GetBoolean(0);
                    phoneTaken = reader.GetBoolean(1);
                }
            }

            if (emailTaken)
            {
                await transaction.RollbackAsync(cancellationToken);
                Log.Warning(
                    "Подача заявки отклонена: e-mail уже используется поданной заявкой. Class={Class}, Method={Method}",
                    ClassName, method);
                return RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.EmailTaken);
            }

            if (phoneTaken)
            {
                await transaction.RollbackAsync(cancellationToken);
                Log.Warning(
                    "Подача заявки отклонена: телефон уже используется поданной заявкой. Class={Class}, Method={Method}",
                    ClassName, method);
                return RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.PhoneTaken);
            }

            // --- Вставка заявки: идентификатор УЗ AD не заполняется (NULL) ---
            // Заявка ожидает решения администратора: NULL = не принята,
            // заполненный objectGUID = принята. Время подачи — UTC, усечённое
            // до целых секунд (точность до секунды по требованию)
            DateTime utcNow = DateTime.UtcNow;
            DateTime submittedAt = new(
                utcNow.Ticks - utcNow.Ticks % TimeSpan.TicksPerSecond,
                DateTimeKind.Utc);

            long requestId;

            await using (NpgsqlCommand insertCommand = connection.CreateCommand())
            {
                insertCommand.Transaction = transaction;
                insertCommand.CommandText = """
                    INSERT INTO webshelf.registration_requests
                        (last_name, first_name, patronymic, phone, email,
                         personal_data_policy_version, cookie_policy_version, submitted_at)
                    VALUES (@lastName, @firstName, @patronymic, @phone, @email,
                            @personalDataPolicyVersion, @cookiePolicyVersion, @submittedAt)
                    RETURNING id
                    """;
                insertCommand.Parameters.AddWithValue("lastName", application.LastName.Trim());
                insertCommand.Parameters.AddWithValue("firstName", application.FirstName.Trim());
                insertCommand.Parameters.AddWithValue("patronymic", application.Patronymic.Trim());
                insertCommand.Parameters.AddWithValue("phone", normalizedPhone);
                insertCommand.Parameters.AddWithValue("email", normalizedEmail);
                insertCommand.Parameters.AddWithValue("personalDataPolicyVersion", personalDataPolicy.Version);
                insertCommand.Parameters.AddWithValue("cookiePolicyVersion", cookiePolicy.Version);
                insertCommand.Parameters.AddWithValue("submittedAt", submittedAt);

                object? rawId = await insertCommand.ExecuteScalarAsync(cancellationToken);
                requestId = Convert.ToInt64(rawId, CultureInfo.InvariantCulture);
            }

            // --- Списание пермита: только после успешной вставки заявки ---
            // Обе операции в одной транзакции: либо заявка записана и счётчик
            // уменьшен, либо не произошло ничего
            await using (NpgsqlCommand decrementCommand = connection.CreateCommand())
            {
                decrementCommand.Transaction = transaction;
                decrementCommand.CommandText =
                    "UPDATE webshelf.registration_permits SET counter = counter - 1 WHERE permit = @permit";
                decrementCommand.Parameters.AddWithValue("permit", application.Permit.Trim());

                await decrementCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);

            Log.Information(
                "Заявка на регистрацию записана, счётчик пермита уменьшен. RequestId={RequestId}, PersonalDataPolicyVersion={PersonalDataPolicyVersion}, CookiePolicyVersion={CookiePolicyVersion}. Class={Class}, Method={Method}",
                requestId, personalDataPolicy.Version, cookiePolicy.Version, ClassName, method);
            return RegistrationSubmitResult.FromSuccess(requestId);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            // Гонка между предварительной проверкой контактов и вставкой:
            // нарушение UNIQUE поймано самой таблицей. Код ограничения
            // определяет, какой контакт дублируется
            Log.Warning(
                ex,
                "Подача заявки отклонена ограничением уникальности (гонка с параллельной подачей). Constraint={Constraint}. Class={Class}, Method={Method}",
                ex.ConstraintName, ClassName, method);

            return ex.ConstraintName switch
            {
                "registration_requests_email_key" =>
                    RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.EmailTaken),
                "registration_requests_phone_key" =>
                    RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.PhoneTaken),
                _ => RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.ServerError)
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Ошибка подачи заявки на регистрацию. Class={Class}, Method={Method}", ClassName, method);
            return RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.ServerError);
        }
    }
}
