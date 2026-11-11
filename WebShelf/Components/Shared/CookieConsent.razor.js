/**
 * CookieConsent.razor.js — хранение решения пользователя о согласии
 * на обработку файлов cookie (JS-isolation, ES-модуль).
 *
 * Решение хранится в localStorage браузера (ключ ws-cookie-consent) и
 * не передаётся на сервер. Запись не является cookie: при очистке данных
 * сайта в браузере решение удаляется вместе с ними — это же способ отзыва
 * согласия (баннер спросит решение заново).
 *
 * Согласие привязано к редакции cookie-политики (журнал редакций в БД,
 * webshelf.policy_versions): в запись сохраняется номер редакции
 * (policyVersion), на момент которой дано согласие. После публикации
 * новой редакции политики сохранённое решение считается отсутствующим,
 * и баннер повторно запрашивает согласие (информированность согласия,
 * ст. 9 152-ФЗ).
 *
 * API (вызывается из Blazor через JS interop):
 *   hasDecision(policyVersion) — есть ли действующее сохранённое решение
 *     для указанной редакции cookie-политики (boolean): записи с другой
 *     редакцией (включая отсутствующую у старых записей) не учитываются
 *   saveDecision(accepted, policyVersion) — записать решение (boolean)
 *   getDecision() — прочитать запись: null | { accepted, date, version,
 *     policyVersion }; проверяется только версия формата записи
 *   resetDecision() — удалить решение (принудительный повторный запрос)
 */

/** Ключ localStorage. */
const STORAGE_KEY = "ws-cookie-consent";

/**
 * Версия формата записи согласия (не редакция политики!). Увеличивается
 * только при изменении состава полей записи. Редакция cookie-политики —
 * отдельное поле policyVersion, передаваемое при каждом вызове.
 */
const CONSENT_VERSION = 1;

/**
 * Читает сырую запись из localStorage; при недоступном хранилище
 * (запрещены cookie/сайт-данные, приватный режим с ограничениями)
 * возвращает null без исключения.
 * @returns {string|null} Сырая запись или null.
 */
function readRaw() {
    try {
        return localStorage.getItem(STORAGE_KEY);
    } catch (e) {
        // Хранилище недоступно — решения нет
        return null;
    }
}

/**
 * Записывает сырую запись в localStorage; при недоступном хранилище
 * молча пропускает запись (баннер в этом сеансе больше не показывается).
 * @param {string} value Строка для записи.
 */
function writeRaw(value) {
    try {
        localStorage.setItem(STORAGE_KEY, value);
    } catch (e) {
        // Хранилище недоступно — решение сохраняется только в памяти сеанса
    }
}

/**
 * Проверяет наличие действующего сохранённого решения о согласии
 * применительно к указанной редакции cookie-политики. Делегирует
 * getDecision(): записи с несовпадающей версией формата, повреждённые,
 * устаревшие (без поля policyVersion) и данные до другой редакции
 * политики решением не считаются — баннер запросит согласие заново,
 * как описано в WebShelfDocs/Решения в проекте/Версионирование политик.md.
 * @param {number} policyVersion Номер актуальной редакции cookie-политики.
 * @returns {boolean} true, если действующее решение сохранено.
 */
export function hasDecision(policyVersion) {
    const decision = getDecision();
    return decision !== null && decision.policyVersion === policyVersion;
}

/**
 * Записывает решение пользователя о согласии с привязкой к редакции
 * cookie-политики, на момент которой оно дано.
 * @param {boolean} accepted - true — согласие дано; false — отклонено.
 * @param {number} policyVersion Номер актуальной редакции cookie-политики.
 */
export function saveDecision(accepted, policyVersion) {
    writeRaw(JSON.stringify({
        version: CONSENT_VERSION,
        accepted: accepted === true,
        date: new Date().toISOString(),
        policyVersion: policyVersion
    }));
}

/**
 * Возвращает сохранённое решение (запись формата текущей версии).
 * @returns {Object|null} { accepted: boolean, date: string, version: number,
 *   policyVersion: number|null } либо null, если записи нет / запись
 *   повреждена / версия формата не совпадает. Привязка к редакции политики
 *   проверяется в hasDecision: записи без policyVersion (старый формат)
 *   возвращаются здесь, но решением для новой редакции не являются.
 */
export function getDecision() {
    const raw = readRaw();
    if (raw === null) {
        return null;
    }

    try {
        const decision = JSON.parse(raw);
        if (decision === null || typeof decision !== "object" || decision.version !== CONSENT_VERSION) {
            return null;
        }

        return decision;
    } catch (e) {
        // Повреждённая запись — решения нет
        return null;
    }
}

/**
 * Удаляет сохранённое решение (отзыв согласия): при следующем входе
 * баннер запросит решение заново.
 */
export function resetDecision() {
    try {
        localStorage.removeItem(STORAGE_KEY);
    } catch (e) {
        // Хранилище недоступно — удалять нечего
    }
}
