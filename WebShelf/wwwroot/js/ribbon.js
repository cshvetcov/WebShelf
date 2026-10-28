/**
 * ribbon.js — логика переключения вкладок ленточного меню WebShelf.
 * Функционал кнопок намеренно не реализован (только визуальный каркас).
 *
 * API:
 *   WebShelfRibbon.init(rootElementId)
 *   WebShelfRibbon.dispose(rootElementId)
 *   WebShelfRibbon.setPageBackground(enabled)
 *   WebShelfRibbon.logout()
 */
(function () {
    "use strict";

    /** @type {Map<string, { root: HTMLElement, onTabClick: Function }>} */
    const instances = new Map();

    /**
     * Инициализирует переключение вкладок для корневого элемента ленты.
     * @param {string} rootId - id корневого .ws-ribbon
     */
    function init(rootId) {
        if (!rootId || instances.has(rootId)) {
            return;
        }

        const root = document.getElementById(rootId);
        if (!root) {
            return;
        }

        /**
         * Обработчик клика по вкладке.
         * @param {MouseEvent} e
         */
        function onTabClick(e) {
            const tab = e.target.closest(".ws-ribbon-tab");
            if (!tab || !root.contains(tab)) {
                return;
            }

            const tabId = tab.getAttribute("data-tab");
            if (!tabId) {
                return;
            }

            root.querySelectorAll(".ws-ribbon-tab").forEach(function (t) {
                t.classList.remove("is-active");
                t.setAttribute("aria-selected", "false");
            });
            root.querySelectorAll(".ws-ribbon-panel").forEach(function (p) {
                p.classList.remove("is-active");
            });

            tab.classList.add("is-active");
            tab.setAttribute("aria-selected", "true");

            const panel = root.querySelector('.ws-ribbon-panel[data-panel="' + tabId + '"]');
            if (panel) {
                panel.classList.add("is-active");
            }
        }

        root.addEventListener("click", onTabClick);
        instances.set(rootId, { root: root, onTabClick: onTabClick });
    }

    /**
     * Освобождает обработчики для указанной ленты.
     * @param {string} rootId
     */
    function dispose(rootId) {
        const inst = instances.get(rootId);
        if (!inst) {
            return;
        }
        inst.root.removeEventListener("click", inst.onTabClick);
        instances.delete(rootId);
    }

    /**
     * Добавляет или снимает класс фона страницы для ленты.
     * @param {boolean} enabled
     */
    function setPageBackground(enabled) {
        if (enabled) {
            document.body.classList.add("ws-ribbon-page");
        } else {
            document.body.classList.remove("ws-ribbon-page");
        }
    }

    /**
     * Полный выход: браузерный переход на /account/logout.
     * Не использует Blazor navigation — браузер сам следует 302 на /entry.
     */
    function logout() {
        window.location.assign("/account/logout");
    }

    window.WebShelfRibbon = {
        init: init,
        dispose: dispose,
        setPageBackground: setPageBackground,
        logout: logout
    };
})();
