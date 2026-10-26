/**
 * window.js — общая логика окон WebShelf.
 * Перетаскивание, кнопка закрытия (с пузырём или реальным закрытием),
 * переключатель видимости пароля.
 *
 * API (вызывается из Blazor через JS interop):
 *   WebShelfWindow.init(elementId, options)
 *   WebShelfWindow.dispose(elementId)
 */
(function () {
    "use strict";

    /** @type {Map<string, object>} */
    const instances = new Map();

    /**
     * Инициализирует поведение окна по id корневого элемента.
     * @param {string} elementId - id элемента .ws-window
     * @param {{ canClose?: boolean, closeBubbleText?: string, center?: boolean }} options
     */
    function init(elementId, options) {
        try {
            dispose(elementId);

            const root = document.getElementById(elementId);
            if (!root) {
                console.warn("[WebShelfWindow] Элемент не найден:", elementId);
                return;
            }

            const opts = Object.assign(
                {
                    canClose: false,
                    closeBubbleText: "Это окно не может быть закрыто",
                    center: true
                },
                options || {}
            );

            const titleBar = root.querySelector(".ws-window-titlebar");
            const btnClose = root.querySelector(".ws-window-btn-close");
            const bubble = root.querySelector(".ws-window-close-bubble");

            const state = {
                root,
                titleBar,
                btnClose,
                bubble,
                opts,
                isDragging: false,
                startX: 0,
                startY: 0,
                initialLeft: 0,
                initialTop: 0,
                bubbleTimer: null,
                handlers: {}
            };

            if (opts.center) {
                centerWindow(root);
            }

            // --- Перетаскивание ---
            if (titleBar) {
                state.handlers.onMouseDown = function (e) {
                    if (btnClose && (e.target === btnClose || btnClose.contains(e.target))) {
                        return;
                    }
                    state.isDragging = true;
                    state.startX = e.clientX;
                    state.startY = e.clientY;
                    const rect = root.getBoundingClientRect();
                    state.initialLeft = rect.left;
                    state.initialTop = rect.top;
                    document.body.style.cursor = "grabbing";
                    e.preventDefault();
                };

                state.handlers.onMouseMove = function (e) {
                    if (!state.isDragging) return;
                    root.style.left = state.initialLeft + (e.clientX - state.startX) + "px";
                    root.style.top = state.initialTop + (e.clientY - state.startY) + "px";
                };

                state.handlers.onMouseUp = function () {
                    if (state.isDragging) {
                        state.isDragging = false;
                        document.body.style.cursor = "";
                    }
                };

                state.handlers.onTouchStart = function (e) {
                    if (btnClose && (e.target === btnClose || btnClose.contains(e.target))) {
                        return;
                    }
                    const touch = e.touches[0];
                    state.isDragging = true;
                    state.startX = touch.clientX;
                    state.startY = touch.clientY;
                    const rect = root.getBoundingClientRect();
                    state.initialLeft = rect.left;
                    state.initialTop = rect.top;
                };

                state.handlers.onTouchMove = function (e) {
                    if (!state.isDragging) return;
                    const touch = e.touches[0];
                    root.style.left = state.initialLeft + (touch.clientX - state.startX) + "px";
                    root.style.top = state.initialTop + (touch.clientY - state.startY) + "px";
                };

                state.handlers.onTouchEnd = function () {
                    state.isDragging = false;
                };

                titleBar.addEventListener("mousedown", state.handlers.onMouseDown);
                document.addEventListener("mousemove", state.handlers.onMouseMove);
                document.addEventListener("mouseup", state.handlers.onMouseUp);
                titleBar.addEventListener("touchstart", state.handlers.onTouchStart, { passive: true });
                document.addEventListener("touchmove", state.handlers.onTouchMove, { passive: true });
                document.addEventListener("touchend", state.handlers.onTouchEnd);
            }

            // --- Кнопка закрытия ---
            if (btnClose) {
                state.handlers.onCloseClick = function (e) {
                    e.stopPropagation();
                    e.preventDefault();

                    if (opts.canClose) {
                        root.style.display = "none";
                        root.dispatchEvent(new CustomEvent("wswindow-closed", { bubbles: true }));
                        return;
                    }

                    // Окно нельзя закрыть — показываем пузырь
                    if (bubble) {
                        if (opts.closeBubbleText) {
                            bubble.textContent = opts.closeBubbleText;
                        }
                        bubble.classList.add("ws-visible");
                        if (state.bubbleTimer) {
                            clearTimeout(state.bubbleTimer);
                        }
                        state.bubbleTimer = setTimeout(function () {
                            bubble.classList.remove("ws-visible");
                        }, 2500);
                    }
                };

                btnClose.addEventListener("click", state.handlers.onCloseClick);
            }

            // --- Переключатели пароля внутри окна ---
            const toggles = root.querySelectorAll(".ws-toggle-password");
            state.passwordToggles = [];
            toggles.forEach(function (btn) {
                const handler = function () {
                    const wrapper = btn.closest(".ws-input-wrapper");
                    if (!wrapper) return;
                    const input = wrapper.querySelector("input[type='password'], input[type='text']");
                    if (!input) return;

                    const isPassword = input.type === "password";
                    input.type = isPassword ? "text" : "password";
                    btn.classList.toggle("ws-hidden-eye", !isPassword);
                    btn.setAttribute(
                        "aria-label",
                        isPassword ? "Скрыть пароль" : "Показать пароль"
                    );
                };
                btn.addEventListener("click", handler);
                state.passwordToggles.push({ btn, handler });
            });

            // --- Реакция на resize (перецентрирование, если окно ещё не двигали) ---
            state.handlers.onResize = function () {
                if (!state.moved && opts.center) {
                    centerWindow(root);
                }
            };
            // Помечаем, что пользователь сдвинул окно
            const markMoved = function () {
                state.moved = true;
            };
            state.handlers.markMovedMouse = function () {
                if (state.isDragging) markMoved();
            };
            document.addEventListener("mousemove", state.handlers.markMovedMouse);
            window.addEventListener("resize", state.handlers.onResize);

            instances.set(elementId, state);
        } catch (err) {
            console.error("[WebShelfWindow.init]", err);
        }
    }

    /**
     * Освобождает обработчики окна.
     * @param {string} elementId
     */
    function dispose(elementId) {
        try {
            const state = instances.get(elementId);
            if (!state) return;

            if (state.titleBar && state.handlers.onMouseDown) {
                state.titleBar.removeEventListener("mousedown", state.handlers.onMouseDown);
                state.titleBar.removeEventListener("touchstart", state.handlers.onTouchStart);
            }
            if (state.handlers.onMouseMove) {
                document.removeEventListener("mousemove", state.handlers.onMouseMove);
                document.removeEventListener("mouseup", state.handlers.onMouseUp);
                document.removeEventListener("touchmove", state.handlers.onTouchMove);
                document.removeEventListener("touchend", state.handlers.onTouchEnd);
            }
            if (state.btnClose && state.handlers.onCloseClick) {
                state.btnClose.removeEventListener("click", state.handlers.onCloseClick);
            }
            if (state.passwordToggles) {
                state.passwordToggles.forEach(function (item) {
                    item.btn.removeEventListener("click", item.handler);
                });
            }
            if (state.handlers.onResize) {
                window.removeEventListener("resize", state.handlers.onResize);
            }
            if (state.handlers.markMovedMouse) {
                document.removeEventListener("mousemove", state.handlers.markMovedMouse);
            }
            if (state.bubbleTimer) {
                clearTimeout(state.bubbleTimer);
            }

            instances.delete(elementId);
        } catch (err) {
            console.error("[WebShelfWindow.dispose]", err);
        }
    }

    /**
     * Центрирует окно на экране.
     * @param {HTMLElement} el
     */
    function centerWindow(el) {
        const rect = el.getBoundingClientRect();
        el.style.left = Math.max(0, (window.innerWidth - rect.width) / 2) + "px";
        el.style.top = Math.max(0, (window.innerHeight - rect.height) / 2) + "px";
    }

    /**
     * Добавляет класс фона страницы (для экрана входа).
     * @param {boolean} enabled
     */
    function setPageBackground(enabled) {
        try {
            document.body.classList.toggle("ws-window-page", !!enabled);
        } catch (err) {
            console.error("[WebShelfWindow.setPageBackground]", err);
        }
    }

    window.WebShelfWindow = {
        init: init,
        dispose: dispose,
        setPageBackground: setPageBackground
    };
})();
