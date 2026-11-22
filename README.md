# TunBridge

**TunBridge** — лёгкое нативное приложение для Windows (Win32 / GDI+) и Linux (Qt 6 Widgets), которое направляет трафик через удалённый прокси-сервер. Поддерживаются два режима работы:

- **Системный прокси** — локальный HTTP-прокси, который прописывается в настройки Windows и перенаправляет трафик в вышестоящий SOCKS5- или HTTP-прокси.
- **Весь трафик (TUN)** — создание виртуального сетевого адаптера `TunBridge` через `tun2socks` + `wintun`, с изменением системных маршрутов и DNS.

Приложение умеет автоматически искать прокси в локальной сети, проверять авторизацию и определять протокол, измерять задержку и страну выхода, управлять программой обхода DPI (Zapret / winws), сворачиваться в трей и запускаться вместе с Windows.

## Возможности

- Два режима подключения: системный прокси и TUN.
- SOCKS5 (с авторизацией) и HTTP CONNECT, автоматическое определение протокола.
- Локальный HTTP-мост с поддержкой `CONNECT` и обычных HTTP-запросов.
- Поиск прокси в сети по заданному порту.
- Проверка связи: пинг, код страны, состояние авторизации.
- Счётчик трафика и статус подключения в реальном времени.
- Управление Zapret: остановка и автоматическое восстановление после выключения TUN.
- Автозапуск в трей, запуск свёрнутым, работа в системном трее.
- Загрузка `wintun.dll` и `tun2socks.exe` с официальных источников с проверкой SHA-256 и подписи.
- Тёмная палитра Windows 11, DPI-масштабирование, собственные обработчики отрисовки контролов.

## Загрузка

Готовые исполняемые файлы доступны в разделе [Releases](https://github.com/qwisixDEV/TunBridge/releases).

## Структура проекта

```
TunBridge/
├── CMakeLists.txt              # Конфигурация сборки исполняемого файла TunBridge
├── README.md
├── .gitignore
├── include/
│   └── tunbridge/
│       ├── common.hpp          # Общие константы, состояние, типы и утилиты
│       ├── config.hpp          # Конфигурация и системный прокси
│       ├── system.hpp          # Системные операции, службы, Zapret
│       ├── net.hpp             # SOCKS5 / HTTP CONNECT и локальный мост
│       ├── tun.hpp             # TUN-движок и загрузка компонентов
│       ├── probe.hpp           # Сканер сети и проверка связи
│       ├── app.hpp             # Управление режимами и экранами
│       └── ui.hpp              # Отрисовка, контролы, окно и трей
└── src/
    ├── main.cpp                # Точка входа WinMain
    ├── state.cpp               # Определения общего состояния
    ├── util.cpp                # Безопасные копирования, SHA-256, адаптеры
    ├── config.cpp              # Сохранение/загрузка конфигурации, автозапуск
    ├── system.cpp              # Процессы, службы, маршруты, Zapret
    ├── net.cpp                 # Сетевой движок локального прокси
    ├── tun.cpp                 # Запуск TUN, маршруты, загрузка wintun/tun2socks
    ├── probe.cpp               # Фоновый сканер и тест подключения
    ├── app.cpp                 # Старт/остановка режимов, переключение экранов
    └── ui.cpp                  # Отрисовка интерфейса и обработка сообщений
```

## Требования для сборки

- Windows 10 или Windows 11.
- CMake 3.20 или новее.
- Один из компиляторов:
  - Visual Studio 2019/2022 (MSVC, рабочая нагрузка «Разработка классических приложений на C++»);
  - MinGW-w64 GCC (например, из MSYS2, пакет `mingw-w64-x86_64-gcc`);
  - Clang для Windows / MSYS2 Clang.
- Все зависимости — системные библиотеки Windows (`ws2_32`, `iphlpapi`, `wininet`, `comctl32`, `gdiplus`, `shell32`, `advapi32`, `crypt32`, `user32`, `gdi32`, `ole32`). Внешние библиотеки не требуются.
- Исполняемый файл собирается со статической линковкой рантайма (`/MT` в MSVC или `-static`, `-static-libgcc`, `-static-libstdc++` в MinGW-w64) и со strip (`-s`), поэтому для запуска не нужны DLL MSYS2/MinGW или Visual C++ Redistributable.

## Сборка

### Visual Studio / MSVC

Из «Developer PowerShell for VS»:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Готовый файл: `build\Release\TunBridge.exe`.

### MinGW-w64 (MSYS2)

Из терминала MSYS2 MINGW64:

```bash
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Готовый файл: `build\TunBridge.exe`.

### Clang (MSYS2)

```bash
cmake -S . -B build-clang -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_COMPILER=clang++
cmake --build build-clang --parallel
```

## Запуск

Запустите `TunBridge.exe`. Настройки открываются кнопкой с шестерёнкой.

- Для режима **Системный прокси** достаточно указать IP/порт вышестоящего прокси и при необходимости логин/пароль.
- Для режима **TUN** требуются права администратора: приложение создаёт адаптер, меняет маршруты и DNS. `wintun.dll` и `tun2socks.exe` можно скачать прямо из окна настроек — файлы сохраняются рядом с исполняемым файлом и проверяются по SHA-256.
- Если обнаружен запущенный Zapret / winws, TunBridge предложит остановить его на время работы TUN и при включённой опции восстановит после отключения.

### Параметры командной строки

| Параметр | Назначение |
|---|---|
| `--minimized` | Запустить свёрнутым в трей |
| `--autostart-tun` | Запустить сразу в режиме TUN |
| `--download-tun` | Скачать и проверить компоненты TUN |
| `--stop-zapret` | Остановить службы и процессы Zapret / WinDivert |

Повторный запуск без параметров активирует уже открытое окно приложения.

## Конфигурация

Настройки хранятся в реестре пользователя:

```
HKEY_CURRENT_USER\Software\TunBridge
```

Там сохраняются IP и порт прокси, логин, пароль, локальный порт, режим, параметры трея и автовосстановления Zapret. Автозапуск регистрируется в стандартном разделе `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` под именем `TunBridge`.

В режиме системного прокси TunBridge изменяет параметры `ProxyEnable` / `ProxyServer` в `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` и восстанавливает их при отключении.

## Примечания

- Приложение не содержит встроенных сторонних библиотек: `wintun.dll` и `tun2socks.exe` загружаются отдельно с официальных релизов и проверяются по контрольным суммам.
- Изменение маршрутов и создание TUN-адаптера выполняются только с правами администратора.
- Для работы TUN может потребоваться разрешить приложение в брандмауэре Windows.

## Linux (Arch Linux / CachyOS)

Linux-порт сохраняет всю функциональность Windows-версии, но разделяет права: GUI **никогда** не запускается от root. Привилегированные операции (TUN, маршруты, DNS, Zapret) выполняет отдельный `tunbridge-helper` через `pkexec` с Polkit-политикой `org.tunbridge.helper.policy`.

### Зависимости

```bash
sudo pacman -S --needed base-devel cmake ninja gcc qt6-base curl openssl zlib \
               iproute2 polkit systemd
```

### Сборка и установка

```bash
git clone https://github.com/qwisixDEV/TunBridge.git
cd TunBridge
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Через PKGBUILD (Arch / CachyOS):

```bash
cd packaging/arch
makepkg -si
```

### Что установится

| Файл | Назначение |
|---|---|
| `/usr/bin/tunbridge` | GUI от обычного пользователя (Qt6 Widgets, без QML/WebEngine) |
| `/usr/bin/tunbridge-helper` | привилегированный хелпер, запускается только через `pkexec` |
| `/usr/share/applications/tunbridge.desktop` | запись в меню приложений |
| `/usr/share/polkit-1/actions/org.tunbridge.helper.policy` | политика Polkit для TUN/маршрутов/DNS/Zapret |

### Поведение в Linux

- **Системный прокси:** KDE Plasma 6 — `kwriteconfig6` + `kioslaverc` и уведомление KIO через D-Bus; GNOME / Cinnamon / Budgie — `gsettings org.gnome.system.proxy`; Hyprland / Sway / i3 — `~/.config/tunbridge/proxy.env` и `systemctl --user set-environment`. Исходные значения сохраняются и восстанавливаются при отключении.
- **Весь трафик (TUN):** `/dev/net/tun` + `tun2socks` без `wintun.dll`. Хелпер поднимает `tunbridge0` (10.251.251.1/24, MTU 1420), добавляет маршрут к вышестоящему прокси через исходный шлюз, `/1`-маршруты, блокирует утечки IPv6 и настраивает DNS через `resolvectl` (или бэкапит `/etc/resolv.conf`). Если GUI умер или отключился, хелпер по закрытому каналу мгновенно откатывает всё состояние.
- **Zapret:** обнаруживаются активные юниты `zapret*` и процессы `nfqws`/`tpws`; включение TUN предлагает остановить их, опция «Автовозврат Zapret» возвращает исходное состояние.
- **Ресурсы:** один `epoll`-поток для локального HTTP-моста, фиксированные буферы, `TCP_NODELAY`/`MSG_NOSIGNAL`, никаких фоновых опросов. Таймер статистики и пинг запускаются только при открытом окне; в трее CPU ≈ 0%.
- **Конфиг:** `$XDG_CONFIG_HOME/tunbridge/config.ini` (права `0600`), автозапуск — `$XDG_CONFIG_HOME/autostart/tunbridge.desktop`.
- **Загрузка tun2socks:** `$XDG_DATA_HOME/tunbridge/bin/tun2socks`, официальный релиз `xjasonlyu/tun2socks` под `linux-amd64`/`linux-arm64`, обязательная проверка SHA-256 из GitHub API.

### Ручная проверка на живой системе

1. `pkexec /usr/bin/tunbridge-helper --socket /tmp/test.sock` — должен запросить пароль и не запускать фоновые циклы.
2. Системный прокси: подключить/отключить в KDE, GNOME и Hyprland; проверить, что настройки вернулись в исходное состояние.
3. TUN: подключиться, проверить `ip addr show tunbridge0`, `ip route`, `resolvectl status`, отсутствие IPv6-утечек на `ipleak.net`.
4. Убить GUI (`kill -9`) при активном TUN — хелпер должен снять интерфейс, маршруты и DNS.
5. Zapret: запустить юнит `zapret`, включить TUN с автовозвратом, отключиться — юнит должен подняться снова.
6. Измерить потребление: `pidstat -p $(pgrep -f '/usr/bin/tunbridge$') 1` в трее должно показывать ~0% CPU.

## Лицензия

Проект распространяется под лицензией [MIT](LICENSE). Подробности в файле `LICENSE`.
