#!/bin/bash

# Скрипт для настройки планировщика заданий (cron)
# для мониторинга новых устройств ввода каждую минуту

echo "================================================================"
echo "   НАСТРОЙКА ПЛАНИРОВЩИКА ЗАДАНИЙ ДЛЯ МОНИТОРИНГА УСТРОЙСТВ"
echo "   ОПРОС КАЖДУЮ МИНУТУ"
echo "================================================================"
echo

# Конфигурация
SCRIPT_DIR="/opt/scripts"
SCRIPT_NAME="input_device_monitor_cron.sh"
FULL_SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"
LOG_FILE="/var/log/input_devices_cron.log"
STATE_FILE="/var/tmp/known_input_devices.txt"
BACKUP_DIR="/var/tmp/input_devices_backup"

# Проверка запуска от root
if [ "$EUID" -ne 0 ]; then 
    echo "Пожалуйста, запустите скрипт с sudo: sudo $0"
    exit 1
fi

# Шаг 1: Создание директории для скриптов
echo "Шаг 1: Создание директории $SCRIPT_DIR..."
mkdir -p "$SCRIPT_DIR"
if [ $? -eq 0 ]; then
    echo "  ✓ Директория создана"
else
    echo "  ✗ Ошибка создания директории"
    exit 1
fi

# Шаг 2: Создание скрипта мониторинга для cron
echo "Шаг 2: Создание скрипта мониторинга..."

cat > /tmp/$SCRIPT_NAME << 'EOF'
#!/bin/bash

# ========================================================
# input_device_monitor_cron.sh - Мониторинг новых устройств ввода
# Запускается по cron каждую минуту
# ========================================================

# Конфигурация
LOG_FILE="/var/log/input_devices_cron.log"
STATE_FILE="/var/tmp/known_input_devices.txt"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
HOSTNAME=$(hostname)

# Функция логирования
log_message() {
    local message="$1"
    echo "$TIMESTAMP - $HOSTNAME - $message" >> "$LOG_FILE"
    
    # Также выводим в системный лог для отладки
    logger "input-monitor: $message"
}

# Функция для создания уникального идентификатора устройства
get_device_id() {
    local device_block="$1"
    
    # Создаем уникальный идентификатор на основе I и N строк
    local i_line=$(echo "$device_block" | grep "^I:" | head -1)
    local n_line=$(echo "$device_block" | grep "^N:" | head -1)
    
    # Извлекаем bus, vendor, product из I строки
    local bus=$(echo "$i_line" | grep -o "Bus=[0-9a-fA-F]\+" | cut -d= -f2)
    local vendor=$(echo "$i_line" | grep -o "Vendor=[0-9a-fA-F]\+" | cut -d= -f2)
    local product=$(echo "$i_line" | grep -o "Product=[0-9a-fA-F]\+" | cut -d= -f2)
    
    # Извлекаем имя из N строки
    local name=$(echo "$n_line" | grep -o 'Name="[^"]*"' | cut -d'"' -f2 | tr ' ' '_')
    
    # Если не удалось извлечь, используем заглушку
    [ -z "$bus" ] && bus="0000"
    [ -z "$vendor" ] && vendor="0000"
    [ -z "$product" ] && product="0000"
    [ -z "$name" ] && name="unknown"
    
    echo "${bus}:${vendor}:${product}:${name}"
}

# Функция для извлечения имени устройства
get_device_name() {
    local device_block="$1"
    local n_line=$(echo "$device_block" | grep "^N:" | head -1)
    echo "$n_line" | grep -o 'Name="[^"]*"' | cut -d'"' -f2
}

# Функция для извлечения обработчиков устройства
get_device_handlers() {
    local device_block="$1"
    local h_line=$(echo "$device_block" | grep "^H:" | head -1)
    echo "$h_line" | cut -c4-
}

# Функция для определения типа устройства
get_device_type() {
    local handlers="$1"
    
    if [[ $handlers == *"kbd"* ]]; then
        echo "Клавиатура"
    elif [[ $handlers == *"mouse"* ]]; then
        echo "Мышь"
    elif [[ $handlers == *"js"* ]]; then
        echo "Джойстик"
    elif [[ $handlers == *"event"* ]]; then
        echo "Устройство событий"
    else
        echo "Неизвестно"
    fi
}

# Функция для проверки новых устройств
check_new_devices() {
    local new_devices=0
    
    # Проверяем существование файла devices
    if [ ! -f "/proc/bus/input/devices" ]; then
        log_message "ОШИБКА: Файл /proc/bus/input/devices не найден"
        return 1
    fi
    
    # Создаем временные файлы
    local temp_devices=$(mktemp)
    local temp_ids=$(mktemp)
    
    # Получаем текущие устройства
    local current_count=0
    local current_device=""
    
    while IFS= read -r line; do
        if [[ $line == I:* ]]; then
            if [ -n "$current_device" ]; then
                current_count=$((current_count + 1))
                echo "$current_device" >> "$temp_devices"
                echo "$(get_device_id "$current_device")" >> "$temp_ids"
            fi
            current_device="$line\n"
        elif [[ $line =~ ^[NPHB]: ]] && [ -n "$current_device" ]; then
            current_device="${current_device}${line}\n"
        fi
    done < "/proc/bus/input/devices"
    
    # Добавляем последнее устройство
    if [ -n "$current_device" ]; then
        current_count=$((current_count + 1))
        echo "$current_device" >> "$temp_devices"
        echo "$(get_device_id "$current_device")" >> "$temp_ids"
    fi
    
    log_message "Текущее количество устройств: $current_count"
    
    # Если файл состояния не существует, создаем его
    if [ ! -f "$STATE_FILE" ]; then
        cat "$temp_ids" > "$STATE_FILE"
        log_message "Инициализация списка устройств. Всего устройств: $current_count"
        rm -f "$temp_devices" "$temp_ids"
        return 0
    fi
    
    # Создаем временный файл для новых ID
    local new_ids_file=$(mktemp)
    
    # Ищем новые устройства
    local line_num=0
    while IFS= read -r current_id; do
        line_num=$((line_num + 1))
        
        # Проверяем, есть ли текущий ID в файле состояния
        if ! grep -q "^$current_id$" "$STATE_FILE"; then
            # Новое устройство найдено
            new_devices=$((new_devices + 1))
            echo "$current_id" >> "$new_ids_file"
            
            # Получаем информацию об устройстве
            local device_block=$(sed -n "${line_num}p" "$temp_devices")
            local name=$(get_device_name "$device_block")
            local handlers=$(get_device_handlers "$device_block")
            local dev_type=$(get_device_type "$handlers")
            
            # Логируем новое устройство
            log_message ">>> НОВОЕ УСТРОЙСТВО ОБНАРУЖЕНО <<<"
            log_message "  ID: $current_id"
            log_message "  Имя: $name"
            log_message "  Тип: $dev_type"
            log_message "  Обработчики: $handlers"
            
            # Отправляем уведомление в системный лог
            logger "input-monitor: Новое устройство - $name ($dev_type)"
        fi
    done < "$temp_ids"
    
    # Добавляем новые ID в файл состояния
    if [ $new_devices -gt 0 ]; then
        cat "$new_ids_file" >> "$STATE_FILE"
        sort -u "$STATE_FILE" -o "$STATE_FILE"
        log_message "ИТОГ: Добавлено новых устройств: $new_devices"
        
        # Создаем резервную копию с датой
        local backup_file="$BACKUP_DIR/state_$(date +%Y%m%d_%H%M%S).txt"
        mkdir -p "$BACKUP_DIR"
        cp "$STATE_FILE" "$backup_file"
        log_message "Резервная копия состояния сохранена: $backup_file"
    fi
    
    # Очищаем временные файлы
    rm -f "$temp_devices" "$temp_ids" "$new_ids_file"
    
    return 0
}

# Функция для проверки работоспособности
health_check() {
    # Проверяем доступность /proc/bus/input/
    if [ ! -d "/proc/bus/input" ]; then
        log_message "КРИТИЧЕСКАЯ ОШИБКА: Директория /proc/bus/input не существует"
        return 1
    fi
    
    # Проверяем права на чтение
    if [ ! -r "/proc/bus/input/devices" ]; then
        log_message "ОШИБКА: Нет прав на чтение /proc/bus/input/devices"
        return 1
    fi
    
    # Проверяем размер лог-файла (ротация при необходимости)
    if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE") -gt 10485760 ]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        log_message "Лог-файл превысил 10MB, выполнена ротация"
    fi
    
    return 0
}

# Основная функция
main() {
    # Проверка работоспособности
    health_check
    if [ $? -ne 0 ]; then
        exit 1
    fi
    
    log_message "=== НАЧАЛО ЦИКЛА МОНИТОРИНГА (каждую минуту) ==="
    
    # Проверяем новые устройства
    check_new_devices
    
    log_message "=== ЗАВЕРШЕНИЕ ЦИКЛА МОНИТОРИНГА ==="
    
    exit 0
}

# Запуск основной функции
main
EOF

# Проверка синтаксиса созданного скрипта
echo "  Проверка синтаксиса скрипта..."
bash -n /tmp/$SCRIPT_NAME
if [ $? -eq 0 ]; then
    echo "  ✓ Синтаксис корректен"
else
    echo "  ✗ Ошибка синтаксиса в скрипте"
    exit 1
fi

# Копирование скрипта
echo "Шаг 3: Установка скрипта в $FULL_SCRIPT_PATH..."
cp /tmp/$SCRIPT_NAME "$FULL_SCRIPT_PATH"
chmod 755 "$FULL_SCRIPT_PATH"
rm /tmp/$SCRIPT_NAME
echo "  ✓ Скрипт установлен"

# Шаг 4: Создание лог-файла
echo "Шаг 4: Настройка лог-файла $LOG_FILE..."
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"
echo "  ✓ Лог-файл создан: $(ls -la $LOG_FILE)"

# Шаг 5: Создание директории для резервных копий
echo "Шаг 5: Создание директории для резервных копий..."
mkdir -p "$BACKUP_DIR"
chmod 755 "$BACKUP_DIR"
echo "  ✓ Директория создана: $BACKUP_DIR"

# Шаг 6: Инициализация файла состояния
echo "Шаг 6: Инициализация файла состояния $STATE_FILE..."
if [ -f "/proc/bus/input/devices" ]; then
    # Создаем временный скрипт для инициализации
    cat > /tmp/init_state.sh << 'EOF'
#!/bin/bash
STATE_FILE="/var/tmp/known_input_devices.txt"
> "$STATE_FILE"

while IFS= read -r line; do
    if [[ $line == I:* ]]; then
        bus=$(echo "$line" | grep -o "Bus=[0-9a-fA-F]\+" | cut -d= -f2)
        vendor=$(echo "$line" | grep -o "Vendor=[0-9a-fA-F]\+" | cut -d= -f2)
        product=$(echo "$line" | grep -o "Product=[0-9a-fA-F]\+" | cut -d= -f2)
        [ -z "$bus" ] && bus="0000"
        [ -z "$vendor" ] && vendor="0000"
        [ -z "$product" ] && product="0000"
        
        # Читаем следующую строку для имени
        read -r next_line
        if [[ $next_line == N:* ]]; then
            name=$(echo "$next_line" | grep -o 'Name="[^"]*"' | cut -d'"' -f2 | tr ' ' '_')
            [ -z "$name" ] && name="unknown"
            echo "${bus}:${vendor}:${product}:${name}" >> "$STATE_FILE"
        fi
    fi
done < /proc/bus/input/devices

sort -u "$STATE_FILE" -o "$STATE_FILE"
echo "Инициализировано устройств: $(wc -l < "$STATE_FILE")"
EOF
    
    chmod +x /tmp/init_state.sh
    /tmp/init_state.sh
    rm /tmp/init_state.sh
    
    echo "  ✓ Файл состояния создан"
else
    touch "$STATE_FILE"
    echo "  ⚠ Файл devices не найден, создан пустой файл состояния"
fi

chmod 666 "$STATE_FILE"

# Шаг 7: Настройка crontab для запуска каждую минуту
echo "Шаг 7: Настройка crontab для запуска каждую минуту..."

# Создание временного файла с текущим crontab
crontab -l > /tmp/current_cron 2>/dev/null || echo "" > /tmp/current_cron

# Проверка, существует ли уже задача
if grep -q "$FULL_SCRIPT_PATH" /tmp/current_cron; then
    echo "  ⚠ Задача уже существует в crontab"
    
    # Показываем существующую задачу
    grep "$FULL_SCRIPT_PATH" /tmp/current_cron
else
    # Добавление новой задачи (каждую минуту)
    echo "* * * * * $FULL_SCRIPT_PATH >> /var/log/input_devices_cron_exec.log 2>&1" >> /tmp/current_cron
    crontab /tmp/current_cron
    echo "  ✓ Задача добавлена в crontab (запуск каждую минуту)"
fi

rm /tmp/current_cron

# Шаг 8: Проверка настроек
echo "Шаг 8: Проверка настроек..."
echo
echo "Текущий crontab:"
echo "----------------"
crontab -l | grep -v "^#"
echo

# Шаг 9: Тестовый запуск
echo "Шаг 9: Выполнение тестового запуска..."
echo

# Выполняем тестовый запуск
bash "$FULL_SCRIPT_PATH"
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "  ✓ Тестовый запуск выполнен успешно"
    
    # Показываем последние записи из лога
    echo
    echo "Последние 10 записей в лог-файле:"
    echo "----------------"
    if [ -f "$LOG_FILE" ]; then
        tail -10 "$LOG_FILE"
    else
        echo "Лог-файл не найден"
    fi
else
    echo "  ✗ Ошибка при тестовом запуске (код: $TEST_EXIT_CODE)"
fi

# Шаг 10: Создание скрипта для просмотра статистики
echo "Шаг 10: Создание скрипта для просмотра статистики..."

cat > /usr/local/bin/input-device-stats << 'EOF'
#!/bin/bash

# Скрипт для просмотра статистики мониторинга устройств

LOG_FILE="/var/log/input_devices_cron.log"
STATE_FILE="/var/tmp/known_input_devices.txt"

echo "=========================================="
echo "   СТАТИСТИКА МОНИТОРИНГА УСТРОЙСТВ"
echo "=========================================="
echo

# Информация о файле состояния
if [ -f "$STATE_FILE" ]; then
    TOTAL_DEVICES=$(wc -l < "$STATE_FILE")
    echo "Всего уникальных устройств обнаружено: $TOTAL_DEVICES"
    echo
    echo "Последние 5 обнаруженных устройств:"
    echo "------------------------"
    tail -5 "$STATE_FILE" | while read line; do
        echo "  $line"
    done
else
    echo "Файл состояния не найден"
fi

echo

# Информация о лог-файле
if [ -f "$LOG_FILE" ]; then
    LOG_SIZE=$(du -h "$LOG_FILE" | cut -f1)
    LOG_LINES=$(wc -l < "$LOG_FILE")
    echo "Лог-файл: $LOG_FILE"
    echo "Размер лога: $LOG_SIZE"
    echo "Всего записей: $LOG_LINES"
    echo
    echo "Последние 10 событий:"
    echo "------------------------"
    tail -10 "$LOG_FILE"
else
    echo "Лог-файл не найден"
fi

echo
echo "Для просмотра лога в реальном времени:"
echo "  tail -f $LOG_FILE"
EOF

chmod +x /usr/local/bin/input-device-stats
echo "  ✓ Скрипт статистики создан: /usr/local/bin/input-device-stats"

# Итоговая информация
echo
echo "================================================================"
echo "   НАСТРОЙКА ЗАВЕРШЕНА УСПЕШНО!"
echo "================================================================"
echo
echo "Скрипт мониторинга: $FULL_SCRIPT_PATH"
echo "Лог-файл:           $LOG_FILE"
echo "Файл состояния:     $STATE_FILE"
echo "Резервные копии:    $BACKUP_DIR"
echo
echo "Интервал опроса:    КАЖДУЮ МИНУТУ (через cron)"
echo
echo "Полезные команды:"
echo "  input-device-stats                    # Просмотр статистики"
echo "  tail -f $LOG_FILE                      # Просмотр лога в реальном времени"
echo "  crontab -l                              # Просмотр заданий cron"
echo "  sudo tail -f /var/log/syslog | grep CRON  # Просмотр лога cron"
echo "  wc -l $STATE_FILE                        # Количество отслеживаемых устройств"
echo "  ls -la $BACKUP_DIR                        # Просмотр резервных копий"
echo
echo "Для проверки работы подождите 1-2 минуты и выполните:"
echo "  input-device-stats"
echo
