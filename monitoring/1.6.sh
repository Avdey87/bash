#!/bin/bash

# Скрипт для настройки cron на мониторинг процессов каждые 5 минут

echo "Настройка планировщика заданий для мониторинга процессов"
echo "==========================================================================="

# Конфигурация
SCRIPT_DIR="/opt/scripts"
SCRIPT_NAME="process_monitor_cron.sh"
FULL_SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"
LOG_FILE="/var/log/process_monitor.log"
PID_STATE_FILE="/tmp/known_pids_cron.txt"

# Создание директории для скриптов
echo "Создание директории $SCRIPT_DIR..."
sudo mkdir -p "$SCRIPT_DIR"

# Создание основного скрипта для cron (исправленная версия)
cat > /tmp/$SCRIPT_NAME << 'EOF'
#!/bin/bash

# process_monitor_cron.sh - Скрипт для cron мониторинга процессов

# Конфигурация
LOG_FILE="/var/log/process_monitor.log"
PID_STATE_FILE="/tmp/known_pids_cron.txt"

# Функция логирования
log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$timestamp - $message" >> "$LOG_FILE"
}

# Функция получения имени процесса
get_process_name() {
    local pid=$1
    if [ -L "/proc/$pid/exe" ] && [ -e "/proc/$pid/exe" ]; then
        readlink "/proc/$pid/exe" 2>/dev/null | xargs basename 2>/dev/null
    elif [ -f "/proc/$pid/comm" ]; then
        cat "/proc/$pid/comm" 2>/dev/null
    else
        echo "N/A"
    fi
}

# Функция получения статуса
get_status() {
    local pid=$1
    if [ -f "/proc/$pid/status" ] && [ -r "/proc/$pid/status" ]; then
        state=$(grep "^State:" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
        echo "${state:-?}"
    else
        echo "N/A"
    fi
}

# Функция проверки новых процессов
check_new_processes() {
    local new_pids=0
    
    # Получаем текущие PID
    current_pids=$(ls -1 /proc/ | grep -E '^[0-9]+$' | sort -n)
    
    # Если файл состояния не существует, создаем его
    if [ ! -f "$PID_STATE_FILE" ]; then
        echo "$current_pids" > "$PID_STATE_FILE"
        log_message "Инициализация списка PID. Всего процессов: $(echo "$current_pids" | wc -l)"
        return
    fi
    
    # Читаем известные PID
    known_pids=$(cat "$PID_STATE_FILE" 2>/dev/null || echo "")
    
    # Ищем новые процессы
    for pid in $current_pids; do
        if ! echo "$known_pids" | grep -q "^$pid$"; then
            if [ -d "/proc/$pid" ]; then
                name=$(get_process_name "$pid")
                status=$(get_status "$pid")
                log_message "CRON ОБНАРУЖИЛ НОВЫЙ ПРОЦЕСС: PID=$pid, NAME=$name, STATUS=$status"
                
                # Дополнительная информация о новом процессе
                if [ -f "/proc/$pid/cmdline" ] && [ -r "/proc/$pid/cmdline" ]; then
                    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c 1-100)
                    log_message "  Команда: $cmdline"
                fi
                new_pids=$((new_pids + 1))
            fi
        fi
    done
    
    # Обновляем файл состояния
    echo "$current_pids" > "$PID_STATE_FILE"
    
    if [ $new_pids -gt 0 ]; then
        log_message "Обнаружено новых процессов: $new_pids"
    fi
}

# Основная функция
main() {
    log_message "=== CRON ЗАПУСК ==="
    check_new_processes
    log_message "=== CRON ЗАВЕРШЕНИЕ ==="
}

main
EOF

# Копирование скрипта в целевую директорию
sudo cp /tmp/$SCRIPT_NAME "$FULL_SCRIPT_PATH"
sudo chmod +x "$FULL_SCRIPT_PATH"
rm /tmp/$SCRIPT_NAME

# Создание лог-файла с правильными правами
echo "Создание лог-файла $LOG_FILE..."
sudo touch "$LOG_FILE"
sudo chmod 666 "$LOG_FILE"
sudo chown $USER:$USER "$LOG_FILE"

# Проверка существования лог-файла
if [ -f "$LOG_FILE" ]; then
    echo "Лог-файл создан успешно"
    ls -la "$LOG_FILE"
else
    echo "Ошибка создания лог-файла"
fi

# Настройка crontab
echo "Настройка crontab для запуска каждые 5 минут..."

# Создание временного файла с текущим crontab
crontab -l > /tmp/current_cron 2>/dev/null || echo "" > /tmp/current_cron

# Проверка, существует ли уже задача
if grep -q "$FULL_SCRIPT_PATH" /tmp/current_cron; then
    echo "Задача уже существует в crontab"
else
    # Добавление новой задачи
    echo "*/5 * * * * $FULL_SCRIPT_PATH" >> /tmp/current_cron
    crontab /tmp/current_cron
    echo "Задача добавлена в crontab"
fi

rm /tmp/current_cron

# Просмотр настроенного crontab
echo -e "\nТекущий crontab:"
echo "----------------"
crontab -l

# Проверка скрипта
echo -e "\nПроверка скрипта:"
echo "----------------"
ls -la "$FULL_SCRIPT_PATH"

# Информация о настройке
echo -e "\nНастройка завершена!"
echo "Скрипт: $FULL_SCRIPT_PATH"
echo "Лог-файл: $LOG_FILE"
echo "PID state: $PID_STATE_FILE"
echo -e "\nДля просмотра логов используйте:"
echo "tail -f $LOG_FILE"

# Тестовый запуск
echo -e "\nВыполнить тестовый запуск? (y/n)"
read -r answer
if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    echo "Запуск тестового выполнения..."
    bash "$FULL_SCRIPT_PATH"
    echo -e "\nЛог после тестового запуска:"
    if [ -f "$LOG_FILE" ]; then
        tail -10 "$LOG_FILE"
    else
        echo "Лог-файл не найден"
    fi
fi

echo -e "\nДля проверки работы cron через 5 минут используйте:"
echo "sudo tail -f /var/log/syslog | grep CRON"
