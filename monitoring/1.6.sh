#!/bin/bash

# Скрипт для настройки cron на мониторинг процессов каждые 5 минут

echo "Настройка планировщика заданий для мониторинга процессов"
echo "========================================================"

# Конфигурация
SCRIPT_DIR="/opt/scripts"
SCRIPT_NAME="process_monitor_cron.sh"
FULL_SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"
LOG_DIR="/var/log"
CRON_LOG="$LOG_DIR/process_cron.log"

# Создание директории для скриптов
echo "Создание директории $SCRIPT_DIR..."
sudo mkdir -p "$SCRIPT_DIR"

# Создание основного скрипта для cron
cat > /tmp/$SCRIPT_NAME << 'EOF'
#!/bin/bash

# process_monitor_cron.sh - Скрипт для cron мониторинга процессов

# Конфигурация
LOG_FILE="/var/log/process_monitor.log"
PID_STATE_FILE="/tmp/known_pids_cron.txt"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# Функция логирования
log_message() {
    echo "$TIMESTAMP - $1" >> "$LOG_FILE"
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

# Функция проверки новых процессов
check_new_processes() {
    # Получаем текущие PID
    current_pids=$(ls -1 /proc/ | grep -E '^[0-9]+$' | sort)
    
    # Если файл состояния не существует, создаем его
    if [ ! -f "$PID_STATE_FILE" ]; then
        echo "$current_pids" > "$PID_STATE_FILE"
        log_message "Инициализация списка PID. Всего процессов: $(echo "$current_pids" | wc -l)"
        return
    fi
    
    # Читаем известные PID
    known_pids=$(cat "$PID_STATE_FILE" 2>/dev/null || echo "")
    
    # Ищем новые процессы
    while read pid; do
        if [ -n "$pid" ] && ! echo "$known_pids" | grep -q "^$pid$"; then
            if [ -d "/proc/$pid" ]; then
                name=$(get_process_name "$pid")
                log_message "CRON ОБНАРУЖИЛ НОВЫЙ ПРОЦЕСС: PID=$pid, NAME=$name"
                
                # Дополнительная информация о новом процессе
                if [ -f "/proc/$pid/cmdline" ]; then
                    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c 1-100)
                    log_message "  Команда: $cmdline"
                fi
                
                if [ -f "/proc/$pid/status" ]; then
                    uid=$(grep "^Uid:" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
                    log_message "  UID: $uid"
                fi
            fi
        fi
    done <<< "$current_pids"
    
    # Обновляем файл состояния
    echo "$current_pids" > "$PID_STATE_FILE"
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

# Создание лог-файла
sudo touch "$LOG_FILE"
sudo chmod 666 "$LOG_FILE"

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
echo "PID state: /tmp/known_pids_cron.txt"
echo -e "\nДля просмотра логов используйте:"
echo "tail -f $LOG_FILE"

# Тестовый запуск
echo -e "\nВыполнить тестовый запуск? (y/n)"
read -r answer
if [ "$answer" = "y" ]; then
    echo "Запуск тестового выполнения..."
    $FULL_SCRIPT_PATH
    echo "Лог после тестового запуска:"
    tail -5 "$LOG_FILE"
fi
