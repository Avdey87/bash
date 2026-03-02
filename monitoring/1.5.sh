#!/bin/bash

# Скрипт с логированием новых процессов

# Конфигурация
LOG_FILE="/tmp/process_monitor.log"
PID_STATE_FILE="/tmp/known_pids.txt"
SCRIPT_NAME=$(basename "$0")

# Функция логирования
log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$timestamp - $message" >> "$LOG_FILE"
    echo "$timestamp - $message"
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
    local new_pids=0
    
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
                log_message "НОВЫЙ ПРОЦЕСС: PID=$pid, NAME=$name"
                new_pids=$((new_pids + 1))
            fi
        fi
    done <<< "$current_pids"
    
    # Обновляем файл состояния
    echo "$current_pids" > "$PID_STATE_FILE"
    
    if [ $new_pids -gt 0 ]; then
        log_message "Обнаружено новых процессов: $new_pids"
    else
        log_message "Новых процессов не обнаружено"
    fi
}

# Функция отображения таблицы
display_table() {
    echo -e "\n"$(date "+%Y-%m-%d %H:%M:%S")" - Текущие процессы:"
    echo "=================================================================================================="
    printf "%-8s %-20s %-30s %-15s %-15s %-10s\n" "PID" "NAME" "CMDLINE" "STATUS" "LIMITS" "FD"
    echo "=================================================================================================="
    
    for pid in $(ls -1 /proc/ | grep -E '^[0-9]+$' | sort -n | head -10); do
        if [ -d "/proc/$pid" ]; then
            name=$(get_process_name "$pid" | cut -c 1-20)
            echo "  $pid    $name    ..." # Упрощенно для демонстрации
        fi
    done
    echo "=================================================================================================="
}

# Основная функция
main() {
    log_message "=== ЗАПУСК СКРИПТА $SCRIPT_NAME ==="
    
    # Проверяем новые процессы
    check_new_processes
    
    # Отображаем таблицу
    display_table
    
    log_message "=== ЗАВЕРШЕНИЕ СКРИПТА ===\n"
}

# Запуск
main
