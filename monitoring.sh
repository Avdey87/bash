#!/bin/bash

# ============================================
# Мониторинг процессов через /proc
# ============================================

# Конфигурация
LOG_FILE="/var/log/proc_monitor.log"
SCRIPT_NAME=$(basename "$0")
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# Функция для логирования
log_message() {
    echo "[$TIMESTAMP] $1" >> "$LOG_FILE"
}

# Функция для получения имени процесса по PID
get_process_name() {
    local pid=$1
    if [ -e "/proc/$pid/exe" ]; then
        readlink "/proc/$pid/exe" 2>/dev/null | xargs basename 2>/dev/null
    else
        echo "N/A"
    fi
}

# Функция для получения выбранных параметров процесса
get_process_params() {
    local pid=$1
    local param_file
    
    # Выбираем 4 параметра: cmdline, status, limits, environ
    # (можно заменить на любые другие из списка)
    
    # Параметр 1: cmdline (командная строка)
    if [ -r "/proc/$pid/cmdline" ]; then
        param1=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-50)
        [ -z "$param1" ] && param1="N/A"
    else
        param1="N/A"
    fi
    
    # Параметр 2: status (статус процесса)
    if [ -r "/proc/$pid/status" ]; then
        param2=$(grep -E "^(State|VmRSS)" "/proc/$pid/status" 2>/dev/null | tr '\n' ' ' | cut -c1-50)
        [ -z "$param2" ] && param2="N/A"
    else
        param2="N/A"
    fi
    
    # Параметр 3: limits (лимиты)
    if [ -r "/proc/$pid/limits" ]; then
        param3=$(head -n 2 "/proc/$pid/limits" 2>/dev/null | tail -n 1 | awk '{print $1, $2}' | cut -c1-50)
        [ -z "$param3" ] && param3="N/A"
    else
        param3="N/A"
    fi
    
    # Параметр 4: environ (переменные окружения)
    if [ -r "/proc/$pid/environ" ]; then
        param4=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | head -n 1 | cut -c1-50)
        [ -z "$param4" ] && param4="N/A"
    else
        param4="N/A"
    fi
    
    echo "$param1|$param2|$param3|$param4"
}

# Функция для проверки, является ли директория числовой (PID)
is_numeric_dir() {
    [[ $1 =~ ^[0-9]+$ ]] && [ -d "/proc/$1" ]
}

# Функция для получения текущих процессов
get_current_processes() {
    local pids=()
    for dir in /proc/[0-9]*/; do
        pid=$(basename "$dir")
        if is_numeric_dir "$pid"; then
            pids+=("$pid")
        fi
    done
    echo "${pids[@]}"
}

# Основная функция мониторинга
monitor_processes() {
    log_message "Запуск мониторинга процессов"
    
    # Файл для хранения предыдущего списка процессов
    PREV_PIDS_FILE="/tmp/proc_monitor_prev_${SCRIPT_NAME}.tmp"
    
    # Получаем текущие процессы
    current_pids=($(get_current_processes))
    
    # Загружаем предыдущие процессы
    if [ -f "$PREV_PIDS_FILE" ]; then
        prev_pids=($(cat "$PREV_PIDS_FILE"))
    else
        prev_pids=()
    fi
    
    # Находим новые процессы
    new_pids=()
    for pid in "${current_pids[@]}"; do
        found=0
        for old_pid in "${prev_pids[@]}"; do
            if [ "$pid" = "$old_pid" ]; then
                found=1
                break
            fi
        done
        if [ $found -eq 0 ]; then
            new_pids+=("$pid")
        fi
    done
    
    # Если есть новые процессы, записываем их в лог
    if [ ${#new_pids[@]} -gt 0 ]; then
        log_message "Обнаружены новые процессы:"
        
        # Создаем временный файл для таблицы
        temp_table=$(mktemp)
        
        # Заголовок таблицы
        printf "%-10s %-25s %-50s %-30s %-30s %-50s\n" \
               "PID" "NAME" "CMDLINE" "STATUS" "LIMITS" "ENVIRON" > "$temp_table"
        printf "%s\n" "-------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$temp_table"
        
        # Заполняем таблицу новыми процессами
        for pid in "${new_pids[@]}"; do
            name=$(get_process_name "$pid")
            params=$(get_process_params "$pid")
            
            # Разбиваем параметры
            IFS='|' read -r param1 param2 param3 param4 <<< "$params"
            
            # Записываем в таблицу
            printf "%-10s %-25s %-50s %-30s %-30s %-50s\n" \
                   "$pid" "$name" "$param1" "$param2" "$param3" "$param4" >> "$temp_table"
        done
        
        # Добавляем таблицу в лог
        cat "$temp_table" >> "$LOG_FILE"
        rm "$temp_table"
        
        log_message "Добавлено новых процессов: ${#new_pids[@]}"
    else
        log_message "Новых процессов не обнаружено"
    fi
    
    # Сохраняем текущие процессы для следующего запуска
    printf "%s\n" "${current_pids[@]}" > "$PREV_PIDS_FILE"
    
    log_message "Мониторинг завершен"
}

# Функция для разового вывода всех процессов (пункт 1.4)
show_all_processes() {
    echo "Текущие процессы:"
    echo "================="
    
    # Заголовок таблицы
    printf "%-10s %-25s %-50s %-30s %-30s %-50s\n" \
           "PID" "NAME" "CMDLINE" "STATUS" "LIMITS" "ENVIRON"
    printf "%s\n" "-------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    
    # Получаем все процессы
    all_pids=($(get_current_processes))
    
    # Заполняем таблицу
    for pid in "${all_pids[@]}"; do
        name=$(get_process_name "$pid")
        params=$(get_process_params "$pid")
        
        IFS='|' read -r param1 param2 param3 param4 <<< "$params"
        
        printf "%-10s %-25s %-50s %-30s %-30s %-50s\n" \
               "$pid" "$name" "$param1" "$param2" "$param3" "$param4"
    done
}

# Основная логика скрипта
case "$1" in
    --show-all)
        show_all_processes
        ;;
    --monitor)
        monitor_processes
        ;;
    *)
        echo "Использование: $0 [--show-all | --monitor]"
        echo "  --show-all  - показать все текущие процессы"
        echo "  --monitor   - запустить мониторинг новых процессов"
        exit 1
        ;;
esac

exit 0
