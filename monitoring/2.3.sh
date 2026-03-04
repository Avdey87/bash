#!/bin/bash

echo "========================================================"
echo "   МОНИТОРИНГ НОВЫХ УСТРОЙСТВ ВВОДА С ЛОГИРОВАНИЕМ"
echo "========================================================"
echo

# Конфигурация
LOG_FILE="/tmp/input_devices_monitor.log"
STATE_FILE="/tmp/known_input_devices.txt"
SCRIPT_NAME=$(basename "$0")

# Проверка существования директории
if [ ! -d "/proc/bus/input" ]; then
    echo "Ошибка: Директория /proc/bus/input не существует"
    exit 1
fi

# Проверка прав доступа
if [ ! -r "/proc/bus/input" ]; then
    echo "Ошибка: Нет прав для чтения /proc/bus/input"
    echo "Попробуйте: sudo $0"
    exit 1
fi

# Функция логирования
log_message() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$timestamp - $message" | tee -a "$LOG_FILE"
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
    local name=$(echo "$n_line" | grep -o 'Name="[^"]*"' | cut -d'"' -f2)
    
    # Создаем ID: bus:vendor:product:name
    echo "${bus:-0000}:${vendor:-0000}:${product:-0000}:${name:-unknown}"
}

# Функция для извлечения имени устройства
get_device_name() {
    local device_block="$1"
    local n_line=$(echo "$device_block" | grep "^N:" | head -1)
    echo "$n_line" | grep -o 'Name="[^"]*"' | cut -d'"' -f2 | sed 's/ /_/g'
}

# Функция для извлечения обработчиков устройства
get_device_handlers() {
    local device_block="$1"
    local h_line=$(echo "$device_block" | grep "^H:" | head -1)
    echo "$h_line" | cut -c4-
}

# Функция для разбора устройств из файла
parse_devices() {
    local devices_file="$1"
    local -n devices_array="$2"
    local -n ids_array="$3"
    
    if [ ! -f "$devices_file" ] || [ ! -r "$devices_file" ]; then
        return 1
    fi
    
    local current_device=""
    local device_count=0
    
    # Читаем файл построчно и группируем по устройствам
    while IFS= read -r line; do
        if [[ $line == I:* ]]; then
            # Сохраняем предыдущее устройство
            if [ -n "$current_device" ]; then
                device_count=$((device_count + 1))
                devices_array[$device_count]="$current_device"
                ids_array[$device_count]=$(get_device_id "$current_device")
            fi
            # Начинаем новое устройство
            current_device="$line\n"
        elif [[ $line =~ ^[NPHB]: ]] && [ -n "$current_device" ]; then
            current_device="${current_device}${line}\n"
        fi
    done < "$devices_file"
    
    # Сохраняем последнее устройство
    if [ -n "$current_device" ]; then
        device_count=$((device_count + 1))
        devices_array[$device_count]="$current_device"
        ids_array[$device_count]=$(get_device_id "$current_device")
    fi
    
    return $device_count
}

# Функция для проверки новых устройств
check_new_devices() {
    local new_devices=0
    
    log_message "=== НАЧАЛО ПРОВЕРКИ НОВЫХ УСТРОЙСТВ ==="
    
    # Получаем текущие устройства
    declare -a current_devices=()
    declare -a current_ids=()
    
    parse_devices "/proc/bus/input/devices" current_devices current_ids
    local current_count=$?
    
    log_message "Текущее количество устройств: $current_count"
    
    # Если файл состояния не существует, создаем его
    if [ ! -f "$STATE_FILE" ]; then
        # Сохраняем все текущие устройства в файл состояния
        > "$STATE_FILE"
        for ((i=1; i<=current_count; i++)); do
            echo "${current_ids[$i]}" >> "$STATE_FILE"
        done
        log_message "Инициализация списка устройств. Всего устройств: $current_count"
        return 0
    fi
    
    # Загружаем известные ID из файла состояния
    declare -a known_ids=()
    while IFS= read -r id; do
        known_ids+=("$id")
    done < "$STATE_FILE"
    
    # Ищем новые устройства
    for ((i=1; i<=current_count; i++)); do
        local current_id="${current_ids[$i]}"
        local is_new=1
        
        # Проверяем, есть ли текущий ID в известных
        for known_id in "${known_ids[@]}"; do
            if [ "$current_id" = "$known_id" ]; then
                is_new=0
                break
            fi
        done
        
        # Если устройство новое - логируем
        if [ $is_new -eq 1 ]; then
            new_devices=$((new_devices + 1))
            
            # Извлекаем информацию для логирования
            local name=$(get_device_name "${current_devices[$i]}")
            local handlers=$(get_device_handlers "${current_devices[$i]}")
            
            # Определяем тип устройства по обработчикам
            local device_type="Неизвестно"
            if [[ $handlers == *"kbd"* ]]; then
                device_type="Клавиатура"
            elif [[ $handlers == *"mouse"* ]]; then
                device_type="Мышь"
            elif [[ $handlers == *"js"* ]]; then
                device_type="Джойстик"
            elif [[ $handlers == *"event"* ]]; then
                device_type="Устройство событий"
            fi
            
            log_message "НОВОЕ УСТРОЙСТВО ОБНАРУЖЕНО:"
            log_message "  ID: $current_id"
            log_message "  Имя: $name"
            log_message "  Тип: $device_type"
            log_message "  Обработчики: $handlers"
            
            # Добавляем ID в файл состояния
            echo "$current_id" >> "$STATE_FILE"
        fi
    done
    
    # Очищаем файл состояния от дубликатов
    sort -u "$STATE_FILE" -o "$STATE_FILE"
    
    if [ $new_devices -gt 0 ]; then
        log_message "ИТОГ: Обнаружено новых устройств: $new_devices"
    else
        log_message "Новых устройств не обнаружено"
    fi
    
    log_message "=== ЗАВЕРШЕНИЕ ПРОВЕРКИ ==="
    echo
}

# Функция для вывода текущей таблицы устройств
show_devices_table() {
    echo
    echo "ТЕКУЩИЕ УСТРОЙСТВА ВВОДА:"
    echo "--------------------------------------------------------"
    
    if [ -f "/proc/bus/input/devices" ] && [ -r "/proc/bus/input/devices" ]; then
        declare -a devices=()
        declare -a ids=()
        
        parse_devices "/proc/bus/input/devices" devices ids
        local count=$?
        
        printf "%-4s | %-30s | %-20s | %-30s\n" "№" "ИМЯ УСТРОЙСТВА" "ТИП" "ОБРАБОТЧИКИ"
        echo "------------------------------------------------------------------------------------------"
        
        for ((i=1; i<=count; i++)); do
            local name=$(get_device_name "${devices[$i]}" | sed 's/_/ /g')
            local handlers=$(get_device_handlers "${devices[$i]}")
            
            # Определяем тип
            local type="Другое"
            if [[ $handlers == *"kbd"* ]]; then
                type="Клавиатура"
            elif [[ $handlers == *"mouse"* ]]; then
                type="Мышь"
            elif [[ $handlers == *"js"* ]]; then
                type="Джойстик"
            fi
            
            printf "%-4s | %-30s | %-20s | %-30s\n" "$i" "${name:0:30}" "$type" "${handlers:0:30}"
        done
        
        echo "------------------------------------------------------------------------------------------"
        echo "Всего устройств: $count"
    else
        echo "Файл devices недоступен"
    fi
}

# Функция для просмотра лога
show_log() {
    echo
    echo "ПОСЛЕДНИЕ ЗАПИСИ В ЛОГ-ФАЙЛЕ:"
    echo "--------------------------------------------------------"
    
    if [ -f "$LOG_FILE" ]; then
        tail -20 "$LOG_FILE"
    else
        echo "Лог-файл еще не создан"
    fi
    echo
}

# Основная функция
main() {
    log_message "=== ЗАПУСК СКРИПТА $SCRIPT_NAME ==="
    
    # Показываем текущие устройства
    show_devices_table
    
    # Проверяем новые устройства
    check_new_devices
    
    # Показываем последние записи из лога
    show_log
    
    # Статистика
    echo "СТАТИСТИКА:"
    echo "--------------------------------------------------------"
    
    if [ -f "$STATE_FILE" ]; then
        known_count=$(wc -l < "$STATE_FILE")
        echo "Известных устройств (всего когда-либо обнаруженных): $known_count"
    fi
    
    if [ -f "$LOG_FILE" ]; then
        log_size=$(du -h "$LOG_FILE" | cut -f1)
        log_lines=$(wc -l < "$LOG_FILE")
        echo "Лог-файл: $LOG_FILE"
        echo "Размер лога: $log_size, записей: $log_lines"
    fi
    
    echo
    log_message "=== ЗАВЕРШЕНИЕ СКРИПТА $SCRIPT_NAME ==="
}

# Запуск основной функции
main

# Сохраняем копию лога с датой
backup_file="/tmp/input_devices_$(date +%Y%m%d_%H%M%S).log"
cp "$LOG_FILE" "$backup_file" 2>/dev/null
echo "Резервная копия лога сохранена в: $backup_file"
