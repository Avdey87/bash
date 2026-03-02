#!/bin/bash

# Скрипт для отображения информации о процессах в виде таблицы

echo "Таблица процессов с параметрами"
echo "==============================="
echo

# Выбранные 4 параметра:
# 1. cmdline - командная строка
# 2. status - статус и память
# 3. limits - лимиты
# 4. fd_count - количество файловых дескрипторов

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

# Функция получения параметров
get_param() {
    local pid=$1
    local param_type=$2
    
    if [ ! -d "/proc/$pid" ]; then
        echo "N/A"
        return
    fi
    
    case $param_type in
        "cmdline")
            if [ -f "/proc/$pid/cmdline" ] && [ -r "/proc/$pid/cmdline" ]; then
                cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c 1-40)
                [ -n "$cmd" ] && echo "$cmd" || echo "N/A"
            else
                echo "N/A"
            fi
            ;;
            
        "status")
            if [ -f "/proc/$pid/status" ] && [ -r "/proc/$pid/status" ]; then
                state=$(grep "^State:" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
                mem=$(grep "^VmRSS:" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
                [ -n "$mem" ] && mem="${mem}KB" || mem="0KB"
                echo "${state:-?} ${mem}"
            else
                echo "N/A"
            fi
            ;;
            
        "limits")
            if [ -f "/proc/$pid/limits" ] && [ -r "/proc/$pid/limits" ]; then
                open_files=$(grep "Max open files" "/proc/$pid/limits" 2>/dev/null | awk '{print $4}')
                echo "${open_files:-N/A} files"
            else
                echo "N/A"
            fi
            ;;
            
        "fd_count")
            if [ -d "/proc/$pid/fd" ] && [ -r "/proc/$pid/fd" ]; then
                count=$(ls -1 "/proc/$pid/fd" 2>/dev/null | wc -l)
                echo "$count fds"
            else
                echo "0 fds"
            fi
            ;;
            
        *)
            echo "N/A"
            ;;
    esac
}

# Функция для рисования разделителя
print_separator() {
    printf "+%s+%s+%s+%s+%s+%s+\n" \
        "--------" "----------------" "----------------------------------------" \
        "-----------" "-----------" "-----------"
}

# Заголовок таблицы
print_separator
printf "| %-6s | %-14s | %-38s | %-9s | %-9s | %-9s |\n" \
    "PID" "NAME" "CMDLINE" "STATUS" "LIMITS" "FD"
print_separator

# Получаем первые 20 процессов для примера
count=0
for pid in $(ls -1 /proc/ | grep -E '^[0-9]+$' | sort -n | head -20); do
    if [ -d "/proc/$pid" ]; then
        name=$(get_process_name "$pid" | cut -c 1-14)
        cmdline=$(get_param "$pid" "cmdline" | cut -c 1-38)
        status=$(get_param "$pid" "status" | cut -c 1-9)
        limits=$(get_param "$pid" "limits" | cut -c 1-9)
        fd_count=$(get_param "$pid" "fd_count" | cut -c 1-9)
        
        printf "| %-6s | %-14s | %-38s | %-9s | %-9s | %-9s |\n" \
            "$pid" "$name" "$cmdline" "$status" "$limits" "$fd_count"
        
        count=$((count + 1))
    fi
done

print_separator
echo -e "\nВсего отображено процессов: $count"
echo "Для просмотра всех процессов используйте полную версию скрипта"
