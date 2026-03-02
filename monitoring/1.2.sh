#!/bin/bash

# Скрипт для получения имени процесса по PID из /proc

echo "Получение имени процесса по PID через /proc/PID/exe"
echo "=================================================="

# Функция получения имени процесса
get_process_name() {
    local pid=$1
    
    # Проверяем существование процесса
    if [ ! -d "/proc/$pid" ]; then
        echo "Процесс $pid не существует"
        return 1
    fi
    
    # Пытаемся получить имя через /proc/PID/exe
    if [ -L "/proc/$pid/exe" ] && [ -e "/proc/$pid/exe" ]; then
        exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
        if [ -n "$exe_path" ]; then
            echo "$(basename "$exe_path")"
        else
            echo "N/A"
        fi
    # Альтернативный метод через /proc/PID/comm
    elif [ -f "/proc/$pid/comm" ]; then
        cat "/proc/$pid/comm" 2>/dev/null
    else
        echo "N/A"
    fi
}

# Тестирование на нескольких процессах
test_pids="1 2 3 4 5 10 20 30 40 50"

echo -e "\nPID\tИмя процесса"
echo "------------------------"

for pid in $test_pids; do
    if [ -d "/proc/$pid" ]; then
        name=$(get_process_name "$pid")
        echo -e "$pid\t$name"
    else
        echo -e "$pid\t(процесс не существует)"
    fi
done

echo "------------------------"

# Интерактивный режим
echo -e "\nВведите PID для получения имени процесса (или 'q' для выхода):"
while read -p "PID: " input; do
    if [ "$input" = "q" ]; then
        break
    fi
    
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        if [ -d "/proc/$input" ]; then
            name=$(get_process_name "$input")
            echo "Процесс с PID=$input: $name"
            echo "Полный путь: $(readlink /proc/$input/exe 2>/dev/null || echo 'N/A')"
        else
            echo "Процесс с PID=$input не найден"
        fi
    else
        echo "Пожалуйста, введите число"
    fi
done
