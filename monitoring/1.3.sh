#!/bin/bash

# Скрипт для получения различных параметров процесса из /proc

echo "Получение параметров процесса из /proc/PID/"
echo "==========================================="

# Функция для получения параметров процесса
get_process_params() {
    local pid=$1
    local param=$2
    
    if [ ! -d "/proc/$pid" ]; then
        echo "N/A (процесс не существует)"
        return 1
    fi
    
    case $param in
        "cmdline")
            echo "=== /proc/$pid/cmdline ==="
            if [ -r "/proc/$pid/cmdline" ]; then
                tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "Нет доступа"
            else
                echo "Нет доступа к чтению"
            fi
            ;;
            
        "environ")
            echo "=== /proc/$pid/environ (первые 200 символов) ==="
            if [ -r "/proc/$pid/environ" ]; then
                tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | head -10 || echo "Нет доступа"
            else
                echo "Нет доступа к чтению"
            fi
            ;;
            
        "limits")
            echo "=== /proc/$pid/limits (основные лимиты) ==="
            if [ -r "/proc/$pid/limits" ]; then
                grep -E "Max open files|Max processes|Max file size" "/proc/$pid/limits" 2>/dev/null || echo "Лимиты не найдены"
            else
                echo "Нет доступа к чтению"
            fi
            ;;
            
        "status")
            echo "=== /proc/$pid/status (основная информация) ==="
            if [ -r "/proc/$pid/status" ]; then
                grep -E "^(Name|Pid|PPid|State|VmRSS|Threads)" "/proc/$pid/status" 2>/dev/null || echo "Статус не найден"
            else
                echo "Нет доступа к чтению"
            fi
            ;;
            
        "mounts")
            echo "=== /proc/$pid/mounts (первые 5 записей) ==="
            if [ -r "/proc/$pid/mounts" ]; then
                head -5 "/proc/$pid/mounts" 2>/dev/null || echo "Нет доступа"
            else
                echo "Нет доступа к чтению"
            fi
            ;;
            
        "cwd")
            echo "=== /proc/$pid/cwd ==="
            if [ -L "/proc/$pid/cwd" ]; then
                readlink "/proc/$pid/cwd" 2>/dev/null || echo "Нет доступа"
            else
                echo "Нет доступа"
            fi
            ;;
            
        "fd")
            echo "=== /proc/$pid/fd (первые 5 файловых дескрипторов) ==="
            if [ -d "/proc/$pid/fd" ] && [ -r "/proc/$pid/fd" ]; then
                ls -la "/proc/$pid/fd" 2>/dev/null | head -5 || echo "Нет доступа"
            else
                echo "Нет доступа"
            fi
            ;;
            
        "root")
            echo "=== /proc/$pid/root ==="
            if [ -L "/proc/$pid/root" ]; then
                readlink "/proc/$pid/root" 2>/dev/null || echo "Нет доступа"
            else
                echo "Нет доступа"
            fi
            ;;
            
        *)
            echo "Неизвестный параметр. Доступные параметры:"
            echo "cmdline, environ, limits, status, mounts, cwd, fd, root"
            ;;
    esac
}

# Тестирование на нескольких процессах
echo -e "\nВыберите PID для анализа:"
read -p "PID: " selected_pid

echo -e "\nВыберите параметр для просмотра:"
echo "1) cmdline - командная строка"
echo "2) environ - переменные окружения"
echo "3) limits - лимиты процесса"
echo "4) status - статус процесса"
echo "5) mounts - точки монтирования"
echo "6) cwd - текущая рабочая директория"
echo "7) fd - файловые дескрипторы"
echo "8) root - корневая директория"
echo "9) все параметры"

read -p "Выбор (1-9): " choice

echo -e "\n"$(printf '=%.0s' {1..60})"\n"

case $choice in
    1) get_process_params "$selected_pid" "cmdline" ;;
    2) get_process_params "$selected_pid" "environ" ;;
    3) get_process_params "$selected_pid" "limits" ;;
    4) get_process_params "$selected_pid" "status" ;;
    5) get_process_params "$selected_pid" "mounts" ;;
    6) get_process_params "$selected_pid" "cwd" ;;
    7) get_process_params "$selected_pid" "fd" ;;
    8) get_process_params "$selected_pid" "root" ;;
    9) 
        for param in cmdline environ limits status mounts cwd fd root; do
            get_process_params "$selected_pid" "$param"
            echo -e "\n"$(printf '=%.0s' {1..60})"\n"
        done
        ;;
    *) echo "Неверный выбор" ;;
esac
