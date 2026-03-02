#!/bin/bash

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
        readlink "/proc/$pid/exe" 2
