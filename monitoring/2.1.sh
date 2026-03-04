#!/bin/bash

# Упрощенный скрипт для просмотра /proc/bus/input/

echo "========================================================"
echo "   ПРОСМОТР ДИРЕКТОРИИ /proc/bus/input/"
echo "========================================================"
echo

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

# 1. Содержимое директории
echo "1. СОДЕРЖИМОЕ ДИРЕКТОРИИ:"
echo "------------------------"
ls -la /proc/bus/input/
echo

# 2. Содержимое файла devices
echo "2. УСТРОЙСТВА ВВОДА (первые 20 строк):"
echo "------------------------"
head -20 /proc/bus/input/devices 2>/dev/null || echo "Файл devices недоступен"
echo

# 3. Содержимое файла handlers
echo "3. ОБРАБОТЧИКИ ВВОДА:"
echo "------------------------"
cat /proc/bus/input/handlers 2>/dev/null || echo "Файл handlers недоступен"
echo

# 4. Статистика
echo "4. СТАТИСТИКА:"
echo "------------------------"
devices_count=$(grep -c "^I:" /proc/bus/input/devices 2>/dev/null || echo "0")
handlers_count=$(wc -l < /proc/bus/input/handlers 2>/dev/null || echo "0")
echo "Всего устройств ввода: $devices_count"
echo "Всего обработчиков: $handlers_count"

# 5. Сохранение в файл
output_file="proc_input_$(date +%Y%m%d_%H%M%S).txt"
cp /proc/bus/input/devices "$output_file" 2>/dev/null && \
    echo -e "\nИнформация сохранена в файл: $output_file"
