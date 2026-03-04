#!/bin/bash

# Упрощенный скрипт для разбора данных из /proc/bus/input/ по столбцам
# С использованием циклов

echo "========================================================"
echo "   РАЗБОР ДАННЫХ /proc/bus/input/ ПО СТОЛБЦАМ"
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

# 1. Содержимое директории с разбивкой по столбцам
echo "1. СОДЕРЖИМОЕ ДИРЕКТОРИИ (разбивка по столбцам):"
echo "------------------------"

# Используем цикл для чтения вывода ls построчно
ls -la /proc/bus/input/ 2>/dev/null | while read -r line; do
    # Пропускаем строку "total"
    if [[ $line == total* ]]; then
        continue
    fi
    
    # Разбиваем строку на столбцы
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    month=$(echo "$line" | awk '{print $6}')
    day=$(echo "$line" | awk '{print $7}')
    time=$(echo "$line" | awk '{print $8}')
    name=$(echo "$line" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=""; print $0}' | sed 's/^[ \t]*//')
    
    echo "Права: $permissions | Владелец: $owner | Группа: $group | Размер: $size | Имя: $name"
done
echo

# 2. Разбор файла devices по столбцам
echo "2. УСТРОЙСТВА ВВОДА (разбивка по строкам и столбцам):"
echo "------------------------"

if [ -f "/proc/bus/input/devices" ] && [ -r "/proc/bus/input/devices" ]; then
    line_num=0
    
    # Используем цикл для чтения файла построчно
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        
        # Определяем тип строки по первому символу
        line_type=$(echo "$line" | cut -c1)
        
        case $line_type in
            I)
                # Разбираем строку с информацией об устройстве
                bus=$(echo "$line" | grep -o "Bus=[0-9a-fA-F]\+" | cut -d= -f2)
                vendor=$(echo "$line" | grep -o "Vendor=[0-9a-fA-F]\+" | cut -d= -f2)
                product=$(echo "$line" | grep -o "Product=[0-9a-fA-F]\+" | cut -d= -f2)
                echo "[$line_num] УСТРОЙСТВО: Bus=$bus | Vendor=$vendor | Product=$product"
                ;;
            N)
                # Извлекаем имя устройства
                name=$(echo "$line" | grep -o 'Name="[^"]*"' | cut -d'"' -f2)
                echo "      Имя: $name"
                ;;
            P)
                # Физический путь
                phys=$(echo "$line" | cut -c4-)
                echo "      Phys: $phys"
                ;;
            H)
                # Обработчики
                handlers=$(echo "$line" | cut -c4-)
                echo "      Обработчики: $handlers"
                ;;
            B)
                # Возможности устройства
                prop=$(echo "$line" | grep -o "PROP=[0-9a-fA-F]\+" | cut -d= -f2)
                ev=$(echo "$line" | grep -o "EV=[0-9a-fA-F]\+" | cut -d= -f2)
                echo "      PROP=$prop | EV=$ev"
                ;;
        esac
    done < /proc/bus/input/devices
    
    # Подсчет количества устройств с помощью цикла
    device_count=0
    while IFS= read -r line; do
        if [[ $line == I:* ]]; then
            device_count=$((device_count + 1))
        fi
    done < /proc/bus/input/devices
    
    echo "------------------------"
    echo "Всего устройств: $device_count"
    echo
else
    echo "Файл devices недоступен"
fi

# 3. Разбор файла handlers по столбцам
echo "3. ОБРАБОТЧИКИ ВВОДА (разбивка по столбцам):"
echo "------------------------"

if [ -f "/proc/bus/input/handlers" ] && [ -r "/proc/bus/input/handlers" ]; then
    handler_num=0
    
    # Используем цикл для чтения файла построчно
    while IFS= read -r line; do
        handler_num=$((handler_num + 1))
        
        # Разбиваем строку на части
        # Пример строки: N: Number kbd
        name_part=$(echo "$line" | awk '{print $3}')
        minor=$(echo "$line" | grep -o "\[[0-9]\+\]" | tr -d '[]')
        
        if [ -n "$minor" ]; then
            echo "Обработчик #$handler_num: $name_part | Минорный номер: $minor"
        else
            echo "Обработчик #$handler_num: $line"
        fi
    done < /proc/bus/input/handlers
    
    echo "------------------------"
    echo "Всего обработчиков: $handler_num"
    echo
else
    echo "Файл handlers недоступен"
fi

# 4. Создание сводной таблицы с помощью циклов
echo "4. СВОДНАЯ ТАБЛИЦА УСТРОЙСТВ:"
echo "------------------------"

if [ -f "/proc/bus/input/devices" ] && [ -r "/proc/bus/input/devices" ]; then
    # Используем временные переменные для сбора информации
    current_device=0
    device_name=""
    device_handlers=""
    
    # Заголовок таблицы
    printf "%-5s | %-30s | %-30s\n" "№" "ИМЯ УСТРОЙСТВА" "ОБРАБОТЧИКИ"
    echo "----------------------------------------------------------------------"
    
    # Читаем файл и собираем информацию по каждому устройству
    while IFS= read -r line; do
        if [[ $line == I:* ]]; then
            # Если это новое устройство и есть данные от предыдущего - выводим
            if [ $current_device -gt 0 ]; then
                printf "%-5s | %-30s | %-30s\n" "$current_device" "${device_name:0:30}" "${device_handlers:0:30}"
            fi
            
            # Начинаем новое устройство
            current_device=$((current_device + 1))
            device_name=""
            device_handlers=""
            
        elif [[ $line == N:* ]]; then
            device_name=$(echo "$line" | grep -o 'Name="[^"]*"' | cut -d'"' -f2)
            
        elif [[ $line == H:* ]]; then
            device_handlers=$(echo "$line" | cut -c4-)
        fi
    done < /proc/bus/input/devices
    
    # Выводим последнее устройство
    if [ $current_device -gt 0 ]; then
        printf "%-5s | %-30s | %-30s\n" "$current_device" "${device_name:0:30}" "${device_handlers:0:30}"
    fi
    
    echo "----------------------------------------------------------------------"
    echo "Всего устройств в таблице: $current_device"
    echo
    
    # 5. Дополнительный анализ с вложенными циклами
    echo "5. АНАЛИЗ ТИПОВ УСТРОЙСТВ (вложенные циклы):"
    echo "------------------------"
    
    # Сбрасываем переменные для нового прохода
    current_device=0
    device_name=""
    device_handlers=""
    
    # Внешний цикл - по устройствам
    while IFS= read -r line; do
        if [[ $line == I:* ]]; then
            # Если есть предыдущее устройство - анализируем его
            if [ $current_device -gt 0 ] && [ -n "$device_handlers" ]; then
                echo "Устройство #$current_device: ${device_name:-Неизвестно}"
                
                # Внутренний цикл - по обработчикам
                # Разбиваем строку обработчиков на отдельные слова
                for handler in $device_handlers; do
                    case $handler in
                        *kbd*)
                            echo "  → Поддерживает клавиатуру"
                            ;;
                        *mouse*)
                            echo "  → Поддерживает мышь"
                            ;;
                        *event*)
                            echo "  → Генерирует события"
                            ;;
                        *js*)
                            echo "  → Джойстик"
                            ;;
                    esac
                done
                echo
            fi
            
            # Новое устройство
            current_device=$((current_device + 1))
            device_name=""
            device_handlers=""
            
        elif [[ $line == N:* ]]; then
            device_name=$(echo "$line" | grep -o 'Name="[^"]*"' | cut -d'"' -f2)
            
        elif [[ $line == H:* ]]; then
            device_handlers=$(echo "$line" | cut -c4-)
        fi
    done < /proc/bus/input/devices
    
    # Анализ последнего устройства
    if [ $current_device -gt 0 ] && [ -n "$device_handlers" ]; then
        echo "Устройство #$current_device: ${device_name:-Неизвестно}"
        for handler in $device_handlers; do
            case $handler in
                *kbd*) echo "  → Поддерживает клавиатуру" ;;
                *mouse*) echo "  → Поддерживает мышь" ;;
                *event*) echo "  → Генерирует события" ;;
                *js*) echo "  → Джойстик" ;;
            esac
        done
    fi
fi

# Сохранение результатов в файл
echo
echo "------------------------"
echo "6. СОХРАНЕНИЕ РЕЗУЛЬТАТОВ"

output_file="input_parsed_$(date +%Y%m%d_%H%M%S).txt"

{
    echo "РЕЗУЛЬТАТЫ РАЗБОРА /proc/bus/input/ ПО СТОЛБЦАМ"
    echo "=================================================="
    echo "Дата: $(date)"
    echo "Хост: $(hostname)"
    echo
    echo "1. СОДЕРЖИМОЕ ДИРЕКТОРИИ:"
    ls -la /proc/bus/input/
    echo
    echo "2. УСТРОЙСТВА ВВОДА:"
    cat /proc/bus/input/devices 2>/dev/null || echo "Нет доступа"
    echo
    echo "3. ОБРАБОТЧИКИ ВВОДА:"
    cat /proc/bus/input/handlers 2>/dev/null || echo "Нет доступа"
} > "$output_file"

echo "Результаты сохранены в файл: $output_file"
echo "Размер файла: $(du -h "$output_file" | cut -f1)"

echo
echo "Анализ завершен!"
