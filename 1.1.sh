#!/bin/bash

# Скрипт для просмотра /proc и записи номерных директорий

echo "Просмотр директории /proc и поиск номерных директорий (PID)"
echo "=========================================================="

# Поиск всех номерных директорий в /proc
pid_dirs=$(ls -la /proc/ | grep '^d' | grep -E '[0-9]+' | awk '{print $9}' | sort -n)

# Подсчет количества найденных процессов
count=0

echo "Найденные PID директории:"
echo "------------------------"

# Вывод первых 20 PID для примера
for pid in $pid_dirs; do
    echo "PID: $pid"
    count=$((count + 1))
    if [ $count -ge 20 ]; then
        echo "... и еще $(($(echo "$pid_dirs" | wc -l) - 20)) процессов"
        break
    fi
done

echo "------------------------"
echo "Всего найдено процессов: $(echo "$pid_dirs" | wc -l)"

# Запись в файл
echo "$pid_dirs" > found_pids.txt
echo "Список PID сохранен в файл found_pids.txt"
