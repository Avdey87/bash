# Сначала исправим права на лог-файл
sudo touch /var/log/process_monitor.log
sudo chmod 666 /var/log/process_monitor.log

# Проверим синтаксис скрипта
bash -n /opt/scripts/process_monitor_cron.sh

# Запустим скрипт с sudo
sudo bash /opt/scripts/process_monitor_cron.sh

# Проверим лог
cat /var/log/process_monitor.log
