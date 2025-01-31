from flask import Flask, render_template, request, flash
from scapy.all import sniff, wrpcap
import re
import threading

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Необходимо для использования flash-сообщений

# Регулярное выражение для проверки подсети
subnet_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$')

# Глобальная переменная для сниффера
dump_file = 'capture.pcap'  # Имя файла для сохранения дампа
sniffer_thread = None  # Поток для сниффинга
dump = []  # Список для хранения захваченных пакетов

def start_sniffer(subnet):
    global dump
    dump = []  # Очистка предыдущих результатов
    sniff(filter=f'net {subnet}', prn=lambda x: dump.append(x), store=False)

@app.route('/', methods=['GET', 'POST'])
def index():
    global sniffer_thread, dump
    subnet = None

    if request.method == 'POST':
        subnet = request.form.get('subnet')
        
        # Проверка на корректность подсети
        if subnet and subnet_pattern.match(subnet):
            if request.form.get('start'):
                if sniffer_thread is None or not sniffer_thread.is_alive():
                    sniffer_thread = threading.Thread(target=start_sniffer, args=(subnet,))
                    sniffer_thread.start()
                    flash('Сниффер запущен!', 'success')
                else:
                    flash('Сниффер уже запущен!', 'warning')
            elif request.form.get('stop'):
                if sniffer_thread and sniffer_thread.is_alive():
                    # Остановка сниффера
                    sniffer_thread.join(timeout=1)  # Ждем завершения потока
                    flash('Сниффер остановлен!', 'info')
                    save_dump = request.form.get('save_dump')
                    if save_dump:
                        wrpcap(dump_file, dump)
                        flash(f'Дамп сохранен в {dump_file}', 'success')
                    else:
                        flash('Сниффер остановлен, но дамп не сохранен.', 'info')
                else:
                    flash('Сниффер не запущен!', 'warning')
        else:
            flash('Некорректный формат подсети. Используйте формат: 192.168.1.0/24', 'danger')

    return render_template('index.html', subnet=subnet, dump=dump)

if __name__ == '__main__':
    app.run(debug=True, host='10.8.0.1')