from flask import Flask, render_template, request, flash
from scapy.all import AsyncSniffer
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Необходимо для использования flash-сообщений

# Регулярное выражение для проверки подсети
subnet_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$')

# Глобальная переменная для сниффера
sniffer = None

@app.route('/', methods=['GET', 'POST'])
def index():
    global sniffer
    subnet = None

    if request.method == 'POST':
        subnet = request.form.get('subnet')
        
        # Проверка на корректность подсети
        if subnet and subnet_pattern.match(subnet):
            if request.form.get('start'):
                if sniffer is None or not sniffer.running:
                    sniffer = AsyncSniffer(filter=f'net {subnet}')
                    sniffer.start()
                    flash('Сниффер запущен!', 'success')
                else:
                    flash('Сниффер уже запущен!', 'warning')
            elif request.form.get('stop'):
                if sniffer and sniffer.running:
                    sniffer.stop()
                    flash('Сниффер остановлен!', 'success')
                else:
                    flash('Сниффер не запущен!', 'warning')
        else:
            flash('Некорректный формат подсети. Используйте формат: 192.168.1.0/24', 'danger')

    return render_template('index.html', subnet=subnet)

if __name__ == '__main__':
    app.run(debug=True, host='10.8.0.1')