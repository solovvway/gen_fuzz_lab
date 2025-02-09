import matplotlib.pyplot as plt
from ping3 import ping
import time

def get_timeout(target):
    response_time = ping(target)
    return response_time

def collect_ping_data(target, duration):
    start_time = time.time()
    x_data = []
    y_data = []
    
    while time.time() - start_time < duration:
        response_time = get_timeout(target)
        current_time = time.time() - start_time  # Время относительно начала
        if response_time is not None:
            x_data.append(current_time)  # Время в секундах
            y_data.append(response_time * 1000)  # Переводим в миллисекунды
            print(f"Time: {current_time:.2f} s, Response Time: {response_time * 1000:.2f} ms")
        else:
            print("Ping failed, no response.")
        
        time.sleep(1)  # Пауза между пингами

    return x_data, y_data

def plot_ping_data(x_data, y_data, target):
    plt.figure(figsize=(10, 5))
    plt.plot(x_data, y_data, marker='o', linestyle='-', color='blue')
    plt.title(f'Ping Response Time to {target}')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Response Time (ms)')
    plt.ylim(0, max(200, max(y_data) * 1.1))  # Устанавливаем пределы по оси Y
    plt.grid()
    plt.savefig('ping_response_time.png')  # Сохраняем график как изображение
    plt.close()  # Закрываем фигуру

if __name__ == '__main__':
    target_ip = '8.8.8.8'  # Замените на нужный IP-адрес
    duration = 30  # Длительность сбора данных в секундах
    x_data, y_data = collect_ping_data(target_ip, duration)
    plot_ping_data(x_data, y_data, target_ip)