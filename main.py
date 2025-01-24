from flask import Flask, request, jsonify
import requests
import os
from datetime import datetime

app = Flask(__name__)

# Загрузка конфигурации из .env файла
from dotenv import load_dotenv

load_dotenv()

# Белый и черный списки
WHITELIST = ["trusted-source.com", "api.safe-source.net"]
BLACKLIST = ["malicious-site.com", "dangerous-source.net"]

# Внешний API для проверки репутации (например, VirusTotal)
EXTERNAL_REPUTATION_API = os.getenv("REPUTATION_API")  # URL внешнего API
EXTERNAL_API_KEY = os.getenv("API_KEY")  # API ключ для внешнего сервиса


# Логирование активности
def log_request(source, status):
    with open("source_logs.txt", "a") as log_file:
        log_file.write(
            f"{datetime.now()} - Source: {source}, Status: {status}\n")


# Проверка репутации источника
def check_source_reputation(source):
    # Сначала проверим в черном списке
    if source in BLACKLIST:
        return "blacklisted"

    # Проверим в белом списке
    if source in WHITELIST:
        return "trusted"

    # Если источник не найден в списках, проверяем через внешний API
    if EXTERNAL_REPUTATION_API:
        try:
            response = requests.get(
                EXTERNAL_REPUTATION_API,
                headers={"Authorization": f"Bearer {EXTERNAL_API_KEY}"},
                params={"source": source})
            if response.status_code == 200:
                data = response.json()
                if data.get("reputation") == "malicious":
                    return "blacklisted"
                elif data.get("reputation") == "safe":
                    return "trusted"
        except Exception as e:
            print(f"Error checking external API: {e}")

    # Если ничего не найдено, считаем источник подозрительным
    return "unknown"


# Основной API Endpoint
@app.route('/check_source', methods=['POST'])
def check_source():
    data = request.json
    source = data.get("source")

    if not source:
        return jsonify({"error": "Source is required"}), 400

    # Проверяем репутацию источника
    status = check_source_reputation(source)
    log_request(source, status)

    # Возвращаем результат проверки
    return jsonify({"source": source, "status": status})


# Блокировка источника
@app.route('/block_source', methods=['POST'])
def block_source():
    data = request.json
    source = data.get("source")

    if not source:
        return jsonify({"error": "Source is required"}), 400

    # Добавляем источник в черный список
    if source not in BLACKLIST:
        BLACKLIST.append(source)
        log_request(source, "blocked")
        return jsonify({"message": f"Source {source} has been blocked."})
    else:
        return jsonify({"message": f"Source {source} is already blocked."})


# Список заблокированных источников
@app.route('/blacklist', methods=['GET'])
def get_blacklist():
    return jsonify({"blacklist": BLACKLIST})


# Запуск сервиса
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
