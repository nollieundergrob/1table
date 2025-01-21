# Используем официальный образ Python
FROM python:3.10-bookworm

# Устанавливаем зависимости для сборки Python-пакетов (если нужны)
RUN apt-get update && apt-get install -y gcc python3-dev

# Создаем рабочую директорию
WORKDIR /app

# Копируем зависимости и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY . .

# Создаем файл базы данных (если нужно)
RUN touch db.sqlite3

# Команда для запуска сервера
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]