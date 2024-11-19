FROM python:3.9-slim
WORKDIR /app

# Install dependencies
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Run the Flask app
CMD ["python3", "app.py"]