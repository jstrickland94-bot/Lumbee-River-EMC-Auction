FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install flask gunicorn
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:10000", "app:app"]