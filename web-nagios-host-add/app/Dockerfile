FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Add 'docker' SDK so restart can use the Docker socket
RUN pip install --no-cache-dir flask waitress docker

COPY app.py /app/app.py

EXPOSE 8088
CMD ["waitress-serve", "--host=0.0.0.0", "--port=8088", "app:app"]
