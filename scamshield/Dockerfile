FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY scamshield ./scamshield
RUN pip install --no-cache-dir .
VOLUME ["/app/state"]
EXPOSE 8080
CMD ["scamshield", "serve"]
