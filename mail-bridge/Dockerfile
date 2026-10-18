FROM python:3.12.14-slim
WORKDIR /app
COPY server.py http_server.py oauth.py /app/
RUN useradd --uid 10001 --create-home bridge && mkdir /data && chown bridge /data
USER bridge
ENV MAIL_BRIDGE_BIND=0.0.0.0 PORT=8080 LOCALAPPDATA=/data
EXPOSE 8080
CMD ["python", "-u", "http_server.py"]
