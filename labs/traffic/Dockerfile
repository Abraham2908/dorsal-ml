FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests==2.32.3

COPY legit_traffic.py /app/legit_traffic.py
COPY ai_redteam_agent.py /app/ai_redteam_agent.py

CMD ["python", "/app/legit_traffic.py"]
