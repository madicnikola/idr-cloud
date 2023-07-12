# Koristimo zvanični Python obraz iz Docker Hub-a
FROM python:3.9-slim-buster

# Postavimo radni direktorijum u kontejneru
WORKDIR /app

# Kopiramo zavisnosti projekta u radni direktorijum
COPY requirements.txt ./

# Instaliramo zavisnosti projekta
RUN pip install --no-cache-dir -r requirements.txt

# Kopiramo ostatak koda u radni direktorijum
COPY . .

# Definiramo komandu za pokretanje aplikacije
CMD ["python", "run.py"]
