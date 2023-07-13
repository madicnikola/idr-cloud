# Koristimo zvanični Python obraz iz Docker Hub-a
FROM python:3.9-slim-buster as base


FROM base as account-api
# Postavimo radni direktorijum u kontejneru
WORKDIR /account-api/app
# Kopiramo zavisnosti projekta u radni direktorijum
COPY requirements.txt ./
# Instaliramo zavisnosti projekta
RUN pip install --no-cache-dir -r requirements.txt

# Kopiramo ostatak koda u radni direktorijum
COPY /account-api .

# Definiramo komandu za pokretanje aplikacije
CMD ["python", "run.py"]


FROM base as marketplace-courier
# Postavimo radni direktorijum u kontejneru
WORKDIR /marketplace-courier/app
# Kopiramo zavisnosti projekta u radni direktorijum
COPY requirements.txt ./
# Instaliramo zavisnosti projekta
RUN pip install --no-cache-dir -r requirements.txt

# Kopiramo ostatak koda u radni direktorijum
COPY /marketplace-courier .

# Definiramo komandu za pokretanje aplikacije
CMD ["python", "run.py"]

FROM base as marketplace-customer
# Postavimo radni direktorijum u kontejneru
WORKDIR /marketplace-customer/app
# Kopiramo zavisnosti projekta u radni direktorijum
COPY requirements.txt ./
# Instaliramo zavisnosti projekta
RUN pip install --no-cache-dir -r requirements.txt

# Kopiramo ostatak koda u radni direktorijum
COPY /marketplace-customer .

# Definiramo komandu za pokretanje aplikacije
CMD ["python", "run.py"]

FROM base as marketplace-owner
# Postavimo radni direktorijum u kontejneru
WORKDIR /marketplace-owner/app
# Kopiramo zavisnosti projekta u radni direktorijum
COPY requirements.txt ./
# Instaliramo zavisnosti projekta
RUN pip install --no-cache-dir -r requirements.txt

# Kopiramo ostatak koda u radni direktorijum
COPY /marketplace-owner .

# Definiramo komandu za pokretanje aplikacije
CMD ["python", "run.py"]