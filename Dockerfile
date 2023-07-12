# Izaberite sliku sa kojom ćete raditi
FROM python:3.9

# Postavite radni direktorijum u kontejneru
WORKDIR /app

# Kopirajte zavisnosti
COPY requirements.txt .

# Instalirajte sve zavisnosti
RUN pip install -r requirements.txt

# Kopirajte ostatak koda
COPY . .

# Izložite port koji vaša aplikacija koristi
EXPOSE 5000

# Postavite komandu koja će se izvršiti kada se kontejner pokrene
CMD ["python", "run.py"]
