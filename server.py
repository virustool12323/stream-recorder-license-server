# server.py
from flask import Flask, request, jsonify
import sqlite3
import hashlib
import time
import os
import logging
import sys
import secrets
import datetime

# --- Konfiguracja ---
# Użyj zmiennej środowiskowej dla klucza secretnego, domyślnie wygeneruj losowy
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Użyj zmiennej środowiskowej dla nazwy pliku bazy danych
DB_NAME = os.environ.get('DATABASE_URL', 'licenses.db')

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# --- Funkcje pomocnicze do bazy danych ---

def init_db():
    """Inicjalizuje bazę danych SQLite."""
    logger.info(f"Inicjalizacja bazy danych: {DB_NAME}")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Tabela licencji
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            max_activations INTEGER NOT NULL DEFAULT 1,
            is_revoked BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabela aktywacji
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            machine_id TEXT NOT NULL,
            activation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (license_id) REFERENCES licenses (id) ON DELETE CASCADE,
            UNIQUE(license_id, machine_id)
        )
    ''')
    
    # Tabela do przechowywania ważnych kluczy (np. dla testów)
    # W produkcji klucze powinny być generowane i zarządzane bezpiecznym systemem
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS valid_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Baza danych zainicjalizowana pomyślnie.")

def add_license_key(license_key, max_activations=1):
    """(Pomocnicze) Dodaje klucz licencyjny do bazy danych."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO licenses (license_key, max_activations) VALUES (?, ?)", (license_key, max_activations))
        conn.commit()
        logger.info(f"Klucz {license_key} dodany/zaktualizowany w bazie danych.")
    except sqlite3.Error as e:
        logger.error(f"Błąd podczas dodawania klucza {license_key}: {e}")
    finally:
        conn.close()

def add_valid_key_for_testing(license_key):
    """(Pomocnicze) Dodaje klucz do tabeli valid_keys dla testów."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO valid_keys (license_key) VALUES (?)", (license_key,))
        conn.commit()
        logger.info(f"Klucz testowy {license_key} dodany do valid_keys.")
    except sqlite3.Error as e:
        logger.error(f"Błąd podczas dodawania klucza testowego {license_key}: {e}")
    finally:
        conn.close()

# --- Logika API ---

def verify_activation_key(key, machine_id):
    """
    Weryfikuje klucz aktywacyjny i przetwarza aktywację.
    Zwraca słownik z 'status' ('success' lub 'error') i 'message'.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # 1. Sprawdź, czy klucz istnieje i nie jest unieważniony w głównej tabeli
        cursor.execute("SELECT id, max_activations, is_revoked FROM licenses WHERE license_key = ?", (key,))
        result = cursor.fetchone()

        if result:
            license_id, max_activations, is_revoked = result

            if is_revoked:
                logger.warning(f"Próba aktywacji unieważnionego klucza: {key}")
                return {"status": "error", "message": "Kod aktywacyjny został unieważniony."}

            # 2. Sprawdź, czy klucz jest już przypisany do tego komputera
            cursor.execute("SELECT 1 FROM activations WHERE license_id = ? AND machine_id = ?", (license_id, machine_id))
            if cursor.fetchone():
                logger.info(f"Aktywacja potwierdzona dla istniejącego wpisu: {key} na {machine_id}")
                return {"status": "success", "message": "Aktywacja potwierdzona dla tego komputera."}

            # 3. Sprawdź ogólny limit aktywacji
            cursor.execute("SELECT COUNT(*) FROM activations WHERE license_id = ?", (license_id,))
            current_activations = cursor.fetchone()[0]

            if current_activations >= max_activations:
                logger.warning(f"Przekroczony limit aktywacji dla klucza {key}. Użyte: {current_activations}, Limit: {max_activations}")
                return {"status": "error", "message": f"Limit aktywacji ({max_activations}) dla tego kodu został przekroczony."}

            # 4. Jeśli wszystko OK i nie był wcześniej aktywowany na tym komputerze: zarejestruj nową aktywację
            cursor.execute("INSERT INTO activations (license_id, machine_id) VALUES (?, ?)", (license_id, machine_id))
            conn.commit()
            logger.info(f"Udana aktywacja nowego wpisu: {key} na {machine_id}")
            return {"status": "success", "message": "Aktywacja udana."}
        
        else:
            # 5. Jeśli nie znaleziono w 'licenses', sprawdź w 'valid_keys' (dla testów)
            cursor.execute("SELECT 1 FROM valid_keys WHERE license_key = ?", (key,))
            if cursor.fetchone():
                # Symulacja udanej aktywacji dla klucza testowego
                # W rzeczywistości nie zapisujemy tego w 'activations', bo to tylko do testów
                logger.info(f"Udana symulacja aktywacji dla klucza testowego: {key}")
                return {"status": "success", "message": "Aktywacja testowa udana (symulacja)."}
            else:
                logger.warning(f"Nieprawidłowy klucz: {key}")
                return {"status": "error", "message": "Nieprawidłowy kod aktywacyjny."}

    except sqlite3.Error as e:
        logger.error(f"Błąd bazy danych podczas weryfikacji klucza {key}: {e}")
        return {"status": "error", "message": "Błąd serwera podczas weryfikacji klucza."}
    except Exception as e:
        logger.error(f"Nieoczekiwany błąd podczas weryfikacji klucza {key}: {e}")
        return {"status": "error", "message": "Wystąpił nieoczekiwany błąd serwera."}
    finally:
        if conn:
            conn.close()

# --- Endpointy API ---

@app.route('/health', methods=['GET'])
def health_check():
    """Prosty endpoint do sprawdzania stanu serwera."""
    logger.info("Health check")
    return jsonify({"status": "healthy", "timestamp": datetime.datetime.utcnow().isoformat()})

@app.route('/activate', methods=['POST'])
def activate():
    """Endpoint do aktywacji produktu."""
    logger.info("Otrzymano żądanie aktywacji")
    
    # 1. Pobierz dane z żądania
    data = request.get_json()
    if not data:
        logger.warning("Brak danych JSON w żądaniu")
        return jsonify({"status": "error", "message": "Brak danych JSON w żądaniu."}), 400

    key = data.get('key')
    machine_id = data.get('machine_id')

    if not key or not machine_id:
        logger.warning("Brak wymaganych danych (key, machine_id) w żądaniu")
        return jsonify({"status": "error", "message": "Brak wymaganych danych (key, machine_id)."}), 400

    # 2. Przetwórz aktywację
    result = verify_activation_key(key, machine_id)
    
    # 3. Zaloguj wynik
    if result['status'] == 'success':
        logger.info(f"Wynik aktywacji: {result['message']} dla klucza {key[:8]}... na maszynie {machine_id[:8]}...")
    else:
        logger.warning(f"Wynik aktywacji: {result['message']} dla klucza {key[:8]}... na maszynie {machine_id[:8]}...")
    
    # 4. Zwróć odpowiedź
    return jsonify(result)

# --- Inicjalizacja ---

if __name__ == '__main__':
    # Inicjalizuj bazę danych przy starcie
    init_db()
    
    # (Opcjonalnie) Dodaj przykładowy klucz testowy do bazy (usuń przed produkcją)
    # add_valid_key_for_testing("TEST-VALID-KEY")
    
    # Uruchom aplikację Flask
    # Uwaga: Dla Render, serwer (np. Gunicorn) uruchamia aplikację inaczej.
    # Ten blok 'if __name__...' jest głównie dla lokalnego testowania.
    logger.info("Uruchamianie serwera Flask...")
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=False)
