"""
Moduł konfiguracyjny
Cel: Odpowiada za wczytanie pliku ustawień (config.yaml), jego walidacje
oraz automatyczne wykrycie podsieci (jeśli użytkownik zlecił to systemowi).
Jest to pierwszy moduł, który uruchamia się przed skanowanie,
który nie przepuści aplikacji dalej, jeśli ustawienia są błędne.
"""

import json
import logging
import os
import subprocess
import sys

# Biblioteka PyYAML (wymaga doinstalowania przez pip) - standard do czytania plików YAML w Pythonie.
import yaml

# Zabezpieczenie na wypadek, gdyby automatyczne wykrywanie sieci całkowicie zawiodło.
# Ustawiamy najpopularniejszą podsieć używaną przez oprogramowanie VirtualBox/MikroTik.
DEFAULT_SUBNET = "192.168.56.0/24"  

# Zabezpieczenie przed literówkami użytkownika (np. wpisaniem "stndard" zamiast "standard").
VALID_PROFILES = ("quick", "standard", "deep")


def detect_subnet():
    """
    Funkcja próbująca samodzielnie wywnioskować, w jakiej sieci znajduje się kontener.
    Zamiast używać trudnych w parsowaniu tekstowych komend, zmuszamy systemowego Linuksa
    do wyplucia tablicy routingu w czystym formacie JSON ('ip -j route').
    """
    try:
        # subprocess.run to najbezpieczniejszy sposób wywoływania komend systemowych w Pythonie.
        # timeout=5 zapobiega zawieszeniu się skryptu w nieskończoność, jeśli komenda sie zawiesi.
        result = subprocess.run(
            ["ip", "-j", "route"],
            capture_output=True, text=True, timeout=5
        )
        
        # returncode != 0 oznacza, że komenda zakończyła się błędem (np. brak uprawnień)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
            
        routes = json.loads(result.stdout)
        
        # Szukamy pierwszej dostępnej podsieci, w której aktualnie znajduje się nasz interfejs.
        for r in routes:
            dst = r.get("dst", "")
            # Ignorujemy główną bramę internetową ('default'), interesują nas tylko lokalne podsieci (z ukośnikiem '/')
            if "/" in dst and dst != "default":
                return dst
                
    # Łapiemy każdą możliwą awarię (brak komendy, zły format, timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, RuntimeError) as e:
        # Fallback: zamiast wywalać całą aplikację krytycznym błędem, zgłaszamy ostrzeżenie
        # i podstawiamy twardo wpisaną, bezpieczną wartość.
        logging.warning("Nie udało się wykryć podsieci automatycznie (%s), używam %s", e, DEFAULT_SUBNET)
    
    return DEFAULT_SUBNET


def _require(cfg, key):
    """
    Funkcja pomocnicza typu 'Fail-Fast'.
    Sprawdza czy wymagany klucz znajduje się na najwyższym poziomie pliku YAML.
    Jeśli go brakuje, natychmiast wyrzuca wyjątek przerywający działanie programu.
    """
    if key not in cfg:
        raise ValueError(f"Brakuje pola '{key}' w config.yaml")
    return cfg[key]


def _require_nested(cfg, *keys):
    """
    Bardziej zaawansowana funkcja sprawdzająca tzw. klucze zagnieżdżone (drzewo).
    Pozwala upewnić się, że istnieje cała ścieżka, np. sprawdzając pole 'smtp.server'.
    Dzięki pętli jest odporna na sprawdzanie dowolnie głębokich zagnieżdżeń (np. 'a.b.c.d').
    """
    cur = cfg
    path = []
    for k in keys:
        path.append(k) # Zapisujemy ścieżkę do wyświetlenia błędu dla użytkownika
        # Sprawdzamy czy obecny węzeł w ogóle jest słownikiem i czy zawiera nasz klucz
        if not isinstance(cur, dict) or k not in cur:
            raise ValueError(f"Brakuje pola '{'.'.join(path)}' w config.yaml")
        # Przeskakujemy głębiej do następnego węzła
        cur = cur[k]
    return cur


def load_config(path="config.yaml"):
    """
    Główna funkcja tego modułu. Czyta plik z dysku, weryfikuje jego strukturę i zwraca gotowy słownik z danymi.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Plik {path} nie istnieje. Skopiuj config.yaml.example i uzupełnij.")

    # encoding="utf-8" gwarantuje, że skrypt nie "wybuchnie", jeśli wpisałeś w pliku polskie znaki
    with open(path, "r", encoding="utf-8") as f:
        # Używamy safe_load (zamiast zwykłego load), co jest absolutną podstawą cyberbezpieczeństwa.
        cfg = yaml.safe_load(f)

    # Upewniamy się, że plik nie jest pusty ani nie jest zwykłą listą
    if not isinstance(cfg, dict):
        raise ValueError("config.yaml musi zawierać słownik (mapping)")

    # 1. Walidacja głównych ustawień logicznych
    profile = _require(cfg, "profile")
    if profile not in VALID_PROFILES:
        raise ValueError(f"Nieznany profil '{profile}'. Dozwolone: {VALID_PROFILES}")

    # 2. Walidacja sekcji odpowiedzialnej za wysyłanie e-maili
    _require_nested(cfg, "smtp", "server")
    port = _require_nested(cfg, "smtp", "port")
    # Port nie może być stringiem ("465"), musi być prawdziwą liczbą (465) by Python mógł się połączyć
    if not isinstance(port, int):
        raise ValueError("smtp.port musi być liczbą całkowitą")
    _require_nested(cfg, "smtp", "user")
    _require_nested(cfg, "smtp", "password")
    _require_nested(cfg, "smtp", "admin_email")
    
    # 3. Walidacja sekcji z logiką skanera
    _require_nested(cfg, "scan", "output_dir")
    _require_nested(cfg, "scan", "baseline_file")

    # 4. Automatyczne wykrywanie sieci. 
    # Jeśli instalator wrzucił słowo 'auto', system przejmuje kontrolę.
    subnet = cfg.get("subnet", "auto")
    if subnet == "auto":
        cfg["subnet"] = detect_subnet()
        logging.info("Wykryta podsieć: %s", cfg["subnet"])
    else:
        cfg["subnet"] = subnet

    # Na wszelki wypadek każemy systemowi utworzyć folder na zrzuty z Nmapa,
    # zanim jakikolwiek inny skrypt spróbuje coś tam zapisać (exist_ok zapobiega błędom, gdy folder już istnieje).
    os.makedirs(cfg["scan"]["output_dir"], exist_ok=True)

    return cfg


# Blok testowo-diagnostyczny (uruchamiany tylko jeśli wywołasz ten plik ręcznie w terminalu)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        cfg = load_config()
    except (FileNotFoundError, ValueError) as e:
        # Wypisujemy błędy na czerwono (stderr), żeby były lepiej widoczne dla administratora
        print(f"Błąd konfiguracji: {e}", file=sys.stderr)
        sys.exit(1)
        
    # Tworzymy kopię załadowanych ustawień tylko po to, by wydrukować je na ekranie dla testów.
    # Używamy głębokiej kopii (dict(cfg["smtp"])), aby nadpisanie hasła w tym miejscu
    # nie nadpisało oryginalnego hasła w pamięci głównego programu (choć tutaj to i tak tylko test).
    safe = dict(cfg)
    safe["smtp"] = dict(cfg["smtp"])
    safe["smtp"]["password"] = "***" # Maskowanie tajnego hasła aplikacji
    
    # Wydrukowanie na ekranie tego, co widzi Python
    print(json.dumps(safe, indent=2, ensure_ascii=False))
