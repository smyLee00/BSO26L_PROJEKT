"""
Moduł skanera (Scanner)
Cel: Silnik wykonawczy całego systemu. Odpowiada za fizyczne wysłanie pakietów sieciowych
za pomocą zewnętrznego narzędzia 'nmap'. Kontroluje jego parametry, limity czasowe
i zapisuje surowe wyniki do ustrukturyzowanego formatu XML (gotowego do parsowania).
"""

import logging
import os
import subprocess
import sys
import time

# Mapowanie profili na flagi Nmapa.
PROFILE_FLAGS = {
    # -T4: Agresywny timing (szybkie wysyłanie pakietów)
    # -F: Fast mode (skanuje tylko 100 najpopularniejszych portów zamiast 1000)
    "quick":    ["-T4", "-F"],
    
    # -sV: Service Version (próbuje rozpoznać dokładną wersję aplikacji, np. 'Apache 2.4')
    # -sC: Default Scripts (uruchamia bezpieczne skrypty rozpoznawcze z silnika NSE)
    "standard": ["-sV", "-sC"],
    
    # --script vuln: Wymusza użycie skryptów podatnościowych (Vulnerability).
    "deep":     ["-sV", "-sC", "--script", "vuln"],
}

# Timeout (wyłącznik bezpieczeństwa).
# Podsieć z zaporami (firewall) może powodować tzw. "blackholing", przez co Nmap zawiesiłby się 
# i skanował jedną maszynę przez wiele godzin. Zabezpieczamy kontener przez ucięcie procesu.
PROFILE_TIMEOUT = {
    "quick":    120,   # 2 minuty
    "standard": 600,   # 10 minut
    "deep":     1800,  # 30 minut
}


def run_scan(subnet, profile, output_dir):
    """
    Uruchamia podproces systemowy, czeka na jego zakończenie i weryfikuje wyniki.
    Zwraca bezwzględną ścieżkę do pliku *.xml lub None, jeśli wystąpiła awaria.
    """
    if profile not in PROFILE_FLAGS:
        logging.error("Nieznany profil skanowania: %s", profile)
        return None

    # Tworzymy folder na wyniki z flagą exist_ok=True, aby nie rzucało błędem, gdy folder już istnieje.
    os.makedirs(output_dir, exist_ok=True)
    
    # Generowanie unikalnej nazwy pliku ze stempla czasowego
    # Zabezpiecza to przed nadpisaniem wyników, jeśli odpalamy dwa skany pod rząd.
    ts = time.strftime("%Y%m%d_%H%M%S")
    xml_path = os.path.join(output_dir, f"scan_{ts}.xml")

    # Budujemy komendę w formie listy argumentów (najbezpieczniejszy sposób dla 'subprocess').
    # -oX wymusza na Nmapie zapis na dysk w formacie eXtensible Markup Language (XML).
    cmd = ["nmap"] + PROFILE_FLAGS[profile] + ["-oX", xml_path, subnet]
    
    # Zapisujemy do logów ostateczną komendę, by administrator mógł ją ew. odtworzyć ręcznie
    logging.info("Uruchamiam: %s", " ".join(cmd))

    try:
        # Zlecamy systemowi operacyjnemu odpalenie naszego polecenia
        result = subprocess.run(
            cmd,
            # capture_output przechwytuje wszystko to, co Nmap próbowałby wypluć na ekran.
            # Dzięki temu zachowujemy czysty terminal dla logów naszego własnego programu.
            capture_output=True, text=True,
            timeout=PROFILE_TIMEOUT[profile]
        )
        
    except FileNotFoundError:
        # Ten błąd wystąpi wtedy, gdy komenda 'nmap' w ogóle nie istnieje w systemie (brak paczki w Alpine/Linuksie).
        logging.error("Nmap nie znaleziony. Zainstaluj nmap albo uruchom kontener Docker.")
        return None
    except subprocess.TimeoutExpired:
        # Zegar dobił do limitu, proces zatrzymany przez Pythona.
        logging.error("Skanowanie przekroczyło limit czasu (%ds)", PROFILE_TIMEOUT[profile])
        return None

    # returncode != 0 oznacza, że program się zepsuł
    # .strip() usuwa ewentualne białe znaki z tyłu z błędu (stderr) dla czytelności.
    if result.returncode != 0:
        logging.error("Nmap zakończył błędem (kod %d): %s", result.returncode, result.stderr.strip())
        return None

    # Ostatni krok weryfikacji: Nmap mógł zakończyć się kodem '0', ale z powodu błędu praw zapisu 
    # (np. readonly filesystem w Dockerze) stworzył pusty plik o rozmiarze 0 bajtów.
    if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
        logging.error("Plik wynikowy %s nie powstał lub jest pusty", xml_path)
        return None

    logging.info("Skan zakończony. Wynik: %s", xml_path)
    return xml_path


#  Blok diagnostyczny (uruchamiany przy niezależnym wywołaniu z terminala)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    
    # Pozwalamy na wywołanie z argumentami: python scanner.py 192.168.1.0/24 deep
    subnet = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1" # Domyślnie skanuj samego siebie (loopback)
    profile = sys.argv[2] if len(sys.argv) > 2 else "quick"
    
    path = run_scan(subnet, profile, "/tmp/scans")
    
    # Zwracanie ścieżki na standardowe wyjście, jeśli ktoś chciałby chwycić wynik do powłoki bash (np. w zmiennej)
    if path:
        print(f"OK: {path}")
        sys.exit(0)
        
    # Gdy coś poszło nie tak
    print("Skanowanie nieudane.", file=sys.stderr)
    sys.exit(1)
