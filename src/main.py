"""
Moduł zarządzając
Cel: Główny punkt wejścia dla aplikacji działającej w kontenerze. 
Odpowiada za ułożenie klocków w odpowiedniej kolejności: 
1. Wczytaj konfigurację
2. Odpal skaner sieci
3. Przeanalizuj wyniki
4. Wyślij raport
"""

import logging
import sys

import analyzer
import config
import mailer
import scanner


def main():
    """
    Główna pętla logiki skanera.
    Zwraca kody błędów (liczby całkowite), które potem system operacyjny Linux (lub Docker)
    może odczytać, aby wiedzieć, na jakim etapie program uległ awarii.
    """
    
    # Inicjalizacja globalnego formatu logów. Każdy komunikat w systemie będzie miał 
    # prefiks z datą, godziną i poziomem ważności (np. INFO, ERROR).
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.info("=== Start skanowania ===")

    # ETAP 1: Konfiguracja (Bramkarz)
    try:
        cfg = config.load_config()
    except (FileNotFoundError, ValueError) as e:
        # Jeśli brakuje hasła albo pliku YAML, nie ma sensu iść dalej. 
        # Zgłaszamy błąd i konczymy proces z kodem błędu 1.
        logging.error("Błąd konfiguracji: %s", e)
        return 1

    # ETAP 2: Skanowanie (Silnik)
    # Zlecamy modułowi skan
    # Oczekujemy, że w odpowiedzi zwróci nam po prostu ścieżkę do wygenerowanego pliku XML.
    xml_path = scanner.run_scan(
        cfg["subnet"],
        cfg["profile"],
        cfg["scan"]["output_dir"],
    )
    
    # Zabezpieczenie przed awarią Nmapa (np. brak uprawnień root/sudo do wysyłania pakietów surowych).
    if xml_path is None:
        logging.error("Skanowanie nieudane - kończę.")
        return 2 # Kod błędu 2: Błąd infrastruktury/skanowania

    # ETAP 3: Analiza i Triage
    threats = analyzer.analyze(xml_path, cfg["scan"]["baseline_file"])

    if not threats:
        logging.info("Brak zagrożeń - wysyłam raport informacyjny.")

    # ETAP 4: Raportowanie
    # Wysyłamy gotową listę zagrożeń wraz z danymi logowania SMTP do modułu wysyłkowego.
    ok = mailer.send_report(threats, cfg["smtp"])
    if not ok:
        logging.error("Wysyłka raportu nieudana.")
        return 3 # Kod błędu 3: Błąd sieci zewnętrznej / problem z pocztą

    logging.info("=== Koniec skanowania ===")
    
    return 0


if __name__ == "__main__":
    # sys.exit() bierze liczbę, którą zwróciła funkcja main() (0, 1, 2 lub 3) 
    # i przekazuje ją bezpośrednio do kontenera Dockera. 
    # Dzięki temu polecenie 'docker inspect' poprawnie pokaże, dlaczego kontener się zatrzymał
    sys.exit(main())
