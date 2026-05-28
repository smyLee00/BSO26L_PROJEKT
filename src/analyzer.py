"""
Moduł analizatora (Analyzer)
Cel: Pobiera surowy raport z Nmapa (w formacie XML), wyciąga z niego kluczowe informacje,
klasyfikuje znalezione podatności i porównuje aktualny stan sieci z poprzednim (tzw. baseline),
aby wyłapać nowe urządzenia lub nowo otwarte porty.
"""

import json
import logging
import os
import sys
import xml.etree.ElementTree as ET

# Słownik do klasyfikacji powagi zagrożeń (Triage).
# Nmap potrafi wygenerować bardzo dużo logów z silnika NSE (Nmap Scripting Engine).
# Klasyfikujemy je od najgorszego, wyszukując w tekście charakterystycznych słów kluczowych.
SEVERITY_KEYWORDS = [
    # RCE = Remote Code Execution, to najgorszy scenariusz, ktoś może odpalać kod z zewnątrz.
    ("KRYTYCZNY", ("EXPLOITABLE", "RCE", "CRITICAL", "REMOTE CODE EXECUTION")),
    # Podatności znane (CVE) lub luki bezpośrednio uderzające w usługę.
    ("WYSOKI",    ("VULNERABLE", "CVE-")),
    # Ostrzeżenia, np. słabe protokoły szyfrowania, domyślne hasła.
    ("SREDNI",    ("LIKELY", "POSSIBLE", "WARNING")),
]


def classify_severity(text):
    """
    Funkcja przyjmuje tekst (zazwyczaj wynik działania skryptu z Nmapa)
    i dopasowuje go do jednego z 3 poziomów zagrożeń na podstawie słów kluczowych.
    """
    if not text:
        return "NISKI"
    
    # Zamieniamy tekst na wielkie litery, żeby wyszukiwanie było niewrażliwe na wielkość znaków.
    upper = text.upper()
    
    # Przechodzimy hierarchicznie od KRYTYCZNYCH do SREDNICH.
    for level, keywords in SEVERITY_KEYWORDS:
        for kw in keywords:
            # Jeśli znajdziemy słowo kluczowe w tekście, od razu zwracamy ten poziom
            # i kończymy przeszukiwanie.
            if kw in upper:
                return level
    
    # Jeśli skrypt nic nie wyłapał z listy słów kluczowych, z definicji jest to małe ryzyko.
    return "NISKI"


def parse_xml(xml_path):
    """
    Kluczowa funkcja parsująca (czytająca) plik XML zwrócony przez nmap.
    Wyszukuje tylko urządzenia żywe (up) i tylko otwarte porty.
    Zwraca zagnieżdżoną listę słowników.
    """
    tree = ET.parse(xml_path)
    hosts = []

    # Szukamy wszystkich znaczników <host> w pliku
    for host_el in tree.findall(".//host"):
        # Ignorujemy urządzenia, które nie odpowiedziały na ping (stan 'down')
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        # Szukamy adresu IPv4 (Nmap może czasem zwracać same adresy MAC)
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        ports = []
        # Przeszukujemy każdy zadeklarowany port w danym urządzeniu
        for port_el in host_el.findall(".//port"):
            # Ignorujemy porty zamknięte (closed) lub filtrowane (filtered przez firewall)
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            # Wyciągamy informacje o usłudze, o ile Nmap zdołał je rozpoznać (-sV)
            service_el = port_el.find("service")
            service_name = service_el.get("name", "") if service_el is not None else ""
            service_ver = service_el.get("version", "") if service_el is not None else ""

            # Jeśli użyto skryptów (-sC), Nmap doczepi ich wyniki pod dany port
            scripts = []
            for s in port_el.findall("script"):
                scripts.append({"id": s.get("id", ""), "output": s.get("output", "")})

            # Zbieramy wszystkie dane o porcie i dopisujemy je do listy portów hosta
            ports.append({
                "port": int(port_el.get("portid", "0")),
                "proto": port_el.get("protocol", ""),
                "service": service_name,
                "version": service_ver,
                "scripts": scripts,
            })

        # Czasami skrypty Nmapa nie dotyczą konkretnego portu (np. błędy z pingowaniem,
        # globalne błędy certyfikatów). Te dane lądują w tagu <hostscript>.
        host_scripts = []
        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            for s in hostscript_el.findall("script"):
                host_scripts.append({"id": s.get("id", ""), "output": s.get("output", "")})

        # Zamykamy dane całego pojedynczego hosta (IP + Lista Portów + Skrypty Ogólne) i dodajemy do głównej paczki
        hosts.append({"ip": ip, "ports": ports, "host_scripts": host_scripts})

    return hosts


def _hosts_to_baseline(hosts):
    """
    Funkcja pomocnicza. Zamienia skomplikowaną listę słowników na prosty format:
    { "192.168.1.10": [22, 80, 443], "192.168.1.20": [3389] }
    Służy do błyskawicznego porównywania różnic między starą a nową siecią.
    """
    return {h["ip"]: sorted([p["port"] for p in h["ports"]]) for h in hosts}


def compute_diff(hosts, baseline_path):
    """
    Serce systemu ostrzegania o zmianach. 
    Wczytuje stary stan sieci z pliku (baseline) i porównuje go z najnowszym skanem.
    Wyłapuje 4 sytuacje: 
    1. Ktoś podpiął nowy komputer (Nowe IP)
    2. Ktoś odłączył stary komputer (Znikające IP)
    3. Na komputerze uruchomiono nową usługę (Nowy port, np. ktoś zainstalował serwer gry)
    4. Usługa została wyłączona (Znikający port)
    """
    changes = []
    # Spłaszczamy aktualny skan do prostej struktury
    current = _hosts_to_baseline(hosts)

    # Próba wczytania ostatniego zapisanego skanu z dysku
    if os.path.exists(baseline_path):
        try:
            with open(baseline_path, "r", encoding="utf-8") as f:
                previous = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            # Jeśli plik jest uszkodzony, kontynuujemy jakby to był pierwszy w ogóle skan w sieci
            logging.warning("Nie udało się wczytać baseline (%s), traktuję jako pierwszy skan", e)
            previous = None

        if previous is not None:
            # Set (zbior) ułatwia matematyczne odejmowanie, np: ZbiórA - ZbiórB = tylko nowe elementy
            prev_ips = set(previous.keys())
            curr_ips = set(current.keys())

            # Logika 1: Nowe IP (adresy w nowym skanie minus adresy w starym)
            for ip in sorted(curr_ips - prev_ips):
                changes.append({"ip": ip, "port": "-", "opis": "Nowe urządzenie w sieci", "severity": "SREDNI"})
            
            # Logika 2: Znikające IP (adresy w starym skanie minus adresy w nowym)
            for ip in sorted(prev_ips - curr_ips):
                changes.append({"ip": ip, "port": "-", "opis": "Host zniknął z sieci", "severity": "NISKI"})
            
            # Logika 3 i 4: IP które było i nadal jest (sprawdzamy zmiany portów na tym konkretnym maszynie)
            for ip in sorted(prev_ips & curr_ips): # Znak '&' to część wspólna obu zbiorów
                prev_ports = set(previous[ip])
                curr_ports = set(current[ip])
                
                # Nowe otwarte porty (alarm!)
                for p in sorted(curr_ports - prev_ports):
                    changes.append({"ip": ip, "port": p, "opis": "Nowy otwarty port", "severity": "SREDNI"})
                
                # Zamknięte/zablokowane porty (informacja)
                for p in sorted(prev_ports - curr_ports):
                    changes.append({"ip": ip, "port": p, "opis": "Port już niedostępny", "severity": "NISKI"})

    # Pod koniec zawsze nadpisujemy stary stan nowym (zdjęcie aktualnej sieci idzie do archiwum na następny raz)
    try:
        os.makedirs(os.path.dirname(baseline_path) or ".", exist_ok=True)
        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
    except OSError as e:
        logging.warning("Nie udało się zapisać baseline (%s)", e)

    return changes


def analyze(xml_path, baseline_path):
    """
    Główna orkiestracja. Łączy w całość wyciągnięte podatności ze skryptów (np. CVE) 
    oraz strukturalne zmiany w sieci z funkcji diff.
    To ona decyduje co znajdzie się w mailu do administratora.
    """
    hosts = parse_xml(xml_path)
    threats = []

    for h in hosts:
        ip = h["ip"]
        
        # 1. Analiza skryptów na konkretnych portach
        for p in h["ports"]:
            for s in p["scripts"]:
                output = s["output"]
                if not output:
                    continue
                
                # Używamy twardego filtra. Jeśli wynik nie jest zagrożeniem, ignorujemy,
                # żeby nie spamować administratora logami typu "Znaleziono baner HTTP".
                upper = output.upper()
                if "VULNERABLE" in upper or "CVE-" in upper or "EXPLOITABLE" in upper:
                    threats.append({
                        "ip": ip,
                        "port": p["port"],
                        # Przycinamy opis do 200 znaków pierwszej linijki
                        "opis": f"[{s['id']}] {output.strip().splitlines()[0][:200]}",
                        "severity": classify_severity(output),
                    })

        # 2. Analiza skryptów ogólnych (dotyczących całego hosta, a nie jednego portu)
        for s in h["host_scripts"]:
            output = s["output"]
            if not output:
                continue
            
            upper = output.upper()
            if "VULNERABLE" in upper or "CVE-" in upper or "EXPLOITABLE" in upper:
                threats.append({
                    "ip": ip,
                    "port": "-", # Hostscript nie ma konkretnego portu
                    "opis": f"[{s['id']}] {output.strip().splitlines()[0][:200]}",
                    "severity": classify_severity(output),
                })

    # 3. Na koniec doklejamy listę zmian strukturalnych (nowe/znikające urządzenia i porty)
    threats.extend(compute_diff(hosts, baseline_path))

    logging.info("Analiza: %d hostów up, %d wpisów zagrożeń/zmian", len(hosts), len(threats))
    return threats

# Blok wykonawczy (uruchamia się tylko, jeśli odpalamy ten plik samodzielnie w terminalu)
if __name__ == "__main__":
    # Konfiguracja formatu wyświetlania logów
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    
    # Zabezpieczenie przed brakiem argumentów (np. wpisaniem samego python3 analyzer.py)
    if len(sys.argv) < 2:
        print("Użycie: python analyzer.py <plik_xml> [baseline.json]", file=sys.stderr)
        sys.exit(1)
        
    xml = sys.argv[1]
    # Ustawienie domyślnej ścieżki pliku referencyjnego, jeśli użytkownik nie podał drugiego argumentu
    baseline = sys.argv[2] if len(sys.argv) > 2 else "/tmp/baseline.json"
    
    # Odpalenie głównego silnika i wydrukowanie w sformatowany sposób wyników w terminalu
    result = analyze(xml, baseline)
    for t in result:
        print(f"[{t['severity']:10}] {t['ip']:15} port {str(t['port']):5} - {t['opis']}")
