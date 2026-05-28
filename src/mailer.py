"""
Moduł raportujący
Cel: Pobiera listę zagrożeń, parsuje ją w tabelę HTML i wysyła 
wyniki w postaci e-maila do administratora przy pomocy protokołu SMTP.
"""

import logging
import smtplib
import socket
import sys
import time
from email.message import EmailMessage

# Definiujemy paletę kolorów w formacie HEX dla tabeli HTML.
# Kolory są dobierane z myślą o szybkim czytaniu - czerwony alarmuje, szary informuje.
SEVERITY_COLOR = {
    "KRYTYCZNY": "#c0392b", # Ciemnoczerwony (np. luki Remote Code Execution)
    "WYSOKI":    "#e67e22", # Pomarańczowy (znane podatności CVE)
    "SREDNI":    "#f1c40f", # Żółty (ostrzeżenia konfiguracyjne / nowo wykryte maszyny)
    "NISKI":     "#bdc3c7", # Szary (zwykłe informacje o zamknięciu portu/usunięciu maszyny)
}


def _build_html(threats):
    """
    Funkcja budująca sformatowaną tabelkę HTML, która jest wysyłana w wiadomości e-mail.
    """
    rows = []
    for t in threats:
        # Pobieramy odpowiedni kolor. Jeśli z jakiegoś powodu poziom jest nierozpoznany, domyślnie dajemy szary.
        color = SEVERITY_COLOR.get(t["severity"], "#bdc3c7")
        
        # Sanitization (Oczyszczanie danych)
        # Skaner analizuje pakiety z obcych maszyn, w których może znajdować się złośliwy kod (np. próba ataku XSS).
        opis = (t["opis"]
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))
        
        # Doczepiamy nowy wiersz tabeli ze stylem wbudowanym w tag (inline CSS),
        # ponieważ wiele klientów poczty (np. Outlook) ignoruje tradycyjne arkusze <style>.
        rows.append(
            f'<tr style="background-color:{color};color:#fff;">'
            f'<td style="padding:6px 10px;">{t["severity"]}</td>'
            f'<td style="padding:6px 10px;">{t["ip"]}</td>'
            f'<td style="padding:6px 10px;">{t["port"]}</td>'
            f'<td style="padding:6px 10px;">{opis}</td>'
            f'</tr>'
        )

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Skrócony warunek if-else ułożony pod konstrukcję tekstu
    body = (
        "<p style=\"color:#27ae60;font-weight:bold;\">✓ Nie wykryto żadnych zagrożeń w sieci.</p>"
        if not threats else
        f"""<table style=\"border-collapse:collapse;border:1px solid #333;\">
    <thead>
      <tr style=\"background:#333;color:#fff;\">
        <th style=\"padding:6px 10px;text-align:left;\">Poziom</th>
        <th style=\"padding:6px 10px;text-align:left;\">Adres IP</th>
        <th style=\"padding:6px 10px;text-align:left;\">Port</th>
        <th style=\"padding:6px 10px;text-align:left;\">Opis</th>
      </tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>"""
    )
    
    # Pełna konstrukcja szkieletu dokumentu HTML.
    return f"""<!doctype html>
<html><body style="font-family:Arial,sans-serif;">
  <h2>Raport skanowania sieci LAN</h2>
  <p>Wygenerowano: {timestamp}<br>Liczba wpisów: {len(threats)}</p>
  {body}
  <p style="color:#888;font-size:11px;">Skaner LAN - projekt BSO</p>
</body></html>"""


def _build_plain(threats):
    """
    Funkcja budująca w pełni tekstową wersję e-maila
    """
    lines = ["Raport skanowania sieci LAN", "=" * 40, ""]
    if not threats:
        lines.append("Nie wykryto żadnych zagrożeń w sieci.")
    else:
        for t in threats:
            lines.append(f"[{t['severity']}] {t['ip']} port {t['port']} - {t['opis']}")
    lines.append("")
    lines.append(f"Liczba wpisów: {len(threats)}")
    return "\n".join(lines)


def send_report(threats, smtp_cfg):
    """
    Logika wysyłania e-maila. 
    Przyjmuje zestawienia zagrożeń z analizatora oraz blok konfiguracyjny z danymi logowania SMTP.
    """
    # Konstruowanie tytułu wiadomości. Administrator jednym spojrzeniem musi wiedzieć czy skan był spokojny, czy wykrył błędy.
    subject = (
        f"[Skaner LAN] Raport - {len(threats)} zagrożeń"
        if threats else
        "[Skaner LAN] Skan zakończony - brak zagrożeń"
    )

    # Budowanie nagłówków i zawartości maila zgodnego ze standardem MIME.
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_cfg["user"]
    msg["To"] = smtp_cfg["admin_email"]
    
    # Najpierw podpinamy 'Plain Text' jako plan B...
    msg.set_content(_build_plain(threats))
    # ...a następnie dokładamy wersję HTML, która będzie traktowana priorytetowo przez wspierające klienty.
    msg.add_alternative(_build_html(threats), subtype="html")

    try:
        # Próba nawiązania połączenia na bezpiecznym porcie pocztowym.
        # smtplib.SMTP_SSL od razu opakowuje połączenie w bezpieczny kanał, zamiast wysyłać najpierw niezaszyfrowane sygnały 
        # (jak ma to miejsce przy zwykłym SMTP na porcie 587 używającym starttls).
        with smtplib.SMTP_SSL(smtp_cfg["server"], smtp_cfg["port"], timeout=30) as s:
            s.login(smtp_cfg["user"], smtp_cfg["password"])
            s.send_message(msg)
            
    # Łapanie absolutnie wszystkich awarii połączeń (błędne hasło, zablokowany port poczty, brak sieci).
    # Nigdy nie chcemy, aby usterka przy wysyłce maila powodowała wyłączenie skanera błędem krytycznym.
    except (smtplib.SMTPException, socket.error, OSError) as e:
        logging.error("Nie udało się wysłać maila: %s", e)
        return False

    logging.info("Wysłano raport na %s", smtp_cfg["admin_email"])
    return True

# Blok testowy/demonstracyjny (Działa, jeśli wpiszesz komendę 'python3 report.py')
if __name__ == "__main__":
    # Testujemy cały moduł pocztowy na sztywno wpisanych "zagrożeniach", żeby nie trzeba było
    # robić całego rzeczywistego skanu Nmapem (tzw. Mockowanie danych).
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    import config
    cfg = config.load_config()
    demo = [
        # Symulacja znanej luki EternalBlue w starym systemie Windows
        {"ip": "192.168.1.10", "port": 445, "opis": "[smb-vuln-ms17-010] VULNERABLE: EternalBlue", "severity": "KRYTYCZNY"},
        # Symulacja znalezienia niewłaściwej wersji oprogramowania na domyślnym porcie HTTP
        {"ip": "192.168.1.20", "port": 80,  "opis": "[http-server-header] Apache 2.2 (stara wersja)", "severity": "SREDNI"},
        # Zmiana z Baseline (np. podłączono do sieci nowy telefon lub laptop)
        {"ip": "192.168.1.30", "port": "-", "opis": "Nowe urządzenie w sieci", "severity": "SREDNI"},
    ]
    # Próba wysyłki wiadomości do samego siebie w celach testowych.
    ok = send_report(demo, cfg["smtp"])
    
    # Skrypt zwraca kod błędu (1), jeśli mail nie doszedł (żeby mogły go odczytać inne automatyzacje).
    sys.exit(0 if ok else 1)
