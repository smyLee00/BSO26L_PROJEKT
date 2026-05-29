# Skaner sieci LAN
Automatyczny skaner lokalnej sieci komputerowej z wykrywaniem zagrożeń i raportowaniem e-mail. Przeznaczony do uruchamiania w kontenerze Docker na routerach MikroTik z RouterOS 7.x.

## Funkcjonalność

- Skanowanie sieci LAN narzędziem Nmap z wykorzystaniem skryptów NSE
- Trzy profile skanowania: **quick / standard / deep**
- Klasyfikacja zagrożeń wg poziomu krytyczności (KRYTYCZNY / WYSOKI / ŚREDNI / NISKI) na podstawie outputu NSE i numerów CVE
- Porównanie z poprzednim skanem (baseline JSON) — wykrywanie nowych urządzeń, nowych portów i hostów, które zniknęły
- Wysyłka raportu HTML przez SMTP (Gmail z hasłem aplikacji)
- Uruchamianie cykliczne przez Cron

## Wymagania

- Host z Dockerem (RouterOS 7.x z pakietem `container`, Linux, lub WSL2)
- Konto Gmail z włączonym 2FA i wygenerowanym **hasłem aplikacji**
- Dostęp do skanowanej sieci LAN

## Instalacja na urządzeniu właściciela routera

```sh
sudo git clone https://github.com/macius714/BSO26L_PROJEKT && cd lan-scanner && sudo sh install.sh
```
# Proces instalacji
Po wywołaniu powyższej komendy na urządzeniu użytkownika rozpocznie się proces instalacji. Jeśli obok pytania widnieje wartośc zapisana w kwadratowym nawiasie [], oznacza to, że jest to wartość domyślna,
która zostanie automatycznie przypisana w przypadku niepodania żadnych danych. Dla użytkowników niezaawansowanych: w takich przypadkach rekomendujemy pozostawienie wartości domyślnych (przekliknięcie Enterem).
Skrypt zapyta o:
- adres e-mail, na jaki mają trafiać raporty ze skanowań
- dane serwera SMTP (domyślnie `smtp.gmail.com:465`)
- adres e-mail, z jakiego mają być wysyłane maile,
- hasło aplikacji e-mail (wymaga włączonej weryfikacji 2FA oraz wygenerowanego hasła),
- profil skanowania,
- podsieć (lub `auto`),
- harmonogram skanowania w formacie godziny oraz częstotliwości.

Podczas instalacji zostaniesz poproszony o trzykrotne wpisanie hasła do routera, aby możliwe było wgranie na niego narzędzia do skanowania. Jeśli nie znasz hasła, skontaktuj się ze swoim dostawcą internetowym.

Po instalacji obraz jest zbudowany, kontener utworzony, a wpis schedulera dodany.

## Uruchomienie ręczne

Po instalacji narzędzie rozpocznie skanowanie o ustalonych godzinach. Można również uruchomić skanowanie ręcznie, wywołując w terminalu komputera skrypt poleceniem:

```sh
sudo sh scan.sh quick
sudo sh scan.sh standard
sudo sh scan.sh deep
```
w zależności od głębokości skanu.

## Profile skanowania

| Profil | Flagi Nmapa | Czas | Zastosowanie |
|--------|-------------|------|--------------|
| `quick` | `-T4 -F` | sekundy | szybki przegląd, popularne porty |
| `standard` | `-sV -sC` | minuty | wykrywanie wersji + skrypty domyślne |
| `deep` | `-sV -sC --script vuln` | do 30 min | pełne skanowanie podatności |


## Architektura

Pełny opis architektury (warstwy, schematy blokowe, pseudokody) znajduje się w sprawozdaniu Etapu 1.

## Autorzy

- Jakub Mika, 337044
- Maciej Piątkowski, 341162
