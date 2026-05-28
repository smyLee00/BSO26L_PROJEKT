#!/bin/sh
# Wyłączenie instalatora przy wykryciu błędu
set -e

IMAGE_NAME="lan-scanner"
TAR_FILE="lan-scanner.tar"

echo "==========================================="
echo "  Skaner sieci LAN - instalacja"
echo "==========================================="
echo ""

#  Sprawdzenie zaleznosci lokalnych 
for cmd in docker ssh scp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "BŁĄD: '$cmd' nie jest dostępny. Zainstaluj go i spróbuj ponownie."
        exit 1
    fi
done

#  Dane połączenia z MikroTikiem 
printf "Adres IP routera MikroTik: "
read MIKROTIK_IP

# Podawanie zmiennych przez użytkownika [wartość domyślna]
printf "Użytkownik SSH [admin]: "
read MIKROTIK_USER
[ -z "$MIKROTIK_USER" ] && MIKROTIK_USER="admin"

printf "Port SSH [22]: "
read MIKROTIK_PORT
[ -z "$MIKROTIK_PORT" ] && MIKROTIK_PORT="22"

#  Pytania konfiguracyjne 
echo ""
echo " ---Konfiguracja skanera--- "

printf "Adres email administratora (odbiorca raportu): "
read ADMIN_EMAIL

printf "Serwer SMTP [smtp.gmail.com]: "
read SMTP_SERVER
[ -z "$SMTP_SERVER" ] && SMTP_SERVER="smtp.gmail.com"

printf "Port SMTP [465]: "
read SMTP_PORT
[ -z "$SMTP_PORT" ] && SMTP_PORT=465

printf "Login (email nadawcy): "
read SMTP_USER

printf "Hasło aplikacji SMTP: "
read SMTP_PASS

printf "Profil domyślny (quick/standard/deep) [standard]: "
read PROFILE
[ -z "$PROFILE" ] && PROFILE="standard"

printf "Podsieć do skanowania (np. 192.168.88.0/24 lub 'auto') [auto]: "
read SUBNET
[ -z "$SUBNET" ] && SUBNET="auto"

printf "Godzina uruchamiania skanu (format HH:MM) [03:00]: "
read SCAN_TIME
[ -z "$SCAN_TIME" ] && SCAN_TIME="03:00"
SCAN_TIME="${SCAN_TIME}:00"

printf "Częstotliwość skanowania (np. 1h, 12h, 24h, 7d) [24h]: "
read CRON_SCHEDULE
[ -z "$CRON_SCHEDULE" ] && CRON_SCHEDULE="24h"

printf "Interfejs veth na MikroTiku [veth1]: "
read VETH_IFACE
[ -z "$VETH_IFACE" ] && VETH_IFACE="veth1"

#  Generowanie config.yaml 
echo ""
echo "Zapisuję config.yaml ..."
cat > config.yaml <<EOF
subnet: $SUBNET
profile: $PROFILE
smtp:
  server: $SMTP_SERVER
  port: $SMTP_PORT
  user: $SMTP_USER
  password: $SMTP_PASS
  admin_email: $ADMIN_EMAIL
scan:
  output_dir: /tmp/scans
  baseline_file: /data/baseline.json
EOF
chmod 600 config.yaml
echo "OK."

#  Budowa obrazu Docker 
echo ""
echo "Buduję obraz Docker ..."
docker build -t "$IMAGE_NAME:latest" .
echo "OK."

#  Spłaszczenie obrazu do jednej warstwy (wymagane przez RouterOS) 
echo ""
echo "Spłaszczam obraz do jednej warstwy ..."
docker run --name tmp-scanner "$IMAGE_NAME:latest" echo ok
docker export tmp-scanner | docker import \
    --change "WORKDIR /app" \
    --change "ENV PYTHONUNBUFFERED=1" \
    --change "ENV PYTHONDONTWRITEBYTECODE=1" \
    --change "CMD [\"python3\", \"src/main.py\"]" \
    - "$IMAGE_NAME:flat"
docker rm tmp-scanner
echo "OK."

#  Zapis obrazu do pliku tar 
echo ""
echo "Zapisuję obraz do $TAR_FILE ..."
docker save "$IMAGE_NAME:flat" -o "$TAR_FILE"
echo "OK. Rozmiar: $(du -sh $TAR_FILE | cut -f1)"

#  Wgranie plików na MikroTika protokołem SCP
echo ""
echo "Wgrywam pliki na router $MIKROTIK_IP ..."

scp -P "$MIKROTIK_PORT" "$TAR_FILE" \
    "${MIKROTIK_USER}@${MIKROTIK_IP}:/sata1/${TAR_FILE}"
echo "  ✓ $TAR_FILE"

scp -P "$MIKROTIK_PORT" config.yaml \
    "${MIKROTIK_USER}@${MIKROTIK_IP}:/sata1/config.yaml"
echo "  ✓ config.yaml"

#  Konfiguracja kontenera na MikroTiku przez SSH 
echo ""
echo "Konfiguruję kontener na MikroTiku ..."

ssh -p "$MIKROTIK_PORT" "${MIKROTIK_USER}@${MIKROTIK_IP}" "
:local existing [/container/find]
:if (\$existing != \"\") do={
    /container/remove \$existing
    :delay 3
}
/container/envs/add list=scanner-env name=SCAN_PROFILE value=${PROFILE}
/container/add file=sata1/${TAR_FILE} interface=${VETH_IFACE} mount=sata1/config.yaml:/app/config.yaml:ro envlist=scanner-env logging=yes start-on-boot=no root-dir=sata1/scanner-root
:delay 2
:local existing_sched [/system/scheduler/find name=lan-scan]
:if (\$existing_sched != \"\") do={ /system/scheduler/remove \$existing_sched }
/system/scheduler/add name=lan-scan interval=${CRON_SCHEDULE} start-time=${SCAN_TIME} on-event=\"/container/start [/container/find]\" comment=\"Automatyczny skan sieci LAN\"
"

echo ""
echo "==========================================="
echo "  Instalacja zakończona!"
echo ""
echo "  Router:      $MIKROTIK_IP"
echo "  Interfejs:   $VETH_IFACE"
echo "  Profil:      $PROFILE"
echo "  Harmonogram: co $CRON_SCHEDULE (pierwszy skan $SCAN_TIME)"
echo "  Raport:     $ADMIN_EMAIL"
echo ""
echo "  Uruchom skan:"
echo "    sh scan.sh [quick|standard|deep]"
echo "==========================================="
