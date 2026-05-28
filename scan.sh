#!/bin/sh

# Skaner ręczny - działa na zasadzie kopii configu, podmiany trybu skanu na żądany a następnie przywróceniu poprzedniej wartości. 

PROFILE="${1:-standard}"
IP="${2:-192.168.56.2}"
USER="${3:-admin}"
PORT="${4:-22}"

# Walidacja profilu
case "$PROFILE" in
    quick|standard|deep) ;;
    *)
        echo "BŁĄD: Nieprawidłowy profil '$PROFILE'. Dostępne: quick, standard, deep"
        echo "Użycie: sh scan.sh [quick|standard|deep] [ip] [user] [port]"
        exit 1
        ;;
esac

echo "==========================================="
echo "  Skaner sieci LAN (Uruchomienie ręczne)"
echo "  Router : $IP"
echo "  Profil : $PROFILE"
echo "==========================================="
echo ""

# 1. Pobranie aktualnego configu z routera
echo "Pobieram aktualną konfigurację z routera..."
scp -P "$PORT" "${USER}@${IP}:/sata1/config.yaml" ./config_temp.yaml 2>/dev/null

if [ ! -f "config_temp.yaml" ]; then
    echo "[BŁĄD] Nie udało się pobrać pliku config.yaml z routera!"
    exit 1
fi

# Zapisujemy oryginalny profil w pamięci skryptu
ORIG_PROFILE=$(grep "^profile:" config_temp.yaml | awk '{print $2}')
echo "Oryginalny profil harmonogramu to: $ORIG_PROFILE"

# 2. Podmiana profilu i wysłanie na router
echo "Wysyłam tymczasową konfigurację ($PROFILE)..."
sed -i "s/^profile: .*/profile: $PROFILE/" config_temp.yaml
scp -P "$PORT" config_temp.yaml "${USER}@${IP}:/sata1/config.yaml" 2>/dev/null

# 3. Twardy restart kontenera
echo "Restartuję kontener na MikroTiku..."
ssh -p "$PORT" "${USER}@${IP}" "/container/stop [/container/find]; :delay 2; /container/start [/container/find];"

# 4. Przywracamy oryginalny plik
# Dajemy kontenerowi 3 sekundy na start i zaczytanie pliku YAML przez Pythona
sleep 3
echo "Przywracam domyślny profil ($ORIG_PROFILE) dla automatycznego harmonogramu..."
sed -i "s/^profile: .*/profile: $ORIG_PROFILE/" config_temp.yaml
scp -P "$PORT" config_temp.yaml "${USER}@${IP}:/sata1/config.yaml" 2>/dev/null

# Usuwamy plik tymczasowy, żeby nie trzymać haseł lokalnie
rm config_temp.yaml

echo ""
echo "[OK] Skan uruchomiony. Sprawdź logi:"
echo "  ssh -p $PORT ${USER}@${IP}"
echo "  /log/print where topics~\"container\""
