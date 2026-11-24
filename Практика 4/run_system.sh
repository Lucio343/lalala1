#!/bin/bash
# =============================================================================
# Запуск ИАС БИ — полная интеграция
# =============================================================================

set -e

TARGET=${1:-127.0.0.1}
OUTPUT_DIR="./scan_results"
mkdir -p "$OUTPUT_DIR"

echo "=== ИАС БИ: сканирование $TARGET ==="

# 1. Запуск сканеров
echo "[1/6] Nmap..."
nmap -sV -oX "$OUTPUT_DIR/nmap.xml" "$TARGET" > /dev/null

echo "[2/6] Masscan..."
sudo masscan -p1-1000 "$TARGET" --rate 100 -oJ "$OUTPUT_DIR/masscan.json" > /dev/null

echo "[3/6] Nikto..."
nikto -h "$TARGET" -o "$OUTPUT_DIR/nikto.json" -Format json > /dev/null

# 2. Парсинг
echo "[4/6] Парсинг Nmap XML (C++)..."
./nmap_parser "$OUTPUT_DIR/nmap.xml" > "$OUTPUT_DIR/nmap_parsed.json"

echo "[5/6] Парсинг JSON (Python)..."
python3 -c "
from parsers import MasscanParser, NiktoParser, NmapJSONParser
import json

findings = []
findings += MasscanParser.parse('$OUTPUT_DIR/masscan.json')
findings += NiktoParser.parse('$OUTPUT_DIR/nikto.json')
findings += NmapJSONParser.parse('$OUTPUT_DIR/nmap_parsed.json')

with open('$OUTPUT_DIR/all_findings.json', 'w') as f:
    json.dump(findings, f, ensure_ascii=False, indent=2)

print(f'Всего находок: {len(findings)}')
"

# 3. Экспертная система
echo "[6/6] Экспертная система..."
python3 -c "
from expert_system import ExpertSystem
import json

with open('$OUTPUT_DIR/all_findings.json') as f:
    findings = json.load(f)

es = ExpertSystem('rules.yaml')
incident = es.evaluate(findings)

print(f'Инцидент обнаружен: {incident.detected}')
print(f'Оценка риска: {incident.risk_score}')
print(f'Категория: {incident.category}')
print(f'Рекомендации: {incident.recommendations}')

with open('$OUTPUT_DIR/incident.json', 'w') as f:
    json.dump({
        'detected': incident.detected,
        'risk_score': incident.risk_score,
        'category': incident.category,
        'recommendations': incident.recommendations,
    }, f, ensure_ascii=False, indent=2)
"

echo "=== Готово! Результаты в $OUTPUT_DIR ==="
