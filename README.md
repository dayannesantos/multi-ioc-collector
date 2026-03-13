# 🛡️ Multi-IOC Collector

Coletor automático de **Indicadores de Compromisso (IOCs)** de fontes confiáveis e atualizadas em tempo real.

Projeto desenvolvido para portfólio de **Threat Intelligence** — demonstra habilidades em automação, Python, coleta de inteligência e integração com ferramentas de defesa.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-automated-green)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Funcionalidades

- Coleta automática de IOCs de 4 fontes confiáveis:
  - **URLhaus** (Abuse.ch) — URLs maliciosas recentes
  - **MalwareBazaar** (Abuse.ch) — Hashes de malware com assinatura
  - **OpenPhish** — Phishing ativo em tempo real
  - **AlienVault OTX** (opcional)

- Remove duplicatas automaticamente
- Gera arquivos prontos para uso:
  - `iocs_YYYYMMDD_HHMM.csv` → Excel / SIEM / Splunk / Elastic
  - `iocs_YYYYMMDD_HHMM.json` → MISP, scripts ou APIs

- Roda **todo dia automaticamente** às 8h (GitHub Actions)

## Como usar localmente

# 1. Clone o repositório
```
git clone https://github.com/dayannesantos/multi-ioc-collector.git
cd multi-ioc-collector
```
# 2. Crie o .env com suas keys
```
cp .env.example .env
```
# 3. Instale as dependências
```
pip install requests python-dotenv
```
# 4. Rode
```
python multi_ioc_collector.py
```
## Exemplo de saída
```
✅ Total de IOCs únicos: 1.391
🎉 PRONTO! Arquivos salvos em /iocs_coletados/
   → iocs_20260311_2318.csv
   → iocs_20260311_2318.json
```
<img width="839" height="214" alt="ioc-output" src="https://github.com/user-attachments/assets/1f0488c3-ca6b-41d8-8c6f-5fe6f16112c1" />

## 🤖 Automação Diária
O projeto já possui GitHub Actions configurado.<br>
Todo dia às 8h ele roda automaticamente e commita os novos IOCs.

## Feito por Dayanne Santos 🦊
