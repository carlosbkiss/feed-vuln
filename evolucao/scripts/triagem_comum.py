"""Funções compartilhadas pelo preparo e pela publicação da triagem.

Só biblioteca padrão, como o scripts/radar.py, para rodar no Actions sem instalar nada.
"""
from __future__ import annotations

import json
import re
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

SP = timezone(timedelta(hours=-3))
JANELA_DIAS = 7          # item entra e fica 7 dias
PENDENTE_DIAS_EXTRA = 7  # P0 ainda explorado fica mais 7 dias como "Pendente"

KEV_URLS = [
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]
UA = "Mozilla/5.0 (compatible; radar-cyber-triagem/0.1; +https://github.com/carlosbkiss/feed-vuln)"

MESES = ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"]
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


class Caminhos:
    """Todos os arquivos que a triagem lê ou grava, a partir da raiz do repositório."""

    def __init__(self, raiz: Path | str = "."):
        self.raiz = Path(raiz)
        self.entradas = self.raiz / "data" / "entradas.json"
        self.vulns = self.raiz / "data" / "vulns.json"
        self.descartes = self.raiz / "data" / "triagem_descartes.json"
        self.trabalho = self.raiz / ".triagem"          # fora do git (está no .gitignore sugerido)
        self.pendencias = self.trabalho / "pendencias.json"
        self.rascunho = self.trabalho / "rascunho.json"
        self.anterior = self.trabalho / "anterior.json"


def ler_json(p: Path, padrao):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return padrao


def gravar_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def hoje_sp(agora: datetime | None = None) -> date:
    return (agora or datetime.now(timezone.utc)).astimezone(SP).date()


def iso_utc(agora: datetime | None = None) -> str:
    return (agora or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def texto_janela(hoje: date) -> str:
    """'05 a 12/nov/2026'. Se a janela cruza o mês: '28/out a 04/nov/2026'."""
    ini = hoje - timedelta(days=JANELA_DIAS)
    fim = f"{hoje.day:02d}/{MESES[hoje.month - 1]}/{hoje.year}"
    if ini.month == hoje.month:
        return f"{ini.day:02d} a {fim}"
    return f"{ini.day:02d}/{MESES[ini.month - 1]} a {fim}"


def cves_do_item(item: dict) -> set[str]:
    """'CVE-1 / CVE-2' vira {'CVE-1', 'CVE-2'}. Itens 'sem CVE (...)' devolvem conjunto vazio."""
    return set(RE_CVE.findall(item.get("cve", "")))


def chave_item(item: dict) -> str:
    """Identidade estável do item para comparar rodadas: as CVEs ordenadas ou o texto 'sem CVE (...)'."""
    cves = cves_do_item(item)
    return " / ".join(sorted(cves)) if cves else item.get("cve", "").strip().lower()


def baixar_kev(timeout: int = 60) -> tuple[dict[str, dict], str]:
    """Catálogo KEV indexado por CVE. Tenta o espelho no GitHub primeiro (o site da CISA bloqueia robôs às vezes)."""
    erro = ""
    for url in KEV_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                dados = json.loads(r.read().decode("utf-8"))
            return {v["cveID"]: v for v in dados.get("vulnerabilities", [])}, f"ok ({url.split('/')[2]})"
        except Exception as e:  # noqa: BLE001 - qualquer falha cai para a próxima URL
            erro = f"{url.split('/')[2]}: {str(e)[:120]}"
    return {}, f"erro: {erro}"
