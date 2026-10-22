"""Verificação do Radar Cyber (a cada 2h, das 8h às 20h de SP).

Consulta o catálogo CISA KEV e a API da NVD, aplica regras fixas de prioridade
e atualiza:
  - data/alertas.json  -> só é reescrito quando a lista de alertas muda (vai para o git)
  - data/status.json   -> sempre reescrito (hora da verificação; não vai para o git)

Sem dependências externas: só biblioteca padrão.
Variável opcional: NVD_API_KEY (aumenta o limite de requisições da NVD).
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ALERTAS = DATA / "alertas.json"
STATUS = DATA / "status.json"
WATCHLIST = ROOT / "config" / "watchlist.json"

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

JANELA_BUSCA_DIAS = 3      # olha para trás a cada rodada (cobre atrasos e falhas)
RETENCAO_DIAS = 14         # quanto tempo um alerta fica na página
CVSS_CORTE = 9.0
UA = "radar-cyber/1.0 (+https://github.com/carlosbkiss/feed-vuln)"

TRATAMENTO = {
    "P0": "Explorado em fabricante de borda ou acesso: corrigir em até 24h e caçar IOCs retroativos.",
    "P1-KEV": "Explorado ativamente: confirmar inventário e corrigir em até 72h.",
    "P1-WATCH": "Crítico em fabricante relevante: checar exposição; se estiver exposto à internet, tratar como P0.",
    "P2": "Crítico fora da lista prioritária: confirmar se existe no inventário e seguir o ciclo normal.",
}


def agora() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_json(url: str, headers: dict | None = None, tentativas: int = 3) -> dict:
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    erro: Exception | None = None
    for i in range(tentativas):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            erro = e
            time.sleep(6 * (i + 1))
    raise RuntimeError(f"falha ao buscar {url}: {erro}")


def carregar_watchlist() -> tuple[re.Pattern, re.Pattern]:
    cfg = json.loads(WATCHLIST.read_text(encoding="utf-8"))

    def padrao(termos: list[str]) -> re.Pattern:
        partes = [r"(?<![a-z0-9])" + re.escape(t.lower()) + r"(?![a-z0-9])" for t in termos]
        return re.compile("|".join(partes))

    return padrao(cfg["borda_e_acesso"]), padrao(cfg["plataformas_corporativas"])


# ---------------------------------------------------------------- fontes

def buscar_kev(desde: datetime) -> tuple[list[dict], str]:
    ultimo_erro = ""
    for url in KEV_URLS:
        try:
            dados = get_json(url)
            itens = []
            for v in dados.get("vulnerabilities", []):
                adicionado = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if adicionado >= desde.replace(hour=0, minute=0, second=0):
                    itens.append(v)
            return itens, "ok"
        except Exception as e:  # tenta o espelho
            ultimo_erro = str(e)
    return [], f"erro: {ultimo_erro[:160]}"


def nvd_headers() -> dict:
    chave = os.environ.get("NVD_API_KEY", "").strip()
    return {"apiKey": chave} if chave else {}


def pausa_nvd() -> None:
    time.sleep(1 if nvd_headers() else 6.5)


def extrair_cvss(cve: dict) -> tuple[float | None, str, bool]:
    """Maior nota disponível (v4.0, v3.1, v3.0), versão e se é rede sem autenticação."""
    metricas = cve.get("metrics", {})
    melhor: tuple[float | None, str, bool] = (None, "", False)
    for chave, versao in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        for m in metricas.get(chave, []):
            d = m.get("cvssData", {})
            nota = d.get("baseScore")
            if nota is None:
                continue
            vetor = d.get("vectorString", "")
            sem_auth = "AV:N" in vetor and ("PR:N" in vetor)
            if melhor[0] is None or nota > melhor[0]:
                melhor = (float(nota), versao, sem_auth)
    return melhor


def descricao(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def buscar_nvd_criticos(desde: datetime, ate: datetime) -> tuple[list[dict], str]:
    vistos: dict[str, dict] = {}
    try:
        for filtro in ("cvssV3Severity", "cvssV4Severity"):
            inicio = 0
            while True:
                params = {
                    "pubStartDate": desde.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "pubEndDate": ate.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    filtro: "CRITICAL",
                    "resultsPerPage": 2000,
                    "startIndex": inicio,
                }
                dados = get_json(NVD_URL + "?" + urllib.parse.urlencode(params), nvd_headers())
                for item in dados.get("vulnerabilities", []):
                    cve = item["cve"]
                    vistos[cve["id"]] = cve
                total = dados.get("totalResults", 0)
                inicio += dados.get("resultsPerPage", 0) or 2000
                pausa_nvd()
                if inicio >= total:
                    break
        return list(vistos.values()), "ok"
    except Exception as e:
        return list(vistos.values()), f"erro: {str(e)[:160]}"


def buscar_nvd_por_id(cve_id: str) -> dict | None:
    try:
        dados = get_json(NVD_URL + "?" + urllib.parse.urlencode({"cveId": cve_id}), nvd_headers())
        pausa_nvd()
        vs = dados.get("vulnerabilities", [])
        return vs[0]["cve"] if vs else None
    except Exception:
        return None


# ---------------------------------------------------------------- regras

def priorizar(texto: str, cvss: float | None, kev: bool, borda: re.Pattern, corp: re.Pattern) -> tuple[str, str, str]:
    t = texto.lower()
    em_borda = bool(borda.search(t))
    em_corp = bool(corp.search(t))
    nota = cvss or 0.0
    if kev and (em_borda or nota >= CVSS_CORTE):
        return "P0", "KEV + fabricante de borda/acesso ou CVSS ≥ 9", TRATAMENTO["P0"]
    if kev:
        return "P1", "KEV", TRATAMENTO["P1-KEV"]
    if nota >= CVSS_CORTE and (em_borda or em_corp):
        return "P1", "CVSS ≥ 9 em fabricante da lista", TRATAMENTO["P1-WATCH"]
    return "P2", "CVSS ≥ 9 fora da lista", TRATAMENTO["P2"]


# ---------------------------------------------------------------- principal

def main() -> int:
    DATA.mkdir(exist_ok=True)
    t0 = agora()
    desde = t0 - timedelta(days=JANELA_BUSCA_DIAS)
    borda, corp = carregar_watchlist()

    anterior = {"itens": []}
    if ALERTAS.exists():
        anterior = json.loads(ALERTAS.read_text(encoding="utf-8"))
    existentes = {i["id"]: i for i in anterior.get("itens", [])}

    candidatos: dict[str, dict] = {}

    kev, status_kev = buscar_kev(desde)
    for v in kev:
        cve_id = v["cveID"]
        antigo = existentes.get(cve_id, {})
        if antigo.get("origem") == "KEV":  # já enriquecido antes: não consulta a NVD de novo
            cvss, versao = antigo.get("cvss"), antigo.get("cvss_versao", "")
        else:
            detalhe = buscar_nvd_por_id(cve_id)
            cvss, versao, _ = extrair_cvss(detalhe) if detalhe else (antigo.get("cvss"), antigo.get("cvss_versao", ""), False)
        produto = f'{v.get("vendorProject", "")} {v.get("product", "")}'.strip()
        texto = f'{produto} {v.get("vulnerabilityName", "")} {v.get("shortDescription", "")}'
        p, regra, trat = priorizar(texto, cvss, True, borda, corp)
        candidatos[cve_id] = {
            "id": cve_id,
            "origem": "KEV",
            "produto": produto,
            "titulo": v.get("vulnerabilityName", ""),
            "resumo": v.get("shortDescription", "")[:280],
            "cvss": cvss,
            "cvss_versao": versao,
            "publicado": v.get("dateAdded"),
            "prazo_cisa": v.get("dueDate"),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "prioridade": p,
            "regra": regra,
            "tratamento": trat,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    nvd, status_nvd = buscar_nvd_criticos(desde, t0)
    for cve in nvd:
        cve_id = cve["id"]
        cvss, versao, sem_auth = extrair_cvss(cve)
        if cvss is None or cvss < CVSS_CORTE:
            continue
        if cve_id in candidatos:  # já veio pelo KEV; só completa a nota
            candidatos[cve_id]["cvss"] = candidatos[cve_id]["cvss"] or cvss
            candidatos[cve_id]["cvss_versao"] = candidatos[cve_id]["cvss_versao"] or versao
            continue
        desc = descricao(cve)
        p, regra, trat = priorizar(desc, cvss, False, borda, corp)
        candidatos[cve_id] = {
            "id": cve_id,
            "origem": "NVD",
            "produto": "",
            "titulo": "",
            "resumo": desc[:280],
            "cvss": cvss,
            "cvss_versao": versao,
            "sem_autenticacao": sem_auth,
            "publicado": cve.get("published", "")[:10],
            "prioridade": p,
            "regra": regra,
            "tratamento": trat,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    novos = 0
    for cve_id, c in candidatos.items():
        if cve_id in existentes:
            antigo = existentes[cve_id]
            c["detectado"] = antigo.get("detectado")
            # KEV posterior a um alerta NVD sobe a prioridade e conta como novidade
            if antigo.get("origem") == "NVD" and c["origem"] == "KEV":
                c["detectado"] = iso(t0)
                c["escalado"] = True
                novos += 1
        else:
            c["detectado"] = iso(t0)
            novos += 1
        existentes[cve_id] = {**existentes.get(cve_id, {}), **c}

    limite = iso(t0 - timedelta(days=RETENCAO_DIAS))
    itens = [i for i in existentes.values() if (i.get("detectado") or "") >= limite]
    ordem = {"P0": 0, "P1": 1, "P2": 2}
    itens.sort(key=lambda i: (i.get("detectado") or "", -ordem.get(i["prioridade"], 9)), reverse=True)

    ultimo = max((i["detectado"] for i in itens), default=anterior.get("ultimo_alerta"))
    novo_conteudo = {"ultimo_alerta": ultimo, "itens": itens}

    if novo_conteudo != {"ultimo_alerta": anterior.get("ultimo_alerta"), "itens": anterior.get("itens", [])}:
        ALERTAS.write_text(json.dumps(novo_conteudo, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    status = {
        "ultima_verificacao": iso(t0),
        "ultimo_alerta": ultimo,
        "novos_nesta_rodada": novos,
        "alertas_ativos": len(itens),
        "fontes": {"cisa_kev": status_kev, "nvd": status_nvd},
        "janela_busca_dias": JANELA_BUSCA_DIAS,
        "chave_nvd": bool(nvd_headers()),
    }
    STATUS.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(status, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
