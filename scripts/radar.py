"""Radar Cyber: coleta multi-fonte, consolidação por CVE, enriquecimento e métricas.

Roda no GitHub Actions a cada 2h (8h-20h de SP). Só biblioteca padrão.

Saídas
  data/vulns.json        itens exibidos (elegíveis e no escopo). Vai para o git só quando muda.
  data/status.json       saúde das fontes, big numbers e métricas do piloto. Só no site.
  data/execucoes.json    log das últimas rodadas. Só no site.
  .estado/               memória entre rodadas (cache do Actions): artigos vistos,
                         candidatos ainda não elegíveis, saúde das fontes, log.

Regras (resumo; detalhes no README)
  Elegível  = zero-day OU CVSS >= 9 OU está no CISA KEV.
  Zero-day  = está no KEV, ou um artigo com até 3 CVEs fala em exploração ativa.
  Prioridade = regras de config/watchlist.json (P0/P1/P2; fora do escopo não aparece).
  Palavras-chave da RN-004 só pré-classificam artigos e alimentam a métrica de ruído.
"""

from __future__ import annotations

import html
import json
import os
import re
import statistics
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ESTADO = ROOT / ".estado"
VULNS = DATA / "vulns.json"
STATUS = DATA / "status.json"
EXECUCOES_SITE = DATA / "execucoes.json"
CFG_FONTES = ROOT / "config" / "fontes.json"
CFG_WATCH = ROOT / "config" / "watchlist.json"

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
POC_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{ano}/{cve}.json"
POC_PAGE = "https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{ano}/{cve}.json"

UA = "Mozilla/5.0 (compatible; radar-cyber/2.0; +https://github.com/carlosbkiss/feed-vuln)"
CVSS_CORTE = 9.0
JANELA_NVD_DIAS = 3
RETENCAO_DIAS = 14
JANELA_METRICAS_DIAS = 7
MAX_CVES_POR_ARTIGO_PARA_FLAG = 3
NVD_CHECK_INTERVALO_H = 6
POC_CHECK_INTERVALO_H = 24

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)

# RN-004 (palavras-chave da especificação), comparadas sem acento e sem maiúsculas
KEYWORDS_RN004 = [
    "critico", "critical", "cve critico", "critical cve", "vulnerabilidade critica",
    "critical vulnerability", "vulnerabilidades criticas", "critical vulnerabilities",
    "dia-zero", "zero-day", "0-day", "0day", "zeroday", "diazero", "zero day", "dia zero",
]
# sinais de exploração real (mais estritos que a RN-004)
EXPLORACAO = [
    "exploited in the wild", "actively exploited", "under active exploitation",
    "exploited in attacks", "exploited as a zero-day", "exploited zero-day", "zero-day exploited",
    "exploited as zero-day", "in-the-wild exploitation", "exploitation in the wild",
    "explorada ativamente", "exploracao ativa", "explorado ativamente", "sendo explorad",
]

TRATAMENTO = {
    "P0": "Explorado em borda, acesso, identidade ou CI/CD: corrigir em até 24h e caçar IOCs retroativos.",
    "P1-EXP": "Explorado em plataforma corporativa: confirmar inventário e corrigir em até 72h.",
    "P1-WATCH": "Crítico em borda, acesso ou CI/CD, sem exploração confirmada: checar exposição; exposto à internet vira P0.",
    "P2": "Crítico em plataforma corporativa, sem exploração: confirmar no inventário e corrigir no ciclo normal.",
    "P2-KEV": "Explorado, mas fora do parque típico de banco: se aparecer no inventário, é shadow IT; remover ou corrigir.",
}


# ---------------------------------------------------------------- utilidades

def agora() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        if len(s) == 10:
            return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_data_feed(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, IndexError):
        return parse_iso(s)


def norm(t: str) -> str:
    t = unicodedata.normalize("NFKD", t or "")
    return "".join(c for c in t if not unicodedata.combining(c)).lower()


def limpar_html(t: str | None) -> str:
    t = re.sub(r"<[^>]+>", " ", t or "")
    t = html.unescape(t)
    return re.sub(r"\s+", " ", t).strip()


def curto(t: str, n: int = 260) -> str:
    return t if len(t) <= n else t[: n - 1].rsplit(" ", 1)[0] + "…"


def http_get(url: str, headers: dict | None = None, tentativas: int = 2, timeout: int = 40) -> tuple[int, bytes]:
    h = {"User-Agent": UA, "Accept": "*/*"}
    h.update(headers or {})
    ultimo: Exception | None = None
    for i in range(tentativas):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 404, b""
            ultimo = e
            if e.code in (403, 401):
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            ultimo = e
        time.sleep(4 * (i + 1))
    raise RuntimeError(str(ultimo)[:160])


def get_json(url: str, headers: dict | None = None) -> dict:
    status, corpo = http_get(url, {"Accept": "application/json", **(headers or {})})
    if status == 404:
        return {}
    return json.loads(corpo.decode("utf-8"))


def ler_json(p: Path, padrao):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return padrao


def gravar_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def ano_cve(cve: str) -> str:
    return cve.split("-")[1]


# ---------------------------------------------------------------- watchlist e prioridade

def carregar_watchlist() -> tuple[re.Pattern, re.Pattern]:
    cfg = json.loads(CFG_WATCH.read_text(encoding="utf-8"))

    def padrao(termos: list[str]) -> re.Pattern:
        return re.compile("|".join(r"(?<![a-z0-9])" + re.escape(norm(t)) + r"(?![a-z0-9])" for t in termos))

    return padrao(cfg["borda_e_acesso"]), padrao(cfg["plataformas_corporativas"])


def priorizar(texto: str, cvss: float | None, explorado: bool, borda: re.Pattern, corp: re.Pattern):
    t = norm(texto)
    em_borda, em_corp = bool(borda.search(t)), bool(corp.search(t))
    nota = cvss or 0.0
    if explorado and (em_borda or nota >= CVSS_CORTE):
        return "P0", "explorado + borda/acesso ou CVSS ≥ 9", TRATAMENTO["P0"]
    if explorado and em_corp:
        return "P1", "explorado em plataforma corporativa", TRATAMENTO["P1-EXP"]
    if explorado:
        return "P2", "explorado fora das listas", TRATAMENTO["P2-KEV"]
    if nota >= CVSS_CORTE and em_borda:
        return "P1", "CVSS ≥ 9 em borda/acesso", TRATAMENTO["P1-WATCH"]
    if nota >= CVSS_CORTE and em_corp:
        return "P2", "CVSS ≥ 9 em plataforma corporativa", TRATAMENTO["P2"]
    return None, "", ""


# ---------------------------------------------------------------- feeds RSS/Atom

def _txt(el, *nomes) -> str:
    for nome in nomes:
        for filho in el:
            tag = filho.tag.split("}")[-1]
            if tag == nome:
                if nome == "link" and filho.get("href"):
                    if filho.get("rel", "alternate") == "alternate":
                        return filho.get("href")
                    continue
                return (filho.text or "").strip()
    return ""


def ler_feed(fonte: dict) -> list[dict]:
    _, corpo = http_get(fonte["feed"], {"Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"})
    raiz = ET.fromstring(corpo)
    itens = [e for e in raiz.iter() if e.tag.split("}")[-1] in ("item", "entry")]
    artigos = []
    for it in itens:
        titulo = limpar_html(_txt(it, "title"))
        link = _txt(it, "link") or _txt(it, "guid", "id")
        data = parse_data_feed(_txt(it, "pubDate", "published", "updated", "date"))
        resumo = limpar_html(_txt(it, "description", "summary"))
        conteudo = limpar_html(_txt(it, "encoded", "content"))
        if not titulo or not link:
            continue
        artigos.append({
            "fonte": fonte["id"], "titulo": titulo, "link": link.strip(),
            "publicado": iso(data), "resumo": curto(resumo or conteudo),
            "_texto": f"{titulo} {resumo} {conteudo}",
        })
    return artigos


def analisar_artigo(a: dict) -> dict:
    texto = a.pop("_texto", "")
    t = norm(texto)
    cves = sorted({f"CVE-{m.group(1)}-{m.group(2)}" for m in CVE_RE.finditer(texto)})
    a["cves"] = cves[:40]
    a["keyword_rn004"] = any(k in t for k in KEYWORDS_RN004)
    a["exploracao"] = any(k in t for k in EXPLORACAO) or bool(re.search(r"\bzero[- ]?day\b.{0,40}\bexploit", t))
    return a


# ---------------------------------------------------------------- fontes estruturadas

def buscar_kev() -> tuple[dict, str]:
    ultimo = ""
    for url in KEV_URLS:
        try:
            dados = get_json(url)
            return {v["cveID"]: v for v in dados.get("vulnerabilities", [])}, "ok"
        except Exception as e:
            ultimo = str(e)
    return {}, f"erro: {ultimo[:120]}"


def nvd_headers() -> dict:
    k = os.environ.get("NVD_API_KEY", "").strip()
    return {"apiKey": k} if k else {}


def pausa_nvd() -> None:
    time.sleep(0.8 if nvd_headers() else 6.5)


def extrair_cvss(cve: dict) -> tuple[float | None, str, str]:
    melhor: tuple[float | None, str, str] = (None, "", "")
    for chave, versao in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        for m in cve.get("metrics", {}).get(chave, []):
            nota = m.get("cvssData", {}).get("baseScore")
            if nota is None:
                continue
            origem = "NVD" if m.get("type") == "Primary" and "nvd@nist.gov" in m.get("source", "") else "CNA"
            if melhor[0] is None or float(nota) > melhor[0]:
                melhor = (float(nota), versao, origem)
    return melhor


def descricao_nvd(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def nvd_criticos(desde: datetime, ate: datetime) -> tuple[dict, str]:
    vistos: dict[str, dict] = {}
    try:
        for filtro in ("cvssV3Severity", "cvssV4Severity"):
            inicio = 0
            while True:
                q = {
                    "pubStartDate": desde.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "pubEndDate": ate.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    filtro: "CRITICAL", "resultsPerPage": 2000, "startIndex": inicio,
                }
                d = get_json(NVD_URL + "?" + urllib.parse.urlencode(q), nvd_headers())
                for v in d.get("vulnerabilities", []):
                    vistos[v["cve"]["id"]] = v["cve"]
                inicio += d.get("resultsPerPage") or 2000
                pausa_nvd()
                if inicio >= d.get("totalResults", 0):
                    break
        return vistos, "ok"
    except Exception as e:
        return vistos, f"erro: {str(e)[:120]}"


def nvd_por_id(cve_id: str) -> dict | None:
    try:
        d = get_json(NVD_URL + "?" + urllib.parse.urlencode({"cveId": cve_id}), nvd_headers())
        pausa_nvd()
        vs = d.get("vulnerabilities", [])
        return vs[0]["cve"] if vs else {}
    except Exception:
        return None


def buscar_epss(cves: list[str]) -> tuple[dict, str]:
    res: dict[str, dict] = {}
    try:
        for i in range(0, len(cves), 50):
            lote = ",".join(cves[i:i + 50])
            d = get_json(EPSS_URL + "?" + urllib.parse.urlencode({"cve": lote}))
            for r in d.get("data", []):
                res[r["cve"]] = {"score": round(float(r["epss"]), 4), "percentil": round(float(r["percentile"]), 4), "data": r.get("date")}
        return res, "ok"
    except Exception as e:
        return res, f"erro: {str(e)[:120]}"


def buscar_poc(cve: str) -> dict | None:
    try:
        status, corpo = http_get(POC_RAW.format(ano=ano_cve(cve), cve=cve), tentativas=1, timeout=20)
        if status == 404:
            return {"qtd": 0, "link": None}
        repos = json.loads(corpo.decode("utf-8"))
        return {"qtd": len(repos), "link": POC_PAGE.format(ano=ano_cve(cve), cve=cve) if repos else None}
    except Exception:
        return None


# ---------------------------------------------------------------- principal

def main() -> int:
    t0 = agora()
    inicio_relogio = time.time()
    DATA.mkdir(exist_ok=True)
    ESTADO.mkdir(exist_ok=True)

    fontes_cfg = json.loads(CFG_FONTES.read_text(encoding="utf-8"))["fontes"]
    nomes = {f["id"]: f for f in fontes_cfg}
    borda, corp = carregar_watchlist()

    artigos_mem = ler_json(ESTADO / "artigos.json", {})          # link -> artigo
    candidatos = ler_json(ESTADO / "candidatos.json", {})        # cve -> registro não exibido
    saude = ler_json(ESTADO / "saude.json", {})                  # fonte -> {ultimo_ok, ...}
    execucoes = ler_json(ESTADO / "execucoes.json", [])
    vulns_ant = ler_json(VULNS, {"itens": []})
    registros: dict[str, dict] = {i["cve"]: i for i in vulns_ant.get("itens", [])}
    ids_exibidos_antes = set(registros)
    registros.update({k: v for k, v in candidatos.items() if k not in registros})

    def reg(cve: str) -> dict:
        if cve not in registros:
            registros[cve] = {"cve": cve, "fontes": [], "detectado": iso(t0)}
        return registros[cve]

    def add_fonte(r: dict, fid: str, nome: str, titulo: str, link: str, publicado: str | None) -> bool:
        for f in r["fontes"]:
            if f["link"] == link:
                return False
        r["fontes"].append({"id": fid, "nome": nome, "titulo": curto(titulo, 160), "link": link,
                            "publicado": publicado, "visto_em": iso(t0)})
        return True

    # 1) feeds
    artigos_novos = 0
    status_fontes = {}
    for f in fontes_cfg:
        st = saude.get(f["id"], {})
        if not f.get("ativo"):
            status_fontes[f["id"]] = {"estado": "inativa", "obs": f.get("obs", "")}
            continue
        try:
            lidos = ler_feed(f)
            novos = 0
            for a in lidos:
                if a["link"] in artigos_mem:
                    continue
                a = analisar_artigo(a)
                a["coletado"] = iso(t0)
                artigos_mem[a["link"]] = a
                novos += 1
            artigos_novos += novos
            st.update({"ultimo_ok": iso(t0), "erro": None, "itens_feed": len(lidos), "novos_ultima": novos})
            status_fontes[f["id"]] = {"estado": "ok"}
        except Exception as e:
            st.update({"erro": str(e)[:140], "ultima_falha": iso(t0)})
            status_fontes[f["id"]] = {"estado": "erro", "erro": str(e)[:140]}
        saude[f["id"]] = st

    # descarta artigos velhos da memória
    limite_mem = t0 - timedelta(days=RETENCAO_DIAS)
    artigos_mem = {k: a for k, a in artigos_mem.items()
                   if (parse_iso(a.get("publicado")) or parse_iso(a.get("coletado")) or t0) >= limite_mem}

    # 2) artigos -> registros por CVE
    sem_cve = []
    for a in artigos_mem.values():
        f = nomes.get(a["fonte"], {"nome": a["fonte"]})
        if not a["cves"]:
            if a["exploracao"]:
                sem_cve.append({"fonte": f["nome"], "titulo": a["titulo"], "link": a["link"], "publicado": a["publicado"]})
            continue
        poucas = len(a["cves"]) <= MAX_CVES_POR_ARTIGO_PARA_FLAG
        for c in a["cves"]:
            r = reg(c.upper())
            add_fonte(r, a["fonte"], f["nome"], a["titulo"], a["link"], a["publicado"])
            if poucas and a["exploracao"] and not r.get("zero_day"):
                r["zero_day"] = True
                r["zero_day_motivo"] = f"{f['nome']}: exploração ativa relatada"
            if poucas:
                r.setdefault("_titulos", set()).add(a["titulo"])

    # 3) KEV
    kev, st_kev = buscar_kev()
    status_fontes["kev"] = {"estado": "ok" if st_kev == "ok" else "erro", "erro": None if st_kev == "ok" else st_kev}
    limite_kev = (t0 - timedelta(days=RETENCAO_DIAS)).strftime("%Y-%m-%d")
    for cve_id, v in kev.items():
        if v.get("dateAdded", "") >= limite_kev or cve_id in registros:
            r = reg(cve_id)
            r["kev"] = {"adicionado": v.get("dateAdded"), "prazo": v.get("dueDate"),
                        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown")}
            r["produto"] = f'{v.get("vendorProject", "")} {v.get("product", "")}'.strip()
            r["titulo"] = v.get("vulnerabilityName", "")
            r.setdefault("resumo", curto(v.get("shortDescription", "")))
            add_fonte(r, "kev", "CISA KEV", v.get("vulnerabilityName", cve_id),
                      f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
                      v.get("dateAdded"))

    # 4) NVD: críticos recentes + consulta individual de quem veio de notícia/KEV
    criticos, st_nvd = nvd_criticos(t0 - timedelta(days=JANELA_NVD_DIAS), t0)
    status_fontes["nvd"] = {"estado": "ok" if st_nvd == "ok" else "erro", "erro": None if st_nvd == "ok" else st_nvd}

    def aplicar_nvd(r: dict, cve: dict) -> None:
        nota, versao, origem = extrair_cvss(cve)
        r["cvss"], r["cvss_versao"], r["cvss_fonte"] = nota, versao, origem
        r["publicado_nvd"] = (cve.get("published") or "")[:19] + "Z" if cve.get("published") else None
        if not r.get("resumo"):
            r["resumo"] = curto(descricao_nvd(cve))
        r["nvd_checado_em"] = iso(t0)

    for cve_id, cve in criticos.items():
        r = reg(cve_id)
        aplicar_nvd(r, cve)
        add_fonte(r, "nvd", "NVD", cve_id, f"https://nvd.nist.gov/vuln/detail/{cve_id}", r["publicado_nvd"])

    limite_consultas = 120 if nvd_headers() else 25
    consultas = 0
    fila = []
    for cve_id, r in registros.items():
        if cve_id in criticos:
            continue
        veio_de_texto = any(f["id"] not in ("nvd",) and nomes.get(f["id"], {}).get("grupo") in ("noticias", "governo") for f in r["fontes"])
        relevante = veio_de_texto or r.get("kev") or r.get("zero_day")
        checado = parse_iso(r.get("nvd_checado_em"))
        if relevante and (not checado or (r.get("cvss") is None and t0 - checado > timedelta(hours=NVD_CHECK_INTERVALO_H))):
            fila.append(cve_id)
    fila.sort(key=lambda c: (not registros[c].get("kev"), not registros[c].get("zero_day")))
    for cve_id in fila[:limite_consultas]:
        cve = nvd_por_id(cve_id)
        consultas += 1
        if cve is None:
            continue
        r = registros[cve_id]
        if cve:
            aplicar_nvd(r, cve)
            add_fonte(r, "nvd", "NVD", cve_id, f"https://nvd.nist.gov/vuln/detail/{cve_id}", r["publicado_nvd"])
        else:
            r["nvd_checado_em"] = iso(t0)

    # 5) elegibilidade e prioridade
    exibidos: dict[str, dict] = {}
    novos_candidatos: dict[str, dict] = {}
    elegiveis_fora = 0
    for cve_id, r in registros.items():
        titulos = r.pop("_titulos", set())
        if r.get("kev"):
            r["zero_day"] = True
            r["zero_day_motivo"] = "CISA KEV"
        motivos = []
        if r.get("zero_day"):
            motivos.append("zero-day")
        if (r.get("cvss") or 0) >= CVSS_CORTE:
            motivos.append("CVSS ≥ 9")
        if r.get("kev"):
            motivos.append("KEV")
        r["elegivel_por"] = motivos
        datas = [parse_iso(f.get("publicado")) or parse_iso(f.get("visto_em")) for f in r["fontes"]]
        datas = [d for d in datas if d]
        r["primeira_vez"] = iso(min(datas)) if datas else r.get("detectado")
        noticias = [parse_iso(f.get("publicado")) for f in r["fontes"] if f["id"] not in ("nvd", "kev") and f.get("publicado")]
        noticias = [d for d in noticias if d]
        r["primeira_noticia"] = iso(min(noticias)) if noticias else None
        r["link_nvd"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        texto = " ".join([r.get("produto", ""), r.get("titulo", ""), r.get("resumo", "")] + sorted(titulos))
        if not motivos:
            novos_candidatos[cve_id] = r
            continue
        p, regra, trat = priorizar(texto, r.get("cvss"), bool(r.get("kev") or r.get("zero_day")), borda, corp)
        if p is None:
            elegiveis_fora += 1
            if any(f["id"] not in ("nvd",) for f in r["fontes"]):
                novos_candidatos[cve_id] = r      # guarda a proveniência, mas não exibe
            continue
        if r.get("prioridade") and r["prioridade"] != p and p == "P0":
            r["escalado"] = True
        if cve_id not in ids_exibidos_antes:
            r["exibido_em"] = iso(t0)
        r.update({"prioridade": p, "regra": regra, "tratamento": trat})
        r["fontes"].sort(key=lambda f: f.get("publicado") or f.get("visto_em") or "")
        exibidos[cve_id] = r

    # retenção
    lim = iso(t0 - timedelta(days=RETENCAO_DIAS))
    exibidos = {k: v for k, v in exibidos.items()
                if (v.get("primeira_vez") or "") >= lim or ((v.get("kev") or {}).get("adicionado") or "") >= lim[:10]}
    novos_candidatos = {k: v for k, v in novos_candidatos.items() if (v.get("primeira_vez") or v.get("detectado") or "") >= lim}

    # 6) enriquecimento: EPSS (diário) e PoC (24h)
    hoje = t0.strftime("%Y-%m-%d")
    precisa_epss = [c for c, r in exibidos.items() if (r.get("epss") or {}).get("data") != hoje]
    epss, st_epss = buscar_epss(precisa_epss) if precisa_epss else ({}, "ok")
    status_fontes["epss"] = {"estado": "ok" if st_epss == "ok" else "erro", "erro": None if st_epss == "ok" else st_epss}
    for c, e in epss.items():
        exibidos[c]["epss"] = e
    pocs = 0
    for c, r in sorted(exibidos.items(), key=lambda kv: kv[1]["prioridade"]):
        chk = parse_iso((r.get("poc") or {}).get("checado"))
        if pocs >= 40 or (chk and t0 - chk < timedelta(hours=POC_CHECK_INTERVALO_H)):
            continue
        p = buscar_poc(c)
        pocs += 1
        if p is not None:
            p["checado"] = iso(t0)
            r["poc"] = p
    status_fontes["poc"] = {"estado": "ok"}

    # 7) gravar vulns.json só se mudou de verdade
    ordem = {"P0": 0, "P1": 1, "P2": 2}
    itens = sorted(exibidos.values(), key=lambda r: (ordem[r["prioridade"]], -(parse_iso(r["primeira_vez"]) or t0).timestamp()))
    sem_cve.sort(key=lambda a: a.get("publicado") or "", reverse=True)
    conteudo = {"itens": itens, "sem_cve": sem_cve[:25]}

    def sem_volateis(obj):
        s = json.dumps(obj, sort_keys=True, ensure_ascii=False)
        return re.sub(r'"(checado|nvd_checado_em|visto_em)": "[^"]*"', "", s)

    anterior_cmp = {"itens": vulns_ant.get("itens", []), "sem_cve": vulns_ant.get("sem_cve", [])}
    if sem_volateis(conteudo) != sem_volateis(anterior_cmp):
        gravar_json(VULNS, {"atualizado": iso(t0), **conteudo})

    gravar_json(ESTADO / "artigos.json", artigos_mem)
    gravar_json(ESTADO / "candidatos.json", novos_candidatos)

    # 8) métricas do piloto (janela de 7 dias)
    j = t0 - timedelta(days=JANELA_METRICAS_DIAS)
    na_janela = [r for r in itens if (parse_iso(r["primeira_vez"]) or t0) >= j]
    arts = [a for a in artigos_mem.values() if (parse_iso(a.get("publicado")) or parse_iso(a.get("coletado")) or t0) >= j]
    exibidos_ids = {r["cve"] for r in itens}
    kw = [a for a in arts if a["keyword_rn004"]]
    kw_util = [a for a in kw if set(a["cves"]) & exibidos_ids]

    deltas_nvd, deltas_kev = [], []
    for r in itens:
        pn = parse_iso(r.get("primeira_noticia"))
        nvd_pub = parse_iso(r.get("publicado_nvd"))
        if pn and nvd_pub:
            deltas_nvd.append((nvd_pub - pn).total_seconds() / 3600)
        if pn and r.get("kev"):
            deltas_kev.append((parse_iso(r["kev"]["adicionado"]).date() - pn.date()).days)

    kev_semana = [r for r in itens if r.get("kev") and r["kev"]["adicionado"] >= j.strftime("%Y-%m-%d")]
    kev_rel = [r for r in kev_semana if r["prioridade"] in ("P0", "P1")]

    def antes_do_kev(r):
        pn = parse_iso(r.get("primeira_noticia"))
        return bool(pn and pn.date() <= parse_iso(r["kev"]["adicionado"]).date())

    contrib = {}
    for f in fontes_cfg:
        meus = [a for a in arts if a["fonte"] == f["id"]]
        cves_f = {c for a in meus for c in a["cves"]} & exibidos_ids
        contrib[f["id"]] = {"artigos": len(meus), "cves_elegiveis": len(cves_f), "primeira": 0}
    for r in na_janela:
        cand = [(f.get("publicado"), f["id"]) for f in r["fontes"] if f["id"] in contrib and f.get("publicado")]
        if cand:
            contrib[min(cand)[1]]["primeira"] += 1

    def mediana(xs):
        return round(statistics.median(xs), 1) if xs else None

    fontes_saida = []
    for f in fontes_cfg:
        s = saude.get(f["id"], {})
        fontes_saida.append({
            "id": f["id"], "nome": f["nome"], "site": f["site"], "grupo": f["grupo"],
            "estado": status_fontes.get(f["id"], {}).get("estado", "inativa"),
            "erro": status_fontes.get(f["id"], {}).get("erro") or s.get("erro"),
            "obs": f.get("obs", ""), "ultimo_ok": s.get("ultimo_ok"), **contrib.get(f["id"], {}),
        })
    ativas = [f for f in fontes_saida if f["estado"] != "inativa"]

    metricas = {
        "janela_dias": JANELA_METRICAS_DIAS,
        "elegiveis": len(na_janela),
        "explorados": sum(1 for r in na_janela if r.get("zero_day")),
        "p0": sum(1 for r in na_janela if r["prioridade"] == "P0"),
        "p1": sum(1 for r in na_janela if r["prioridade"] == "P1"),
        "p2": sum(1 for r in na_janela if r["prioridade"] == "P2"),
        "com_poc": sum(1 for r in na_janela if (r.get("poc") or {}).get("qtd")),
        "epss_alto": sum(1 for r in na_janela if (r.get("epss") or {}).get("percentil", 0) >= 0.95),
        "fora_do_escopo": elegiveis_fora,
        "artigos": len(arts),
        "artigos_com_cve": sum(1 for a in arts if a["cves"]),
        "keyword_rn004": len(kw),
        "keyword_rn004_util": len(kw_util),
        "keyword_precisao": round(len(kw_util) / len(kw), 3) if kw else None,
        "antecipacao_nvd_mediana_h": mediana(deltas_nvd),
        "antes_da_nvd_pct": round(sum(1 for d in deltas_nvd if d > 0) / len(deltas_nvd), 3) if deltas_nvd else None,
        "antecipacao_nvd_n": len(deltas_nvd),
        "antecipacao_kev_mediana_dias": mediana(deltas_kev),
        "kev_semana": len(kev_semana),
        "kev_relevantes": len(kev_rel),
        "kev_com_noticia_antes": sum(1 for r in kev_semana if antes_do_kev(r)),
        "kev_cobertura_pct": round(sum(1 for r in kev_semana if antes_do_kev(r)) / len(kev_semana), 3) if kev_semana else None,
        "sem_cve_exploracao": len(sem_cve),
        "fontes_ok": sum(1 for f in ativas if f["estado"] == "ok"),
        "fontes_total": len(ativas),
    }

    novos_rodada = [r["cve"] for r in itens if r.get("exibido_em") == iso(t0)]
    duracao = round(time.time() - inicio_relogio, 1)
    rodada = {
        "inicio": iso(t0), "duracao_s": duracao,
        "fontes_ok": metricas["fontes_ok"], "fontes_total": metricas["fontes_total"],
        "fontes_erro": [f["nome"] for f in ativas if f["estado"] == "erro"],
        "artigos_novos": artigos_novos, "consultas_nvd": consultas,
        "exibidos": len(itens), "novos": len(novos_rodada), "kev": st_kev, "nvd": st_nvd,
    }
    execucoes = ([rodada] + execucoes)[:60]
    gravar_json(ESTADO / "execucoes.json", execucoes)
    gravar_json(ESTADO / "saude.json", saude)
    gravar_json(EXECUCOES_SITE, execucoes)

    ultimo_alerta = max((r.get("exibido_em") or r["detectado"] for r in itens), default=None)
    gravar_json(STATUS, {
        "ultima_verificacao": iso(t0),
        "ultimo_alerta": ultimo_alerta,
        "novos_nesta_rodada": novos_rodada,
        "fontes": fontes_saida,
        "estruturadas": {k: status_fontes.get(k, {}) for k in ("kev", "nvd", "epss", "poc")},
        "chave_nvd": bool(nvd_headers()),
        "metricas": metricas,
    })
    print(json.dumps(rodada, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
