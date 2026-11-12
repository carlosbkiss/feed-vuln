"""Preparo da triagem: tudo o que é regra fixa, antes do Claude entrar.

O que faz:
  1. Aplica a validade dos itens (7 dias; P0 ainda explorado vira "Pendente" por mais 7).
  2. Baixa o KEV e marca kev=true em itens que entraram no catálogo desde a última rodada.
  3. Cruza KEV, data/vulns.json e "sem_cve" com o que já foi triado ou descartado.
  4. Grava .triagem/rascunho.json (ponto de partida que o Claude edita)
     e .triagem/pendencias.json (a lista do que o Claude precisa pesquisar).

O Claude não decide nada disso: só lê as pendências, pesquisa e escreve os itens.

Uso:  python evolucao/scripts/triagem_prep.py [--raiz .] [--sem-kev]
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from triagem_comum import (  # noqa: E402
    JANELA_DIAS, PENDENTE_DIAS_EXTRA, Caminhos, baixar_kev, chave_item, cves_do_item,
    gravar_json, hoje_sp, ler_json, texto_janela,
)


# ---------------------------------------------------------------- regras fixas (testadas em tests/)

def aplicar_validade(itens: list[dict], hoje: date) -> tuple[list[dict], list[str], list[str]]:
    """Devolve (mantidos, viraram_pendente, removidos). Não mexe em itens dentro da janela."""
    corte = hoje - timedelta(days=JANELA_DIAS)
    corte_pendente = corte - timedelta(days=PENDENTE_DIAS_EXTRA)
    mantidos, pendentes, removidos = [], [], []
    for it in itens:
        d = date.fromisoformat(it["data"])
        if d >= corte:
            mantidos.append(it)
            continue
        ainda_explorado = it.get("prioridade") == "P0" and it.get("exploracao", "").startswith("Ativa")
        if ainda_explorado and d >= corte_pendente:
            if it.get("status") != "Pendente":
                pendentes.append(it["cve"])
            mantidos.append({**it, "status": "Pendente"})
        else:
            removidos.append(it["cve"])
    return mantidos, pendentes, removidos


def marcar_kev(itens: list[dict], kev: dict[str, dict]) -> list[dict]:
    """Liga kev=true onde alguma CVE do item está no catálogo. Devolve o que mudou, para o Claude revisar o texto."""
    mudancas = []
    for it in itens:
        no_kev = sorted(c for c in cves_do_item(it) if c in kev)
        if no_kev and not it.get("kev"):
            it["kev"] = True
            mudancas.append({
                "cve": it["cve"],
                "no_kev": no_kev,
                "adicionado": min(kev[c]["dateAdded"] for c in no_kev),
                "prazo": min(kev[c].get("dueDate", "") for c in no_kev),
                "acao": "atualizar 'exploracao' e rever 'prioridade' (entrou no KEV)",
            })
    return mudancas


def ja_coberto(entradas: list[dict], descartes: list[dict],
               kev: dict[str, dict] | None = None) -> tuple[set[str], set[str]]:
    """CVEs e links que já têm destino: triados ou descartados com motivo.
    Descarte que entrou no KEV depois de descartado deixa de valer: o fato novo reabre a pendência."""
    kev = kev or {}
    cves, links = set(), set()
    for it in entradas:
        cves |= cves_do_item(it)
        links |= {f.get("url", "") for f in it.get("fontes", [])}
    for d in descartes:
        if d["chave"] in kev and d.get("data") and kev[d["chave"]].get("dateAdded", "") > d["data"]:
            continue
        (cves if d["chave"].startswith("CVE-") else links).add(d["chave"])
    return cves, links


_GENERICAS = {"microsoft", "google", "cisco", "server", "windows", "linux", "apple", "security", "critical",
              "patch", "update", "flaw", "flaws", "vulnerability", "vulnerabilities", "day", "zero-day", "para",
              "with", "from", "cloud", "gateway", "manager", "enterprise", "self-hosted", "on-premises"}


def _mesmo_assunto(titulo: str, produto: str) -> bool:
    """Heurística simples: o título cita uma palavra distintiva do produto já triado (ex.: 'Barracuda', 'Xen')."""
    palavras = {w for w in re.findall(r"[a-z0-9][a-z0-9.-]{3,}", produto.lower()) if w not in _GENERICAS}
    t = titulo.lower()
    return any(re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", t) for w in palavras)


def montar_pendencias(entradas: list[dict], vulns: dict, kev: dict[str, dict],
                      descartes: list[dict], hoje: date) -> dict:
    cves_ok, links_ok = ja_coberto(entradas, descartes, kev)
    inicio = (hoje - timedelta(days=JANELA_DIAS)).isoformat()

    kev_novos = [
        {"cve": c, "fabricante": v.get("vendorProject"), "produto": v.get("product"),
         "nome": v.get("vulnerabilityName"), "adicionado": v.get("dateAdded"), "prazo": v.get("dueDate"),
         "ransomware": v.get("knownRansomwareCampaignUse"), "descricao": v.get("shortDescription")}
        for c, v in kev.items() if v.get("dateAdded", "") >= inicio and c not in cves_ok
    ]
    kev_novos.sort(key=lambda x: x["adicionado"], reverse=True)

    radar, radar_p2 = [], []
    for v in vulns.get("itens", []):
        if v["cve"] in cves_ok:
            continue
        links = [f.get("link") for f in v.get("fontes", []) if f.get("link")]
        if v.get("prioridade") in ("P0", "P1"):
            radar.append({
                "cve": v["cve"], "prioridade_auto": v.get("prioridade"), "regra": v.get("regra"),
                "produto": v.get("produto"), "titulo": v.get("titulo"), "resumo": v.get("resumo"),
                "cvss": v.get("cvss"), "kev": v.get("kev"), "zero_day": v.get("zero_day"),
                "epss": (v.get("epss") or {}).get("score"), "poc": (v.get("poc") or {}).get("qtd"),
                "links": links,
            })
        elif v.get("prioridade") == "P2":
            # a regra automática não conhece contexto; o Claude decide se algum sobe
            radar_p2.append({"cve": v["cve"], "cvss": v.get("cvss"), "resumo": (v.get("resumo") or v.get("titulo") or "")[:220],
                             "links": links[:2]})

    sem_cve = []
    for s in vulns.get("sem_cve", []):
        if (s.get("publicado") or "")[:10] < inicio or s.get("link") in links_ok:
            continue
        # a mesma notícia sai em vários sites; aponta o item que provavelmente já cobre o caso
        parecidos = [it["cve"] for it in entradas if _mesmo_assunto(s.get("titulo", ""), it.get("produto", ""))]
        sem_cve.append({**s, "parece_coberto_por": parecidos})

    return {"kev_na_janela_sem_triagem": kev_novos, "radar_p0_p1_sem_triagem": radar,
            "radar_p2_para_avaliar": radar_p2, "sem_cve_sem_triagem": sem_cve}


# ---------------------------------------------------------------- execução

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raiz", default=".", help="raiz do repositório")
    ap.add_argument("--sem-kev", action="store_true", help="não baixar o KEV (teste offline)")
    args = ap.parse_args()
    c = Caminhos(args.raiz)
    hoje = hoje_sp()

    entradas = ler_json(c.entradas, {"itens": []})
    vulns = ler_json(c.vulns, {"itens": [], "sem_cve": []})
    descartes = ler_json(c.descartes, {"itens": []})["itens"]
    kev, kev_status = ({}, "pulado (--sem-kev)") if args.sem_kev else baixar_kev()

    # cópia intacta para a publicação calcular "N novos, M atualizados"
    c.trabalho.mkdir(exist_ok=True)
    if c.entradas.exists():
        shutil.copyfile(c.entradas, c.anterior)

    itens, viraram_pendente, removidos = aplicar_validade(entradas.get("itens", []), hoje)
    entrou_no_kev = marcar_kev(itens, kev)
    pend = montar_pendencias(itens, vulns, kev, descartes, hoje)

    # o que venceu vira descarte automático: senão volta amanhã como pendência, porque o radar guarda 14 dias
    venceu = [{"chave": cve, "motivo": "saiu por validade da triagem"}
              for item in removidos for cve in (cves_do_item({"cve": item}) or {item})]
    gravar_json(c.rascunho, {"atualizado": entradas.get("atualizado"), "janela": texto_janela(hoje),
                             "itens": itens, "descartes": venceu})
    gravar_json(c.pendencias, {
        "hoje": hoje.isoformat(), "janela": texto_janela(hoje), "kev": kev_status,
        "validade": {"viraram_pendente": viraram_pendente, "removidos": removidos},
        "entrou_no_kev": entrou_no_kev,
        **pend,
        "ja_triados": sorted(chave_item(i) for i in itens),
    })

    resumo = {k: len(v) for k, v in pend.items()}
    print(f"janela {texto_janela(hoje)} | KEV {kev_status} | itens mantidos {len(itens)} | "
          f"removidos {len(removidos)} | viraram Pendente {len(viraram_pendente)} | entrou no KEV {len(entrou_no_kev)}")
    print("pendências:", resumo)
    # KEV fora do ar não impede a rodada; o Claude é avisado pelo campo "kev"
    return 0


if __name__ == "__main__":
    sys.exit(main())
