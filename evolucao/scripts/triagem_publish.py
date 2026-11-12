"""Publicação da triagem: valida o rascunho que o Claude editou e grava data/entradas.json.

O que faz:
  1. Valida cada item contra o esquema (campos, valores permitidos, fontes, datas).
  2. Recusa tudo se houver erro: o arquivo publicado nunca fica pela metade.
  3. Grava data/entradas.json com "atualizado" agora e os itens ordenados por data.
  4. Junta os descartes da rodada em data/triagem_descartes.json (guardados 14 dias),
     para a próxima rodada não pesquisar de novo o que já foi avaliado e deixado de fora.
  5. Imprime a mensagem de commit ("triagem: N novo(s), M atualizado(s)").

Commit, push e PR ficam no workflow, não aqui.

Uso:  python evolucao/scripts/triagem_publish.py [--raiz .] [--verificar]
      --verificar só valida (o Claude roda isso antes de terminar, para corrigir o que faltar)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from triagem_comum import Caminhos, chave_item, gravar_json, hoje_sp, iso_utc, ler_json  # noqa: E402

PRIORIDADES = {"P0", "P1", "P2"}
STATUS = {"Novo", "Pendente", "Resolvido"}
EXPLORACAO = re.compile(r"^(Ativa( \(.+\))?|Exploit público( \(.+\))?|Não confirmada( \(.+\))?|Não( \(.+\))?)$")
CVE_CAMPO = re.compile(r"^(CVE-\d{4}-\d{4,}( / CVE-\d{4}-\d{4,})*|sem CVE \(.+\))$")
DOMINIOS_PROIBIDOS = ("cisa.gov",)   # a ferramenta de leitura é recusada lá; só vale se o link veio do vulns.json
CAMPOS = ["data", "cve", "produto", "cvss", "kev", "zero_day", "exploracao", "prioridade", "tratamento", "fontes", "status"]
DESCARTE_DIAS = 14


def links_do_radar(vulns: dict) -> set[str]:
    links = {f.get("link") for v in vulns.get("itens", []) for f in v.get("fontes", [])}
    links |= {s.get("link") for s in vulns.get("sem_cve", [])}
    return {l for l in links if l}


def validar_item(it: dict, i: int, hoje: date, links_radar: set[str]) -> list[str]:
    e: list[str] = []
    nome = f"item {i} ({it.get('cve', '?')})"
    faltando = [c for c in CAMPOS if c not in it]
    if faltando:
        return [f"{nome}: faltam campos {faltando}"]
    extras = set(it) - set(CAMPOS)
    if extras:
        e.append(f"{nome}: campos fora do esquema {sorted(extras)}")
    try:
        d = date.fromisoformat(it["data"])
        if d > hoje + timedelta(days=1):
            e.append(f"{nome}: data no futuro ({it['data']})")
    except (TypeError, ValueError):
        e.append(f"{nome}: data inválida ({it['data']!r}), use AAAA-MM-DD")
    if not CVE_CAMPO.match(it["cve"]):
        e.append(f"{nome}: 'cve' deve ser 'CVE-... / CVE-...' ou 'sem CVE (produto)'")
    if it["cvss"] is not None and not (isinstance(it["cvss"], (int, float)) and 0 <= it["cvss"] <= 10):
        e.append(f"{nome}: cvss deve ser número de 0 a 10 ou null")
    for b in ("kev", "zero_day"):
        if not isinstance(it[b], bool):
            e.append(f"{nome}: '{b}' deve ser true/false")
    if not EXPLORACAO.match(it["exploracao"]):
        e.append(f"{nome}: 'exploracao' fora do padrão (Ativa | Ativa (detalhe) | Exploit público | Não confirmada | Não)")
    if it["kev"] and not it["exploracao"].startswith("Ativa"):
        e.append(f"{nome}: está no KEV mas 'exploracao' não é 'Ativa'")
    if it["prioridade"] not in PRIORIDADES:
        e.append(f"{nome}: prioridade deve ser P0, P1 ou P2")
    if it["status"] not in STATUS:
        e.append(f"{nome}: status deve ser Novo, Pendente ou Resolvido")
    if not isinstance(it["tratamento"], str) or len(it["tratamento"].strip()) < 30:
        e.append(f"{nome}: 'tratamento' vazio ou curto demais")
    if it["cvss"] is None and "a confirmar" not in it["tratamento"].lower() and it["cve"].startswith("CVE-"):
        e.append(f"{nome}: cvss null exige 'a confirmar' no tratamento")
    fontes = it["fontes"]
    if not isinstance(fontes, list) or not 1 <= len(fontes) <= 3:
        e.append(f"{nome}: 'fontes' precisa de 1 a 3 itens")
    else:
        for f in fontes:
            url = f.get("url", "") if isinstance(f, dict) else ""
            host = urlparse(url).netloc
            if not (isinstance(f, dict) and f.get("nome") and url.startswith("https://") and host):
                e.append(f"{nome}: fonte inválida {f!r} (precisa de nome e url https)")
            elif host.endswith(DOMINIOS_PROIBIDOS) and url not in links_radar:
                e.append(f"{nome}: fonte em {host} só vale se o link veio de data/vulns.json")
    return e


def validar(doc: dict, hoje: date, links_radar: set[str],
            anterior: list[dict] | None = None) -> tuple[list[str], list[str]]:
    """Devolve (erros, avisos). Item herdado sem mudança da rodada anterior só gera aviso:
    a regra nova não trava a publicação por causa de um item que já estava no ar."""
    erros: list[str] = []
    avisos: list[str] = []
    itens = doc.get("itens")
    if not isinstance(itens, list):
        return ["rascunho sem lista 'itens'"], []
    herdados = {chave_item(i): i for i in (anterior or [])}
    vistos: dict[str, int] = {}
    for i, it in enumerate(itens):
        problemas = validar_item(it, i, hoje, links_radar)
        if herdados.get(chave_item(it)) == it:
            avisos += problemas
        else:
            erros += problemas
        k = chave_item(it)
        if k in vistos:
            erros.append(f"item {i} ({it.get('cve')}): duplicado do item {vistos[k]}")
        vistos[k] = i
    for d in doc.get("descartes", []):
        if not (isinstance(d, dict) and d.get("chave") and len(d.get("motivo", "")) >= 10):
            erros.append(f"descarte inválido {d!r} (precisa de 'chave' = CVE ou link, e 'motivo')")
    return erros, avisos


def contar_mudancas(anterior: list[dict], atual: list[dict]) -> tuple[int, int]:
    antes = {chave_item(i): i for i in anterior}
    novos = sum(1 for i in atual if chave_item(i) not in antes)
    atualizados = sum(1 for i in atual if chave_item(i) in antes and antes[chave_item(i)] != i)
    return novos, atualizados


def juntar_descartes(existentes: list[dict], novos: list[dict], hoje: date) -> list[dict]:
    corte = (hoje - timedelta(days=DESCARTE_DIAS)).isoformat()
    por_chave = {d["chave"]: d for d in existentes if d.get("data", "") >= corte}
    for d in novos:
        por_chave[d["chave"]] = {"chave": d["chave"], "motivo": d["motivo"], "data": hoje.isoformat()}
    return sorted(por_chave.values(), key=lambda d: d["data"], reverse=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raiz", default=".")
    ap.add_argument("--verificar", action="store_true", help="só valida, não grava")
    args = ap.parse_args()
    c = Caminhos(args.raiz)
    hoje = hoje_sp()

    doc = ler_json(c.rascunho, None)
    if doc is None:
        print(f"ERRO: {c.rascunho} não existe ou não é JSON válido. Rode o triagem_prep.py antes.")
        return 1
    anterior = ler_json(c.anterior, {"itens": []})["itens"]
    erros, avisos = validar(doc, hoje, links_do_radar(ler_json(c.vulns, {})), anterior)
    if avisos:
        print(f"{len(avisos)} aviso(s) em itens herdados sem mudança (não travam a publicação):")
        print("\n".join(f"  - {a}" for a in avisos))
    if erros:
        print(f"{len(erros)} problema(s) no rascunho:")
        print("\n".join(f"  - {e}" for e in erros))
        return 1
    if args.verificar:
        print(f"rascunho ok: {len(doc['itens'])} itens, {len(doc.get('descartes', []))} descarte(s)")
        return 0

    itens = sorted(doc["itens"], key=lambda x: x["data"], reverse=True)
    novos, atualizados = contar_mudancas(anterior, itens)
    removidos = len({chave_item(i) for i in anterior} - {chave_item(i) for i in itens})

    # mesmo sem mudança nos itens, "atualizado" avança: a página mostra que a triagem rodou
    gravar_json(c.entradas, {"atualizado": iso_utc(), "janela": doc["janela"], "itens": itens})
    desc = juntar_descartes(ler_json(c.descartes, {"itens": []})["itens"], doc.get("descartes", []), hoje)
    gravar_json(c.descartes, {"_comentario": "Avaliados e deixados de fora pela triagem; a próxima rodada não pesquisa de novo.",
                              "itens": desc})

    msg = f"triagem: {novos} novo(s), {atualizados} atualizado(s)"
    print(f"{msg} | saíram {removidos} | descartes guardados {len(desc)}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"mensagem={msg}\nnovos={novos}\natualizados={atualizados}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
