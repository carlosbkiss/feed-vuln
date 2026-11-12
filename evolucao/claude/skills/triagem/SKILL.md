---
name: triagem
description: Triagem diária do Radar Cyber. Lê as pendências preparadas pelo triagem_prep.py, pesquisa só o que falta, edita .triagem/rascunho.json e valida com triagem_publish.py --verificar. Use quando o workflow chamar /triagem ou quando pedirem para triar uma CVE do radar.
allowed-tools: Read, Edit, Write, WebFetch, WebSearch, Bash(python evolucao/scripts/triagem_publish.py --verificar)
---

# Triagem diária do Radar Cyber

Você é a camada de julgamento da triagem. A parte mecânica já foi feita antes de você entrar
(`evolucao/scripts/triagem_prep.py`): validade dos itens, marcação de KEV, cruzamento com o radar.
Não refaça essa parte e não edite nenhum arquivo além de `.triagem/rascunho.json` e `.triagem/resumo.md`.

Os critérios de prioridade, o esquema do item e as regras de fonte estão em
[criterios.md](criterios.md). Leia antes de escrever qualquer item.

## Passo a passo

1. **Leia `.triagem/pendencias.json`.** Ele traz:
   - `kev`: se o download do KEV falhou, diga isso no resumo final e siga sem ele.
   - `entrou_no_kev`: itens já triados que entraram no catálogo. O `kev` já está `true`;
     reescreva `exploracao` (ex.: "Ativa (KEV em 11/11, prazo CISA 25/11)") e reveja a prioridade.
   - `validade`: só informativo. Os itens que saíram já viraram descarte automático no rascunho.
   - `kev_na_janela_sem_triagem`, `radar_p0_p1_sem_triagem`: **todos** precisam virar item ou descarte.
   - `radar_p2_para_avaliar`: a regra automática deu P2. Promova só se o contexto de banco justificar
     (ex.: registry de contêiner, gestão de identidade). O resto: descarte com motivo curto.
   - `sem_cve_sem_triagem`: notícias de exploração sem CVE. Se `parece_coberto_por` aponta um item
     do mesmo caso, descarte com o link como chave ("já coberto por CVE-..."). Se é caso novo e
     relevante, crie item com `cve: "sem CVE (produto)"`.

2. **Pesquise só as pendências.** Para cada uma, abra o advisory do fabricante ou uma notícia
   (WebFetch nos links que vieram nas pendências ou num resultado de WebSearch). Confirme versão
   corrigida, data e status de exploração. Snippet de busca não é fonte.

3. **Faça uma busca curta por fora** do que os feeds pegam: zero-day da semana e advisories dos
   produtos do foco (ver criterios.md). Até 4 buscas; não é para repetir a pesquisa inteira.

4. **Edite `.triagem/rascunho.json`:**
   - item novo: `status: "Novo"`, campos conforme criterios.md;
   - item que já existia e teve fato novo: atualize no lugar, sem mudar `data`;
   - o que ficou de fora: em `descartes`, `{"chave": "CVE-..." ou link, "motivo": "..."}`.
     O descarte vale 14 dias; as próximas rodadas não vão perguntar de novo.

5. **Valide:** `python evolucao/scripts/triagem_publish.py --verificar`. Corrija até passar.
   Avisos em itens herdados não travam; corrija se o item for seu.

6. **Escreva o resumo em `.triagem/resumo.md`** (até 120 palavras, português): o mais grave do
   momento, itens novos ou alterados com prioridade e CVE, descartes relevantes e as páginas que
   não abriram. O workflow usa esse arquivo como descrição do PR.

## O que não fazer

- Não abra páginas de cisa.gov (a leitura é recusada); para KEV, as pendências já trazem os dados.
- Não invente CVE, nota, versão, data nem link. Sem confirmação: `cvss: null` e "a confirmar" no tratamento.
- Não repita um WebFetch que falhou; procure o mesmo fato em outra fonte.
- Não cite nenhum banco pelo nome.
- Não faça commit nem push: o workflow cuida disso depois de validar.
