# Radar Cyber

Protótipo de radar de vulnerabilidades críticas e zero-days para o setor financeiro, publicado no GitHub Pages. Testa a hipótese de que **mais fontes + consolidação por CVE + IA detectam antes e com menos ruído do que só a NVD**.

## Camadas

| Camada | Frequência | Quem atualiza | Arquivo |
| --- | --- | --- | --- |
| Radar consolidado | A cada 2h, das 8h17 às 20h17 (SP) | GitHub Actions, regras fixas, sem IA | `data/vulns.json` |
| Triagem diária | 7h31, 11h31, 15h31 | Claude | `data/entradas.json` |
| Resumo da semana | Sexta, 11h46 | Claude | `data/semana.json` |

`data/status.json` (saúde das fontes, big numbers, métricas) e `data/execucoes.json` (log das rodadas) são gerados a cada rodada e vão só para o site. A memória entre rodadas (artigos vistos, candidatos ainda sem nota, saúde das fontes) fica no cache do Actions, em `.estado/`.

## Pipeline (`scripts/radar.py`)

1. **Coleta** dos feeds em `config/fontes.json` (notícias, fabricantes, governo, produto), mais CISA KEV e NVD.
2. **Análise do artigo:** extrai CVEs do texto, marca palavra-chave da RN-004 e sinais de exploração ativa.
3. **Consolidação por CVE:** um registro por vulnerabilidade, com cada fonte, link da notícia e horário de publicação.
4. **Nota:** CVSS da NVD ou do fabricante (CNA). CVE ainda sem nota fica guardada até a nota sair, sem perder o horário da primeira notícia.
5. **Elegibilidade:** zero-day **ou** CVSS ≥ 9 **ou** KEV.
6. **Prioridade** pela watchlist (tabela abaixo).
7. **Enriquecimento:** EPSS (FIRST) e PoC público catalogado ([PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)).
8. **Métricas** do piloto.

### Zero-day

Está no CISA KEV, **ou** um artigo que cita no máximo 3 CVEs fala em exploração ativa. O limite evita que um resumo de Patch Tuesday com 50 CVEs marque todas como exploradas.

### Prioridade

| Prioridade | Regra |
| --- | --- |
| P0 | Explorado (KEV ou notícia) **e** (borda, acesso, identidade ou CI/CD **ou** CVSS ≥ 9) |
| P1 | Explorado em plataforma corporativa, **ou** CVSS ≥ 9 sem exploração em borda/acesso/CI/CD |
| P2 | CVSS ≥ 9 sem exploração em plataforma corporativa, **ou** explorado fora das listas (shadow IT) |
| fora | Crítico fora das listas: não aparece, mas conta nas métricas |

As listas ficam em `config/watchlist.json`, com comparação por palavra inteira. Prefira produtos (`weblogic`, `soa suite`) a fabricantes amplos (`oracle`).

## Métricas do piloto

| Métrica | Como é calculada |
| --- | --- |
| Antecipação vs NVD | Mediana de (publicação na NVD − primeira notícia), em horas |
| Cobertura do KEV | % das entradas da semana no KEV com notícia antes ou no mesmo dia |
| Ruído da RN-004 | Dos artigos que o filtro por palavra-chave marcaria, % que tinham vulnerabilidade no radar |
| Primeira a publicar | Por fonte: em quantas vulnerabilidades do radar ela saiu antes das outras |

## Histórico

Nada se perde: `data/historico/` vai para o git e nunca é apagado.

| Arquivo | Conteúdo |
| --- | --- |
| `radar-AAAA-MM.json` | Catálogo de toda vulnerabilidade que passou pelo radar, pelo mês da primeira aparição: fontes com links, prioridade máxima, KEV, EPSS máximo, PoC, espera pela nota da NVD |
| `diario/AAAA-MM-DD.json` | Foto do dia (primeira rodada e a partir das 19h): métricas, papel de cada fonte, P0 em aberto, falhas por fonte |
| `triagem/AAAA-MM-DD.json` | Última triagem de cada dia |
| `semanas/AAAA-MM-DD.json` | Cada resumo semanal publicado |

A tela mostra os últimos 14 dias; o histórico guarda tudo, para comparar semanas e medir tendência.

## Configuração

1. **Settings → Pages → Source: GitHub Actions**
2. Recomendado: **Settings → Secrets and variables → Actions → `NVD_API_KEY`** com uma [chave gratuita da NVD](https://nvd.nist.gov/developers/request-an-api-key). Sem ela, a NVD limita a ~25 consultas por rodada.
3. **Actions → radar → Run workflow** para rodar na hora.

Para adicionar uma fonte, inclua uma linha em `config/fontes.json`. Fonte que falhar aparece como "falha" na tabela de fontes, sem quebrar o resto.

## Rodar local

```bash
python scripts/radar.py
python -m http.server 8000
```

Fontes públicas apenas. Das notícias, guardamos só título, link e um resumo curto. Não substitui o advisory do fabricante nem o processo interno de gestão de vulnerabilidades.
