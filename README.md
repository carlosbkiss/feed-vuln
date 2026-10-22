# Radar Cyber

Protótipo de radar de vulnerabilidades críticas para o setor financeiro, publicado no GitHub Pages.

## Três camadas

| Camada | Frequência | Quem atualiza | Arquivo |
| --- | --- | --- | --- |
| Alertas automáticos | A cada 2h, das 8h17 às 20h17 (SP) | GitHub Actions, regras fixas, sem IA | `data/alertas.json` |
| Triagem diária | Diária | Claude | `data/entradas.json` |
| Resumo da semana | Semanal | Claude | `data/semana.json` |

O `data/status.json` (hora da última verificação e saúde das fontes) é gerado a cada rodada e vai só para o site, não para o git. Assim o histórico só ganha commit quando aparece alerta novo.

## Regras de prioridade dos alertas

| Prioridade | Regra |
| --- | --- |
| P0 | No KEV **e** (borda, acesso, identidade ou CI/CD **ou** CVSS ≥ 9) |
| P1 | No KEV em plataforma corporativa, **ou** CVSS ≥ 9 sem exploração em borda/acesso/CI/CD |
| P2 | CVSS ≥ 9 sem exploração em plataforma corporativa, **ou** KEV fora das listas (shadow IT) |
| fora | CVSS ≥ 9 sem exploração e fora das listas: não vira alerta |

As listas ficam em `config/watchlist.json` e a comparação é por palavra inteira. Termos amplos como "oracle" ou "azure" geram ruído; prefira o produto (`weblogic`, `soa suite`). Mudou a lista, a próxima rodada reaplica as regras a todos os alertas guardados.

## Configuração

1. **Settings → Pages → Source: GitHub Actions**
2. Opcional: **Settings → Secrets and variables → Actions → `NVD_API_KEY`** com uma [chave gratuita da NVD](https://nvd.nist.gov/developers/request-an-api-key). Sem ela funciona, só fica mais lento.
3. **Actions → radar → Run workflow** para a primeira rodada.

## Rodar local

```bash
python scripts/check_feeds.py
python -m http.server 8000
```

Abra `http://localhost:8000`. Abrir o `index.html` direto do disco não funciona porque o navegador bloqueia a leitura dos JSON.

Fontes públicas apenas. Não substitui o advisory do fabricante nem o processo interno de gestão de vulnerabilidades.
