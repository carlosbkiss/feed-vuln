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

- **P0**: está no CISA KEV e é de fabricante de borda ou acesso (ou tem CVSS ≥ 9)
- **P1**: está no KEV, ou tem CVSS ≥ 9 em fabricante da lista
- **P2**: CVSS ≥ 9 fora da lista

A lista de fabricantes fica em `config/watchlist.json`.

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
