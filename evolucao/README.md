# Evolução da triagem

Proposta para tirar a triagem diária do agendamento no Cowork e levá-la para dentro do repositório,
rodando no GitHub Actions com o Claude Code. **Nada aqui está ativo:** é para ler, testar e discutir.

## A ideia em uma frase

O que é regra fixa vira Python testado; o que é julgamento fica com o Claude, guiado por uma skill
versionada; e a publicação passa por PR, com um analista aprovando.

## Como fica o fluxo

```
 cron 11h31 (SP)
      │
      ▼
 triagem_prep.py ──► .triagem/pendencias.json   (o que falta triar)
      │              .triagem/rascunho.json     (entradas.json com validade e KEV já aplicados)
      ▼
 Claude (/triagem) ─► pesquisa só as pendências, edita o rascunho, roda --verificar até passar
      │              .triagem/resumo.md
      ▼
 triagem_publish.py ─► valida tudo; se ok, grava data/entradas.json e data/triagem_descartes.json
      │
      ▼
 PR "triagem: N novo(s), M atualizado(s)" ──► analista revisa ──► merge ──► radar.yml republica o Pages
```

## Arquivos

| Arquivo | Papel |
| --- | --- |
| `scripts/triagem_comum.py` | Caminhos, leitura/gravação de JSON, janela, identidade do item, download do KEV |
| `scripts/triagem_prep.py` | Validade (7 dias, P0 explorado vira Pendente por mais 7), marca KEV, monta as pendências |
| `scripts/triagem_publish.py` | Valida o esquema e as regras de fonte; grava; conta novos e atualizados |
| `claude/skills/triagem/SKILL.md` | O passo a passo do Claude (substitui o prompt longo da tarefa agendada) |
| `claude/skills/triagem/criterios.md` | Foco, prioridade P0/P1/P2, esquema e regras de texto: o lugar para afinar o julgamento |
| `workflows/triagem.yml` | O workflow do Actions, com o `claude-code-action` |
| `tests/test_triagem.py` | Testes das regras fixas |

## O que muda em relação a hoje

| Hoje (Cowork agendado) | Proposta |
| --- | --- |
| Prompt longo com regras de negócio e de mecânica misturadas | Mecânica em Python; skill curta só com o julgamento |
| O Claude aplica a validade de 7/14 dias "de cabeça" | `aplicar_validade()` com teste |
| KEV pela ferramenta de leitura web, que pode pedir permissão e falhar | Download direto em Python, com espelho no GitHub |
| JSON validado só como "abre ou não abre" | Validação de campo a campo, valores permitidos, fontes, duplicados |
| Push direto em main | PR para revisão humana |
| Itens deixados de fora são reavaliados toda rodada | `data/triagem_descartes.json` guarda o motivo por 14 dias |
| Item que venceu pode voltar como pendência (o radar guarda 14 dias) | O que vence vira descarte automático |

## Testar localmente

Da raiz do repositório:

```bash
python -m unittest discover -s evolucao/tests -v
python evolucao/scripts/triagem_prep.py            # use --sem-kev para rodar sem internet
cat .triagem/pendencias.json
python evolucao/scripts/triagem_publish.py --verificar
```

Com o rascunho intacto, o `--verificar` já mostra avisos reais nos dados de hoje
(um item com `cvss: null` sem "a confirmar", uma fonte de cisa.gov que não veio do radar).
Avisos em itens herdados não travam a publicação; erros em itens novos ou alterados travam.

Para ver o Claude rodando a skill localmente com o Claude Code: copie a pasta da skill para
`.claude/skills/triagem/`, rode o prep e depois `claude "/triagem"`.

## Como ativar (quando decidir)

1. `git mv evolucao/claude/skills/triagem .claude/skills/triagem`
2. `git mv evolucao/workflows/triagem.yml .github/workflows/triagem.yml`
3. Acrescentar `.triagem/` ao `.gitignore`.
4. Instalar o Claude GitHub App no repositório e criar o secret `ANTHROPIC_API_KEY`
   (ou configurar OIDC, Bedrock, Vertex ou Foundry: ver comentários no workflow).
5. Rodar uma vez pela aba Actions (`workflow_dispatch`) e comparar o PR com a triagem do Cowork do mesmo dia.
6. Só então desligar a tarefa agendada no Cowork.

O `index.html` não precisa mudar: `data/entradas.json` mantém o mesmo esquema.
`data/triagem_descartes.json` é novo e o site ignora.

## Pontos para decidir

- **PR todo dia, mesmo sem novidade?** Hoje o `atualizado` sempre avança, para a página mostrar que a
  triagem rodou. Com PR, isso vira um PR diário. Alternativas: merge automático quando só o
  `atualizado` mudou, ou mostrar a hora da última rodada a partir do log do Actions.
- **Busca na web no Actions.** Não está claro na documentação se a busca na web funciona igual
  no runner. Se não funcionar, a skill fica só com WebFetch nos links das pendências, o que já cobre
  a maior parte; dá para acrescentar feeds de fabricantes no `config/fontes.json` para compensar.
- **Lista de domínios permitidos.** No Enterprise, dá para limitar o WebFetch a domínios conhecidos
  (fabricantes e sites de notícia) via `permissions.allow` nas configurações. Mais seguro, mas uma
  fonte nova passa a exigir mudar a lista.
- **Heurística do `parece_coberto_por`.** Para notícias sem CVE, o prep compara palavras do título com
  o produto dos itens já triados. É uma dica para o Claude, não uma decisão; pode errar para os dois lados.
- **Prazo dos descartes (14 dias).** Um descarte que entra no KEV depois de descartado volta como
  pendência na hora. Outros fatos novos (exploit público, notícia de ataque) ainda não reabrem: só quando o descarte vence.
- **Modelo e custo.** `--max-turns 60` limita a rodada. Vale medir algumas rodadas antes de fixar o modelo.
