# Critérios da triagem

Fonte única das regras de julgamento. O `triagem_publish.py` valida o formato; o conteúdo é com você.

## Foco

O que importa para um grande banco, nesta ordem:

1. **Borda e acesso:** Fortinet, Cisco, Palo Alto, Ivanti, Citrix, F5, SonicWall, BeyondTrust, CyberArk.
2. **Identidade e SSO:** Okta, Entra ID, ADFS, Ping, Oracle Access Manager.
3. **CI/CD e cadeia de software:** GitLab, Jenkins, GitHub Enterprise, Nexus, Artifactory, registries.
4. **Plataformas corporativas:** Microsoft (Exchange, SharePoint, Windows), Oracle (WebLogic, SOA, EBS, DB),
   SAP, Atlassian, VMware.
5. **Runtimes amplamente usados:** PHP, Java, OpenSSL, OpenSSH, bibliotecas como Brotli.
6. **Terceiros com acesso ao ambiente:** RMM e acesso remoto de MSPs (ScreenConnect, N-central).

## Prioridade

| Prioridade | Quando |
| --- | --- |
| P0 | Explorado ou com exploit público em borda, acesso, identidade, CI/CD ou middleware exposto; ou RCE sem login com CVSS ≥ 9.8 em plataforma muito presente em banco |
| P1 | Crítico relevante sem exploração; ou explorado em plataforma corporativa interna; ou explorado em terceiro com acesso ao ambiente |
| P2 | Nicho, shadow IT ou baixo uso em banco |

Pode divergir da prioridade automática do radar (`prioridade_auto`); quando divergir, o motivo
deve ficar claro no `tratamento`.

## Esquema do item

```json
{
  "data": "AAAA-MM-DD",            // publicação do advisory ou entrada no KEV
  "cve": "CVE-2026-1234 / CVE-2026-5678",   // ou "sem CVE (Produto)"
  "produto": "texto curto",
  "cvss": 9.8,                     // ou null se não confirmado
  "kev": true,
  "zero_day": true,                // explorado antes do patch
  "exploracao": "Ativa (detalhe curto)",   // Ativa | Ativa (...) | Exploit público | Não confirmada | Não
  "prioridade": "P0",
  "tratamento": "1 a 2 frases práticas: versão corrigida, mitigação se não der para corrigir, o que verificar.",
  "fontes": [{"nome": "Fabricante", "url": "https://..."}],   // 1 a 3, páginas que você abriu
  "status": "Novo"                 // Novo | Pendente | Resolvido
}
```

## Fontes

- Só páginas que você abriu nesta rodada ou links que já vieram em `data/vulns.json` ou nas pendências.
- Prefira o advisory do fabricante e uma notícia.
- Link de cisa.gov só se já veio do radar.

## Texto

- Português do Brasil, frases curtas, sem copiar trechos das fontes.
- Nenhum banco citado pelo nome.
- `tratamento` é para quem vai agir: o que atualizar, para qual versão, o que olhar enquanto isso.
