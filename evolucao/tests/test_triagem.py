"""Testes das regras fixas. Rodar:  python -m unittest discover -s evolucao/tests -v"""
import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from triagem_comum import chave_item, texto_janela  # noqa: E402
from triagem_prep import aplicar_validade, marcar_kev, montar_pendencias  # noqa: E402
from triagem_publish import contar_mudancas, juntar_descartes, validar  # noqa: E402

HOJE = date(2026, 11, 12)


def item(**kw):
    base = {"data": "2026-11-10", "cve": "CVE-2026-1111", "produto": "Produto X", "cvss": 9.8, "kev": False,
            "zero_day": False, "exploracao": "Não", "prioridade": "P1",
            "tratamento": "Atualizar para a versão 1.2.3 e restringir a interface de gestão.",
            "fontes": [{"nome": "Fabricante", "url": "https://exemplo.com/advisory"}], "status": "Novo"}
    base.update(kw)
    return base


class Validade(unittest.TestCase):
    def test_dentro_da_janela_fica_igual(self):
        it = item(data="2026-11-05")
        mantidos, pend, rem = aplicar_validade([it], HOJE)
        self.assertEqual(mantidos, [it])
        self.assertEqual((pend, rem), ([], []))

    def test_p0_explorado_vira_pendente(self):
        it = item(data="2026-11-04", prioridade="P0", exploracao="Ativa (KEV)")
        mantidos, pend, _ = aplicar_validade([it], HOJE)
        self.assertEqual(mantidos[0]["status"], "Pendente")
        self.assertEqual(pend, ["CVE-2026-1111"])

    def test_p0_pendente_sai_depois_de_14_dias(self):
        it = item(data="2026-10-28", prioridade="P0", exploracao="Ativa", status="Pendente")
        _, _, rem = aplicar_validade([it], HOJE)
        self.assertEqual(rem, ["CVE-2026-1111"])

    def test_p1_vencido_sai(self):
        _, _, rem = aplicar_validade([item(data="2026-11-04")], HOJE)
        self.assertEqual(rem, ["CVE-2026-1111"])


class Kev(unittest.TestCase):
    def test_marca_item_com_varias_cves(self):
        it = item(cve="CVE-2026-1000 / CVE-2026-2222")
        mud = marcar_kev([it], {"CVE-2026-2222": {"dateAdded": "2026-11-11", "dueDate": "2026-11-25"}})
        self.assertTrue(it["kev"])
        self.assertEqual(mud[0]["no_kev"], ["CVE-2026-2222"])

    def test_pendencia_ignora_o_que_ja_foi_triado_ou_descartado(self):
        kev = {c: {"dateAdded": "2026-11-11"} for c in ("CVE-2026-1111", "CVE-2026-3333", "CVE-2026-4444")}
        p = montar_pendencias([item()], {"itens": []}, kev,
                              [{"chave": "CVE-2026-4444", "motivo": "nicho", "data": "2026-11-11"}], HOJE)
        self.assertEqual([k["cve"] for k in p["kev_na_janela_sem_triagem"]], ["CVE-2026-3333"])

    def test_descarte_reabre_se_entrar_no_kev(self):
        kev = {"CVE-2026-4444": {"dateAdded": "2026-11-11"}}
        desc = [{"chave": "CVE-2026-4444", "motivo": "nicho", "data": "2026-11-09"}]
        p = montar_pendencias([], {"itens": []}, kev, desc, HOJE)
        self.assertEqual([k["cve"] for k in p["kev_na_janela_sem_triagem"]], ["CVE-2026-4444"])


class Publicacao(unittest.TestCase):
    def test_item_valido_passa(self):
        erros, _ = validar({"itens": [item()]}, HOJE, set())
        self.assertEqual(erros, [])

    def test_erros_comuns(self):
        ruim = item(prioridade="P3", exploracao="sim", fontes=[], kev=True)
        erros, _ = validar({"itens": [ruim]}, HOJE, set())
        texto = " ".join(erros)
        for trecho in ("prioridade", "exploracao", "fontes", "KEV"):
            self.assertIn(trecho, texto)

    def test_cisa_so_com_link_do_radar(self):
        url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2026-1111"
        it = item(fontes=[{"nome": "CISA", "url": url}])
        self.assertTrue(validar({"itens": [it]}, HOJE, set())[0])
        self.assertFalse(validar({"itens": [it]}, HOJE, {url})[0])

    def test_item_herdado_so_gera_aviso(self):
        velho = item(cvss=None)   # sem "a confirmar": erro se novo, aviso se herdado
        erros, avisos = validar({"itens": [velho]}, HOJE, set(), anterior=[velho])
        self.assertEqual(erros, [])
        self.assertTrue(avisos)

    def test_duplicado(self):
        erros, _ = validar({"itens": [item(), item(cve="CVE-2026-1111")]}, HOJE, set())
        self.assertTrue(any("duplicado" in e for e in erros))

    def test_contagem_ignora_ordem_das_cves(self):
        antes = [item(cve="CVE-2026-1001 / CVE-2026-1002")]
        depois = [item(cve="CVE-2026-1002 / CVE-2026-1001"), item(cve="CVE-2026-9999")]
        self.assertEqual(chave_item(antes[0]), chave_item(depois[0]))
        self.assertEqual(contar_mudancas(antes, depois), (1, 1))

    def test_descartes_expiram(self):
        velhos = [{"chave": "CVE-2026-1", "motivo": "nicho", "data": "2026-10-01"}]
        res = juntar_descartes(velhos, [{"chave": "CVE-2026-2", "motivo": "shadow IT"}], HOJE)
        self.assertEqual([d["chave"] for d in res], ["CVE-2026-2"])


class Janela(unittest.TestCase):
    def test_mesmo_mes(self):
        self.assertEqual(texto_janela(HOJE), "05 a 12/nov/2026")

    def test_virada_de_mes(self):
        self.assertEqual(texto_janela(date(2026, 11, 3)), "27/out a 03/nov/2026")


if __name__ == "__main__":
    unittest.main()
