"""Tests de la logique de détection de cartographie.py (sans connexion Azure).

Lancement : python -m unittest -v
"""
import unittest
from enum import Enum
from types import SimpleNamespace

import cartographie as c


class Acces(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"


class Sens(str, Enum):
    INBOUND = "Inbound"
    OUTBOUND = "Outbound"


def regle(acces=Acces.ALLOW, sens=Sens.INBOUND, source="*", port="22", ports=None):
    """Construit une fausse règle NSG ressemblant à celles renvoyées par le SDK Azure."""
    return SimpleNamespace(
        access=acces, direction=sens,
        source_address_prefix=source, source_address_prefixes=[],
        destination_port_range=port, destination_port_ranges=ports or [],
    )


class TestDetection(unittest.TestCase):
    def test_ssh_ouvert_a_tout_internet_est_signale(self):
        self.assertEqual(c.analyser_regle(regle()), ["SSH (port 22) ouvert depuis Internet"])

    def test_regle_de_refus_non_signalee(self):
        self.assertEqual(c.analyser_regle(regle(acces=Acces.DENY)), [])

    def test_regle_sortante_non_signalee(self):
        self.assertEqual(c.analyser_regle(regle(sens=Sens.OUTBOUND)), [])

    def test_source_interne_non_signalee(self):
        self.assertEqual(c.analyser_regle(regle(source="10.10.1.0/24", port="5432")), [])

    def test_https_depuis_internet_non_signale(self):
        self.assertEqual(c.analyser_regle(regle(source="Internet", port="443")), [])

    def test_tous_les_ports_signales(self):
        self.assertEqual(c.analyser_regle(regle(port="*")), ["tous les ports ouverts depuis Internet"])

    def test_plage_de_ports_couvrant_ssh(self):
        problemes = c.analyser_regle(regle(port=None, ports=["20-30", "443"]))
        self.assertIn("SSH (port 22) ouvert depuis Internet", problemes)

    def test_port_couvert(self):
        self.assertTrue(c.port_couvert("*", 22))
        self.assertTrue(c.port_couvert("20-30", 22))
        self.assertTrue(c.port_couvert("22", 22))
        self.assertFalse(c.port_couvert("443", 22))

    def test_valeur_enumeration(self):
        self.assertEqual(c.valeur(Acces.ALLOW), "Allow")
        self.assertEqual(c.valeur("Allow"), "Allow")

    def test_identifiants_azure(self):
        rid = "/subscriptions/x/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/vnet-prod"
        self.assertEqual(c.groupe_depuis_id(rid), "rg-test")
        self.assertEqual(c.nom_depuis_id(rid), "vnet-prod")


if __name__ == "__main__":
    unittest.main()
