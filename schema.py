"""Génère un schéma Graphviz à partir de inventaire.json (produit par cartographie.py).

Le schéma montre les réseaux virtuels, leurs sous-réseaux, les NSG associés,
les peerings entre réseaux, et met en rouge les NSG qui contiennent une règle risquée.

Prérequis : Graphviz installé (commande `dot`) et la bibliothèque Python `graphviz`.
"""
import argparse
import json
import re

from graphviz import Digraph

ROUGE = "#c00000"
ROUGE_CLAIR = "#f8cbad"
BLEU = "#1f4e79"
BLEU_CLAIR = "#dbe9f6"
VERT = "#2e7d32"
ORANGE = "#e65100"


def ident(prefixe, nom):
    """Construit un identifiant de nœud Graphviz valide."""
    return prefixe + "_" + re.sub(r"[^A-Za-z0-9]", "_", nom)


def libelle_regle(regle):
    sens = "In" if regle["sens"].lower() == "inbound" else "Out"
    ports = ",".join(regle["ports"]) or "*"
    sources = ",".join(regle["sources"]) or "*"
    marque = "[!] " if regle["problemes"] else ""
    return f'{marque}{regle["priorite"]} {sens} {regle["acces"]} {regle["protocole"].lower()} {ports} <- {sources}'


def libelle_nsg(nsg):
    lignes = [libelle_regle(r) + "\\l" for r in nsg["regles"]]
    return nsg["nom"] + "\\n" + ("".join(lignes) if lignes else "aucune règle personnalisée\\l")


def nsg_a_risque(nsg):
    return any(r["problemes"] for r in nsg["regles"])


def construire(inventaire):
    g = Digraph("azure", format="png")
    g.attr(rankdir="LR", compound="true", pad="0.4", nodesep="0.5", ranksep="1.0",
           fontname="Helvetica", fontsize="20", labelloc="t",
           label="Cartographie réseau Azure\\n")
    g.attr("node", fontname="Helvetica", fontsize="11")
    g.attr("edge", fontname="Helvetica", fontsize="10")

    risques = {n["nom"] for n in inventaire["nsg"] if nsg_a_risque(n)}
    nsg_connus = {n["nom"] for n in inventaire["nsg"]}

    # Réseaux virtuels et sous-réseaux
    for vnet in inventaire["reseaux"]:
        with g.subgraph(name="cluster_" + ident("v", vnet["nom"])) as c:
            c.attr(label=f'{vnet["nom"]}\\n{", ".join(vnet["espace_adresses"])}',
                   style="rounded", color=BLEU, fontname="Helvetica-Bold", fontsize="13")
            c.node(ident("ancre", vnet["nom"]), label="", shape="point", width="0.01", style="invis")
            for s in vnet["sous_reseaux"]:
                c.node(ident("s", vnet["nom"] + "_" + s["nom"]),
                       label=f'{s["nom"]}\\n{s["prefixe"]}',
                       shape="box", style="filled,rounded", fillcolor=BLEU_CLAIR, color=BLEU)

    # NSG
    for nsg in inventaire["nsg"]:
        risque = nsg["nom"] in risques
        g.node(ident("nsg", nsg["nom"]), label=libelle_nsg(nsg), shape="note",
               style="filled", fillcolor=ROUGE_CLAIR if risque else "#f2f2f2",
               color=ROUGE if risque else "#7f7f7f", penwidth="2" if risque else "1")

    # Liens sous-réseau -> NSG
    for vnet in inventaire["reseaux"]:
        for s in vnet["sous_reseaux"]:
            if s["nsg"] and s["nsg"] in nsg_connus:
                risque = s["nsg"] in risques
                g.edge(ident("s", vnet["nom"] + "_" + s["nom"]), ident("nsg", s["nsg"]),
                       style="dashed", color=ROUGE if risque else "#7f7f7f",
                       penwidth="2" if risque else "1")

    # Peerings (une seule flèche, double si les deux sens existent)
    vus = {}
    for vnet in inventaire["reseaux"]:
        for p in vnet["peerings"]:
            cle = frozenset([vnet["nom"], p["vers"]])
            vus.setdefault(cle, []).append((vnet["nom"], p))
    for cle, entrees in vus.items():
        origine, p = entrees[0]
        etats = {e[1]["etat"] for e in entrees}
        connecte = etats == {"Connected"}
        g.edge(ident("ancre", origine), ident("ancre", p["vers"]),
               ltail="cluster_" + ident("v", origine), lhead="cluster_" + ident("v", p["vers"]),
               dir="both" if len(entrees) > 1 else "forward",
               label="peering\\n" + ("/".join(sorted(etats))),
               color=VERT if connecte else ORANGE, fontcolor=VERT if connecte else ORANGE,
               penwidth="2")

    # Légende
    g.node("legende", shape="plaintext", fontsize="10",
           label="Légende\\l  fond bleu : sous-réseau\\l  fond rouge : NSG avec règle risquée ([!])\\l"
                 "  flèche verte : peering connecté\\l")
    return g


def main():
    parser = argparse.ArgumentParser(description="Schéma Graphviz de l'inventaire réseau Azure")
    parser.add_argument("--entree", default="inventaire.json")
    parser.add_argument("--sortie", default="schema", help="nom du fichier sans extension")
    args = parser.parse_args()

    with open(args.entree, encoding="utf-8") as f:
        inventaire = json.load(f)
    g = construire(inventaire)
    chemin = g.render(args.sortie, cleanup=True)
    print(f"Schéma généré : {chemin}")


if __name__ == "__main__":
    main()
