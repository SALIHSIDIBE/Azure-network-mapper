"""Inventaire d'un environnement réseau Azure et détection de règles NSG trop permissives.

Étape 1 du projet : lister les réseaux virtuels, sous-réseaux, peerings et NSG,
puis repérer les règles d'entrée ouvertes à tout Internet sur des ports sensibles.

Prérequis : être connecté avec `az login`. L'identifiant d'abonnement est lu
depuis la variable AZURE_SUBSCRIPTION_ID ou, à défaut, depuis `az account show`.
"""
import argparse
import json
import os
import subprocess

SOURCES_OUVERTES = {"*", "0.0.0.0/0", "internet", "any"}
PORTS_SENSIBLES = {
    22: "SSH", 3389: "RDP", 445: "SMB", 1433: "SQL Server",
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
}


def valeur(x):
    """Retourne la valeur texte d'une énumération du SDK Azure (ex. 'Allow'), ou le texte tel quel."""
    return str(getattr(x, "value", x))


def nom_depuis_id(resource_id):
    """Retourne le dernier segment d'un identifiant de ressource Azure."""
    return resource_id.rstrip("/").split("/")[-1] if resource_id else None


def groupe_depuis_id(resource_id):
    """Retourne le nom du groupe de ressources d'un identifiant Azure."""
    parts = resource_id.split("/")
    return parts[parts.index("resourceGroups") + 1] if "resourceGroups" in parts else None


def port_couvert(spec, port):
    """Indique si une spécification de port Azure ('*', '22', '20-30') couvre le port donné."""
    spec = str(spec).strip()
    if spec == "*":
        return True
    if "-" in spec:
        bas, haut = spec.split("-", 1)
        return int(bas) <= port <= int(haut)
    return spec.isdigit() and int(spec) == port


def ports_de_la_regle(regle):
    ports = []
    if getattr(regle, "destination_port_range", None):
        ports.append(regle.destination_port_range)
    ports.extend(getattr(regle, "destination_port_ranges", None) or [])
    return ports


def sources_de_la_regle(regle):
    sources = []
    if getattr(regle, "source_address_prefix", None):
        sources.append(regle.source_address_prefix)
    sources.extend(getattr(regle, "source_address_prefixes", None) or [])
    return sources


def analyser_regle(regle):
    """Retourne la liste des problèmes détectés pour une règle NSG."""
    problemes = []
    if valeur(regle.access).lower() != "allow" or valeur(regle.direction).lower() != "inbound":
        return problemes
    if not any(s.lower() in SOURCES_OUVERTES for s in sources_de_la_regle(regle)):
        return problemes
    specs = ports_de_la_regle(regle)
    if "*" in specs:
        problemes.append("tous les ports ouverts depuis Internet")
    for port, service in PORTS_SENSIBLES.items():
        if any(port_couvert(spec, port) for spec in specs) and "*" not in specs:
            problemes.append(f"{service} (port {port}) ouvert depuis Internet")
    return problemes


def recuperer_id_abonnement():
    sub = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if sub:
        return sub
    resultat = subprocess.run(
        "az account show --query id --output tsv",
        capture_output=True, text=True, shell=True, check=True,
    )
    return resultat.stdout.strip()


def collecter(client, groupe=None):
    inventaire = {"reseaux": [], "nsg": []}
    for vnet in client.virtual_networks.list_all():
        if groupe and groupe_depuis_id(vnet.id) != groupe:
            continue
        inventaire["reseaux"].append({
            "nom": vnet.name,
            "groupe": groupe_depuis_id(vnet.id),
            "espace_adresses": list(vnet.address_space.address_prefixes),
            "sous_reseaux": [
                {
                    "nom": s.name,
                    "prefixe": s.address_prefix,
                    "nsg": nom_depuis_id(s.network_security_group.id) if s.network_security_group else None,
                }
                for s in (vnet.subnets or [])
            ],
            "peerings": [
                {
                    "nom": p.name,
                    "vers": nom_depuis_id(p.remote_virtual_network.id),
                    "etat": valeur(p.peering_state),
                }
                for p in (vnet.virtual_network_peerings or [])
            ],
        })
    for nsg in client.network_security_groups.list_all():
        if groupe and groupe_depuis_id(nsg.id) != groupe:
            continue
        regles = []
        for r in (nsg.security_rules or []):
            regles.append({
                "nom": r.name,
                "priorite": r.priority,
                "acces": valeur(r.access),
                "sens": valeur(r.direction),
                "protocole": valeur(r.protocol),
                "sources": sources_de_la_regle(r),
                "ports": ports_de_la_regle(r),
                "problemes": analyser_regle(r),
            })
        inventaire["nsg"].append({"nom": nsg.name, "groupe": groupe_depuis_id(nsg.id), "regles": regles})
    return inventaire


def afficher(inventaire):
    print("\n=== Réseaux virtuels ===")
    for r in inventaire["reseaux"]:
        print(f"- {r['nom']} ({', '.join(r['espace_adresses'])})")
        for s in r["sous_reseaux"]:
            print(f"    sous-réseau {s['nom']} {s['prefixe']}  NSG : {s['nsg'] or 'aucun'}")
        for p in r["peerings"]:
            print(f"    peering {p['nom']} -> {p['vers']} ({p['etat']})")
    print("\n=== Groupes de sécurité réseau ===")
    total = 0
    for n in inventaire["nsg"]:
        print(f"- {n['nom']}")
        for g in n["regles"]:
            print(f"    règle {g['nom']} : {g['sens']} {g['acces']} {g['protocole']} ports {', '.join(g['ports'])}")
            for probleme in g["problemes"]:
                total += 1
                print(f"      ATTENTION : {probleme}")
    print(f"\n{total} problème(s) détecté(s).")


def main():
    parser = argparse.ArgumentParser(description="Inventaire réseau Azure et détection de règles NSG risquées")
    parser.add_argument("--groupe", help="limiter l'analyse à un groupe de ressources", default=None)
    parser.add_argument("--sortie", help="fichier JSON de sortie", default="inventaire.json")
    args = parser.parse_args()

    from azure.identity import AzureCliCredential
    from azure.mgmt.network import NetworkManagementClient

    client = NetworkManagementClient(AzureCliCredential(), recuperer_id_abonnement())
    inventaire = collecter(client, args.groupe)
    afficher(inventaire)
    with open(args.sortie, "w", encoding="utf-8") as f:
        json.dump(inventaire, f, ensure_ascii=False, indent=2)
    print(f"Inventaire enregistré dans {args.sortie}")


if __name__ == "__main__":
    main()
