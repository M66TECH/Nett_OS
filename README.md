# NettOS

**Diagnostic, maintenance et nettoyage système multiplateforme — Linux et Windows.**

NettOS est un logiciel libre qui **diagnostique avant d'agir**. Il cartographie le
stockage, explique ce qui l'occupe, signale les anomalies, et ne supprime jamais rien
sans simulation puis confirmation explicite. Il n'affiche ni score de « propreté », ni
promesse de vitesse magique : un diagnostic honnête, qui sait répondre « inconnu »
lorsqu'il ne peut pas conclure.

- Licence : **GNU AGPL-3.0-or-later** (voir [LICENSE](LICENSE))
- Langage : **Python 3.10+**
- Interface : **PySide6 / Qt Widgets**
- Persistance : **SQLite** (historique local uniquement)
- Statut : **pré-alpha** — le socle (Phase 1) est en place, le scanner est en cours.

> L'état courant est **strictement en lecture seule**. Aucune opération de
> suppression n'est exposée par cette version.

## Ce que NettOS ne sera jamais

Nettoyeur de registre, optimiseur de mémoire vive, « accélérateur » à score,
collecteur de données d'usage, ni moteur de règles téléchargées à l'exécution.
Ces non-objectifs sont permanents (cahier des charges, section 1.4).

## Installation (développement)

```bash
git clone https://github.com/M66TECH/Nett_OS.git
cd Nett_OS

python -m venv .venv
# Linux
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

## Utilisation

Interface graphique :

```bash
nettos-gui
nettos-gui --lang en
```

Ligne de commande (headless, sans interface) :

```bash
nettos scan /chemin/vers/dossier
nettos scan /chemin/vers/dossier --json
nettos --version
```

Option de langue pour la CLI : `nettos --lang en scan .`

## Développement

```bash
ruff check .            # lint
ruff format --check .   # style
mypy                    # typage statique
pytest -q               # tests
```

Les tests d'interface tournent sans écran (`QT_QPA_PLATFORM=offscreen`) et sont
ignorés si PySide6 n'est pas installé : **le moteur se teste sans Qt**
(règle d'architecture n°7).

### Structure

```
src/nettos/
├── core/           modèles de résultats, erreurs (sans Qt, sans I/O)
├── adapters/       isolent les différences Linux / Windows
├── diagnostics/    moteur de diagnostic (lecture seule)
├── cleaners/       moteur de nettoyage (à venir)
├── security/       contrôles de chemin, liste d'autorisation
├── services/       orchestration appelée par l'UI et la CLI
├── persistence/    SQLite : historique, paramètres, journal
├── ui/             interface Qt + traductions fr/en
└── cli/            ligne de commande
tests/
├── unit/           logique pure
├── integration/    CLI et UI hors écran
└── security/       scénarios d'évasion, liens piégés, permissions
```

## Feuille de route

Le calendrier suit six phases de deux semaines (cahier des charges, section 9).

| Phase | Contenu | État |
|-------|---------|------|
| 1 | Socle, architecture, CI Linux + Windows, i18n, app minimale | ✅ |
| 2 | Scanner de stockage en lecture seule, `nettos scan --json` | ⏳ |
| 3 | Contrat `BaseCleaner`, registre de règles | — |
| 4 | Simulation, confirmation, quarantaine, journalisation | — |
| 5 | Tableau de bord, historique SQLite, fr/en | — |
| 6 | Spécificités Windows/Linux, packaging, alpha | — |

## Sécurité et confidentialité

- Lecture seule par défaut, simulation obligatoire, liste d'autorisation.
- Aucun réseau : pas de télémétrie, pas de compte, pas de service distant.
- Le journal d'audit reste local et supprimable.

Voir [docs/security.md](docs/security.md) et [docs/architecture.md](docs/architecture.md).

## Contributions

Les décisions structurantes sont consignées dans [docs/adr/](docs/adr/).
Toute proposition de fonctionnalité se juge à l'aune du périmètre MVP
(cahier des charges, section 2.1).

## Licence

Distribué sous **GNU Affero General Public License v3.0 ou ultérieure**.
Chaque fichier source porte un en-tête `SPDX-License-Identifier: AGPL-3.0-or-later`.
