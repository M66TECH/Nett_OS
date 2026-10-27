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

> Le nettoyage est désormais possible (phase 4), mais uniquement après
> simulation et confirmation explicite (`--confirm`), et les fichiers partent
> en quarantaine lorsqu'elle est disponible. Toutes les commandes de
> diagnostic restent en lecture seule.

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
nettos scan /chemin/vers/dossier          # rapport texte lisible
nettos scan /chemin/vers/dossier --json   # rapport JSON versionné
nettos scan . --top 20 --decimal          # 20 plus gros dossiers, unités ko/Mo
nettos scan . --no-volumes                # sans énumérer les disques
nettos --version
```

Le rapport texte indique la racine, le nombre de fichiers, la taille logique et
allouée, la durée, le statut, les volumes (espace libre) et les répertoires les
plus volumineux. Les erreurs sont classées (`permission_denied`, `not_found`,
`io_error`) et jamais masquées.

Le JSON suit le schéma `nettos.scan/1` : `status`, `root`, `total_files`,
`total_bytes`, `allocated_bytes`, `error_count_by_kind`, `errors`, `volumes`,
`directories` (limité aux plus gros, `directories_truncated` l'indique).

Codes de sortie : `0` succès, `2` usage invalide, `3` diagnostic incomplet,
`4` annulé. `--lang en` change la langue des messages.

### Règles et simulation (phase 3)

```bash
nettos rules                    # règles actives sur cette plateforme
nettos rules --all              # toutes, y compris celles d'un autre OS
nettos rules --risk moderate    # niveau de risque égal ou supérieur
nettos plan                     # simule toutes les règles actives
nettos plan windows.user.temp   # simule une règle
nettos plan --json              # plan complet en JSON (schema nettos.plan/1)
```

**Aucune commande de cette version ne supprime de fichier.** `plan` énumère
les cibles, leur taille et leur âge, puis affiche explicitement qu'aucune
suppression n'a eu lieu.

### Nettoyage contrôlé (phase 4)

```bash
nettos clean windows.user.temp              # simulation, rien n'est touché
nettos clean windows.user.temp --confirm    # mise en quarantaine réelle
nettos clean --confirm                      # refusé : une règle est requise
nettos quarantine list                      # entrées de la quarantaine
nettos quarantine restore <id>              # restaure un fichier
nettos quarantine purge --yes               # purge définitive
nettos history                              # journal d'audit local
```

Garde-fous appliqués :

- `--confirm` est **obligatoire** pour agir ; sans lui, le code de sortie
  est `5` et rien n'est modifié ;
- chaque cible est **revalidée** juste avant l'opération (identité, taille,
  date, liens, périmètre) ;
- les fichiers partent en **quarantaine** lorsqu'elle est possible ; sinon
  la suppression est signalée comme irréversible ;
- l'espace **réellement** récupéré est mesuré, distinct de l'estimation ;
- tout est consigné dans un journal SQLite local, sans jamais enregistrer le
  contenu des fichiers.

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
├── cleaners/       règles déclaratives + simulation (sans suppression)
├── security/       contrôles de chemin, liste d'autorisation
├── services/       orchestration appelée par l'UI et la CLI
├── persistence/    SQLite : historique, paramètres, journal
├── ui/             interface Qt + traductions fr/en
└── cli/            ligne de commande
tests/
├── support/        utilitaires (liens symboliques portables)
├── unit/           logique pure
├── integration/    CLI, service de scan, UI hors écran, budgets de perf
└── security/       scénarios d'évasion, liens piégés, permissions
```

## Feuille de route

Le calendrier suit six phases de deux semaines (cahier des charges, section 9).

| Phase | Contenu | État |
|-------|---------|------|
| 1 | Socle, architecture, CI Linux + Windows, i18n, app minimale | ✅ |
| 2 | Scanner de stockage en lecture seule, `nettos scan --json` | ✅ |
| 3 | Règles déclaratives, registre explicite, `nettos rules` / `plan` | ✅ |
| 4 | Simulation, confirmation, quarantaine, journalisation | ✅ |
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
