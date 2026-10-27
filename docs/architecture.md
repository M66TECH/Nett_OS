# Architecture de NettOS

Ce document décrit l'organisation des couches, les règles non négociables et
l'état d'avancement du socle. Il suit le cahier des charges v1.1, section 4.

## Vue d'ensemble en couches

De haut en bas :

```
┌──────────────────────────────────────────────────────────┐
│ Interface Qt (ui/)      · ligne de commande (cli/)       │
├──────────────────────────────────────────────────────────┤
│ Services applicatifs (services/)                         │
│   orchestrer : scan, simulation, nettoyage, rapport      │
├──────────────────────────────────────────────────────────┤
│ Moteurs (diagnostics/, cleaners/) + registre de règles   │
├──────────────────────────────────────────────────────────┤
│ Sécurité (security/)  · Persistance (persistence/)       │
├──────────────────────────────────────────────────────────┤
│ Adaptateurs de plateforme (adapters/) : Linux / Windows  │
└──────────────────────────────────────────────────────────┘
```

Le flux des données va toujours **du bas vers le haut** : les adaptateurs
lisent le système, les moteurs agrègent, les services orchestrent, l'UI
affiche. L'UI ne touche jamais au disque directement.

## Règles non négociables

1. **L'interface ne supprime jamais directement un fichier.**
2. Le moteur de diagnostic n'exige pas de privilèges administrateur pour les
   analyses ordinaires.
3. Les règles de nettoyage décrivent cibles, risques et conditions — jamais de
   commandes arbitraires.
4. Les différences Linux/Windows sont isolées dans `adapters/`.
5. Les opérations longues s'exécutent hors du thread graphique, avec progression
   et annulation.
6. Le registre de plugins utilise une liste explicite de modules autorisés,
   jamais un chargement automatique.
7. Le moteur fonctionne et se teste **sans interface graphique**.

Complément d'exigence vérifiable : le moteur ne dépend d'aucun import Qt.
`tests/unit` et `tests/integration/test_cli.py` n'importent jamais PySide6.

## Contrat des résultats

Tout diagnostic produit des objets définis dans `core/result.py` :

- `VolumeInfo` : un volume monté (point de montage, tailles, système de fichiers).
- `ScanErrorRecord` : une erreur rencontrée, avec chemin et raison.
- `ScanResult` : agrégat (nombre de fichiers, octets, erreurs, statut, durée).
- `DiagnosticStatus` : `ok`, `partial`, `unknown`.

Le statut `unknown` est une **réponse légitime** : une analyse qui ne peut pas
conclure ne doit jamais inventer de cause.

## Le scanner (diagnostics/scanner.py)

Le scanner de la phase 2 est un parcours itératif complet :

- parcours avec pile explicite (pas de limite de récursion) ;
- **aucun lien suivi** : liens symboliques POSIX/Windows **et** junctions NTFS,
  détectés par `diagnostics/filesystem.py` (attribut `FILE_ATTRIBUTE_REPARSE_POINT`
  via ctypes, car `is_symlink()` voit une junction comme un répertoire ordinaire) ;
- agrégats en flux : seules les tailles **par répertoire** sont conservées, pas la
  liste des fichiers (budget mémoire) ;
- erreurs classées (`permission_denied`, `not_found`, `io_error`, `other`) et
  comptées, jamais avalées ;
- annulation coopérative à chaque répertoire et à chaque entrée ;
- garde-fou `MAX_DIRECTORIES` contre les structures cycliques ;
- tailles logiques **et** allouées (via `st_blocks` sous POSIX).

### Mesures de performance

Mesuré sur la machine de référence (Windows 10, SSD) :

| Indicateur | Budget | Mesuré |
|------------|--------|--------|
| Scan de 1 M fichiers | 60 s | ≈ 17 s (extrapolé depuis 30 000 fichiers : 0,50 s) |
| Mémoire du moteur | 300 Mo | < 8 Mo de croissance entre 1 000 et 4 000 fichiers |
| Simulation de 10 000 cibles | 5 s | à mesurer en phase 4 |

> La génération de l'arborescence de test n'est pas comptée dans le budget :
> créer 1 M fichiers peut dépasser 15 minutes sur un disque avec antivirus actif.

### Adapters de plateforme (phase 2)

`LinuxAdapter` lit `/proc/self/mounts` (aucun privilège requis), décode les
échappements octaux (`\040`), filtre les pseudo-systèmes (`proc`, `sysfs`, `tmpfs`…)
et interroge `shutil.disk_usage`. `WindowsAdapter` énumère les lecteurs via
`GetLogicalDrives`, filtre les types utilisables (fixe, amovible, réseau) et lit
l'espace via `GetDiskFreeSpaceExW` — le tout par `ctypes`, **sans dépendance
externe**.

## Moteur de nettoyage : règles et simulation (phase 3)

La phase 3 **n'exécute aucune suppression**. Elle livre le modèle, le moteur
de simulation et les premières règles, de sorte que la phase 4 n'ait plus
qu'à brancher le pipeline de confirmation et de quarantaine.

```
CleanerRule  (données immuables)      CleanerRegistry (liste littérale)
   │  targets, excluded, risk,            │  statut calculé :
   │  platforms, version, dates           │  active / not_applicable /
   ▼                                      │  stale / disabled
DeclarativeCleaner  ─────────────►  instanciation refusée si non actif
   │  RULE + roots()
   ▼
SimulationEngine   (UNIQUE parcours de sécurité)
   1. liens et points d'analyse → refusés
   2. exclusions               → gagnent toujours
   3. motif de cible           → correspondance linéaire
   4. filtre d'âge             → `max_age_days`
   5. validation de chemin     → `resolve_no_symlinks`
   6. plafonds                 → candidats, entrées, profondeur
```

**Pourquoi un moteur unique.** La sécurité est écrite et testée une seule
fois. Une règle est un objet de données relisible sans lire de code
(ADR-0005).

**Ce qui n'existe pas encore.** `BaseCleaner.execute()` lève
`NotImplementedError` : une suppression accidentelle est impossible par
construction. La phase 4 ajoutera la revalidation juste avant opération, la
confirmation explicite et la quarantaine.

### Règles livrées

| Identifiant | Risque | Portée |
|-------------|--------|--------|
| `linux.user.cache` | modéré | `~/.cache`, hors caches de compilation et de paquets |
| `linux.user.thumbnails` | faible | miniatures du bureau |
| `linux.user.trash` | modéré | corbeille (suppression définitive) |
| `windows.user.temp` | faible | `%TEMP%`, fichiers de plus de 7 jours |
| `windows.user.thumbnails` | faible | bases de miniatures de l'Explorateur |
| `windows.user.crashdumps` | modéré | vidages et rapports de plus de 30 jours |

Aucune règle livrée n'exige de privilège administrateur, ne vise `C:\Windows`,
`/etc`, `/var/lib` ni le registre. Ces invariants sont vérifiés par
`tests/unit/test_cleaner_registry.py`.

### Performances de simulation

| Scénario | Mesuré |
|----------|--------|
| `%TEMP%` (≈ 20 000 entrées) | 4,2 s |
| Miniatures | 0,02 s |
| Candidat individuel | ≈ 0,08 ms par entrée |

Le coût par entrée a été divisé par 30 en réordonnant les contrôles (filtre
d'âge avant `realpath`) et en pré-compilant les motifs. Un défaut critique
corrigé au passage : les antislashs Windows empêchaient toute correspondance
relative, donc **toutes** les exclusions étaient inopérantes sur Windows.

## Exécution contrôlée et quarantaine (phase 4)

Le pipeline destructif n'est accessible qu'après simulation, et chaque
point de décision est bloquant (section 6.1).

```
simulation ──► décision ──► revalidation ──► action ──► mesure ──► journal
                 │             │              │           │
          sans confirm :    lien/race     quarantaine   réel vs
          rien n'est       → rejet       ou suppression théorique
          touché                           irréversible
```

### La référence de simulation

`CandidateFile` transporte l'identité observée **pendant** la simulation
(`st_dev:st_ino`). La revalidation compare cette référence à l'état courant.
C'est la clé de la protection contre les courses critiques : relire les
métadonnées au moment de l'action reviendrait à comparer l'état présent à
lui-même (ADR-0006).

### Revalidation (`security/revalidation.py`)

1. résolution du chemin et comparaison au périmètre autorisé ;
2. `lstat` — jamais `stat` — et refus des liens et points d'analyse ;
3. comparaison identité, taille et date de modification ;
4. ouverture avec `O_NOFOLLOW` (POSIX) ;
5. `fstat` sur le descripteur : une substitution pendant l'ouverture est
   détectée.

Toute cible rejetée est ignorée **et journalisée** ; le reste du lot continue.

### Quarantaine (`cleaners/quarantine.py`)

| Situation | Comportement |
|-----------|--------------|
| Même volume | renommage atomique |
| Volume différent | copie, vérification de l'empreinte, puis suppression |
| Copie ou suppression impossible | entrée `deleted`, `reversible=False`, signalée |

La quarantaine n'est **pas une sauvegarde** : l'entrée dit explicitement si
la restauration est possible. La purge est explicite (`--yes`) et peut être
limitée par âge.

### Mesure du résultat

`theoretical_bytes` (estimation) et `reclaimed_bytes` (cibles réellement
traitées) sont rapportés séparément, avec leur écart. Liens physiques,
compression et fichiers ouverts expliquent l'écart ; il n'est jamais masqué.

### Journal d'audit (`persistence/audit_log.py`)

SQLite local, schéma versionné. Consigne l'opération, la version de règle,
l'issue de chaque cible et un résumé d'erreurs. **Ne consigne jamais le
contenu des fichiers** ni les chemins simplement parcourus (section 5.2) ;
aucun import réseau n'y figure, ce qui est vérifié par un test.

### Mesures

| Indicateur | Résultat |
|------------|----------|
| Dry-run sur 3 cibles | 0 fichier touché |
| Sans `confirm` | statut `needs_confirmation`, 0 fichier touché |
| Fichier modifié après simulation | rejeté, fichier conservé |
| Lien substitué | rejeté, cible du lien conservée |
| Quarantaine + restauration | contenu identique, empreinte vérifiée |

## Sécurité des chemins (security/path_policy.py)

Deux primitives, testées indépendamment :

- `is_within_root(candidate, root)` : comparaison lexicale après normalisation
  (insensible à la casse sur Windows, sensible sur POSIX).
- `resolve_no_symlinks(path, root=...)` : résout les liens et lève
  `PathOutsideAuthorizedRootError` si le résultat sort du périmètre.

Ces contrôles sont une **première barrière**. La protection complète contre les
courses critiques (TOCTOU) exigera les mécanismes par plateforme décrits en
section 5.5 : `O_NOFOLLOW` / `openat2` sous Linux, `FILE_FLAG_OPEN_REPARSE_POINT`
et handles à partage restrictif sous Windows.

## Adaptateurs de plateforme

`adapters/base.py` définit `PlatformAdapter` (`name`, `list_volumes`).
`adapters/factory.py` sélectionne l'adaptateur selon `sys.platform`. En Phase 1,
la fabrique lève `UnsupportedPlatformError` de façon explicite : mieux vaut une
erreur claire qu'un adaptateur factice.

## Interface et traduction

- `ui/app.py` : `build_application()` crée/configure `QApplication`, choisit la
  langue et installe les traducteurs.
- `ui/main_window.py` : fenêtre minimale, tous les textes passent par `self.tr()`.
- `ui/translations.py` : chargement des `.qm` (fr/en) et détection de la locale.
- `ui/i18n/*.ts` : sources de traduction ; `lrelease` produit les `.qm` livrés.

La discipline de traduction est appliquée dès le premier fichier d'interface
(section 8.3) : le coût marginal est quasi nul maintenant, un rattrapage
ultérieur serait coûteux.

## Ligne de commande

`cli/main.py` utilise `argparse` et appelle les mêmes services que l'UI. Le
mode headless sert aux tests d'intégration CI et à l'automatisation contrôlée.
Aucune confirmation implicite : une future commande `clean` exigera `--confirm`.

## Persistance

`persistence/` est réservé au schéma SQLite (historique d'analyses, paramètres,
journal d'audit). Aucun contenu de fichier n'y sera jamais stocké
(section 4.1). Le schéma arrivera en Phase 5.

## Décisions structurantes

Consignées dans [docs/adr/](adr/). Chaque décision révisée produit un nouvel
enregistrement qui annule explicitement le précédent.
