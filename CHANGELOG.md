# Journal des modifications

Toutes les modifications notables de ce projet sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le
projet adhère au [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

### À venir

- Phase 5 : tableau de bord Qt, historique SQLite dans l'interface, fr/en.

---

## [0.4.0] — 2026-10-26

Phase 4 : pipeline de nettoyage contrôlé, avec revalidation, quarantaine et
journal d'audit. **La suppression devient possible, sous confirmation
explicite.**

### Ajouté

- `security/revalidation.py` : revalidation anti-TOCTOU en étapes —
  périmètre, `lstat`, refus des liens et points d'analyse, comparaison
  identité/taille/date, ouverture `O_NOFOLLOW`, `fstat` sur descripteur.
- `cleaners/quarantine.py` : quarantaine minimale avec métadonnées
  (chemin d'origine, règle, version, date, empreinte SHA-256), restauration
  et purge. Renommage atomique sur même volume ; repli copie + vérification
  d'empreinte ; sinon entrée marquée irréversible.
- `persistence/audit_log.py` : journal SQLite versionné (opérations, cibles,
  résumés d'erreurs), sans contenu de fichier et sans import réseau.
- `services/clean_service.py` : pipeline simulation → décision →
  revalidation → action → mesure → journalisation, avec garde `confirm`.
- CLI : `clean` (`--dry-run` par défaut, `--confirm`, `--json`,
  `--max-targets`), `quarantine list|restore|purge`, `history`
  (`--json`, `--purge`, `--yes`). Code de sortie `5` si confirmation
  manquante.
- Schéma JSON `nettos.clean/1`.
- 83 nouveaux tests : revalidation, exécution, quarantaine, audit, CLI.

### Corrigé

- **Critique** : la première implémentation capturait un nouveau snapshot au
  moment de l'exécution et le comparait à lui-même, annulant toute
  protection TOCTOU. La comparaison porte désormais sur la référence de
  simulation transportée par `CandidateFile`.
- **Critique** : `DirEntry.stat()` ne renseigne pas `st_ino` sous Windows
  (`0:0`), rendant indétectable tout remplacement. L'identité est lue par
  `lstat` sur les seuls candidats retenus.
- Revalidation : une référence de simulation absente est désormais refusée.

### Mesuré

- Dry-run et absence de confirmation : 0 fichier touché (vérifié par test).
- Modification ou substitution de lien après simulation : rejetée, cible
  conservée.
- Restauration : contenu identique, empreinte vérifiée.

---

## [0.3.0] — 2026-10-25

Phase 3 : règles de nettoyage déclaratives et simulation. **Aucune
suppression n'est possible dans cette version.**

### Ajouté

- `cleaners/rules.py` : modèle immuable `CleanerRule` / `CleanTarget` avec
  validation stricte (identifiant, motifs relatifs, risque, dates).
  `RiskLevel` ordonné, `Platform` typée.
- `cleaners/base.py` : contrat `BaseCleaner` (identifiant, version,
  plateformes, cibles, exclusions, risque, simulation, description) et
  `execute()` volontairement bloqué.
- `cleaners/simulation.py` : moteur unique de simulation en lecture seule —
  liens et junctions refusés, exclusions prioritaires, filtre d'âge,
  validation de chemin, plafonds de candidats/entrées/profondeur.
- `cleaners/registry.py` : registre **explicite** (liste littérale, aucune
  découverte dynamique), statuts `active` / `not_applicable` / `stale` /
  `disabled`, instanciation refusée si non actif.
- Six règles livrées : `linux.user.cache`, `linux.user.thumbnails`,
  `linux.user.trash`, `windows.user.temp`, `windows.user.thumbnails`,
  `windows.user.crashdumps`.
- Service `CleanRulesService` et commandes `nettos rules` / `nettos plan`
  (`--json`, `--all`, `--risk`, `--limit`, `--decimal`).
- 116 nouveaux tests : motif de patterns, modèle de règle, simulation de
  sécurité, registre, règles livrées, CLI.

### Corrigé

- **Critique** : sur Windows, `_relative` comparait un chemin natif (`\`) à
  un préfixe POSIX (`/`) : aucune exclusion n'était jamais appliquée.
- Cache des cibles indexé par identifiant seul : un filtre d'âge d'une règle
  pouvait s'appliquer à une autre. Clé désormais exhaustive.
- Règle des miniatures Windows trop large (`**/*.db` capturait `iconcache.db`
  et d'autres bases applicatives).
- Simulation 30× plus lente que nécessaire : `realpath` appelé par fichier au
  lieu des seuls candidats, motifs recompilés à chaque entrée.

### Mesuré

- Simulation de `%TEMP%` (≈ 20 000 entrées) : 4,2 s.
- Coût par entrée : ≈ 0,08 ms.

---

## [0.2.0] — 2026-10-25

Phase 2 : scanner de stockage en lecture seule, exploitable sans interface.

### Ajouté

- `LinuxAdapter` : lecture de `/proc/self/mounts`, décodage des échappements
  octaux, filtrage des pseudo-systèmes, `shutil.disk_usage`.
- `WindowsAdapter` : énumération des lecteurs et espace libre via `ctypes`
  (`GetLogicalDrives`, `GetDiskFreeSpaceExW`) — aucune dépendance externe.
- `diagnostics/filesystem.py` : détection des **junctions NTFS** et points
  d'analyse Windows, invisibles pour `os.DirEntry.is_symlink()`.
- Scanner complet : agrégation par répertoire, erreurs classées
  (`ErrorKind`), tailles logiques et allouées, garde-fou `MAX_DIRECTORIES`,
  annulation coopérative (`CancellationToken`).
- `ScanService` : énumération des volumes + rapport JSON versionné
  (`schema: nettos.scan/1`).
- CLI enrichie : `--top`, `--decimal`, `--no-volumes`, `--errors`, codes de
  sortie documentés.
- `core/formatting.py` : unités binaires (Kio) et décimales (ko) explicites.
- Tests : adaptateurs, agrégation, formatage, service, budgets de performance.
- Job CI « performance » exécutant le budget d'un million de fichiers.

### Corrigé

- **Sécurité** : les junctions NTFS étaient parcourues et comptaient deux fois
  les fichiers (évasion d'arborescence). Détection dédiée et tests dédiés.
- Progression et annulation non déclenchées en début de parcours.
- `LinuxAdapter` ne respectait pas le contrat `PlatformAdapter`.
- Fin de ligne CRLF sur Windows : ajout d'un `.gitattributes`.

### Mesuré

- Scan de 1 M fichiers : ≈ 17 s (budget : 60 s), croissance mémoire < 8 Mo.

---

## [0.1.0] — 2026-10-24

Première pierre du socle : Phase 1 du plan de développement (semaines 1 à 2).

### Ajouté

- Package Python installable `nettos` (layout `src/`, Python 3.10+).
- Modèles du domaine : `VolumeInfo`, `ScanErrorRecord`, `ScanResult`,
  `DiagnosticStatus` (`core/result.py`).
- Erreurs typées : `NettOSError`, `ScanError`, `PathOutsideAuthorizedRootError`,
  `UnsupportedPlatformError`.
- Contrat `PlatformAdapter` et sélection explicite par plateforme.
- Premier scanner de stockage en lecture seule (`diagnostics/scanner.py`) :
  parcours itératif, liens non suivis, erreurs collectées, statut partiel,
  callback de progression.
- Service applicatif `ScanService` et sérialisation JSON.
- Ligne de commande `nettos` : `--version`, `nettos scan [--json] [--lang]`.
- Contrôles de chemin `is_within_root` et `resolve_no_symlinks`.
- Interface Qt minimale (`nettos-gui`) avec traductions françaises et anglaises
  chargées depuis `ui/i18n/`.
- Tests unitaires, d'intégration et de sécurité (21 tests).
- Intégration continue GitHub Actions : lint, typage, tests Linux + Windows
  (Python 3.10 et 3.12), campagne de sécurité.
- Documentation : architecture, sécurité, registre des ADR, guide de contribution.

### Décisions

- Licence AGPL-3.0-or-later conservée (ADR-0001, écart documenté avec le
  cahier des charges).
- Python 3.10 comme version minimale (ADR-0002).
- Arborescence `src/` avec découpage par couches (ADR-0003).
