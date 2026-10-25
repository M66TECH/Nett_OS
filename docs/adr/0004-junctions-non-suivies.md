# 0004 — Ne jamais suivre les junctions ni les points d'analyse

- Statut : acceptée
- Date : 2026-10-25
- Motif : faille de sécurité découverte par les tests de sécurité de la phase 2

## Contexte

Le cahier des charges impose que les liens symboliques ne soient jamais suivis
(section 5.5) : un lien peut pointer vers un fichier sensible ou hors du
périmètre autorisé.

Le scanner de la phase 1 utilisait `os.DirEntry.is_symlink()`. Les tests de
sécurité de la phase 2 ont révélé que **cette API ne détecte pas les junctions
NTFS** : une junction est un *reparse point* de type mount point (tag
`0xA0000003`) que Python présente comme un répertoire ordinaire. Conséquence
mesurée sur Windows : un lien créé par `mklink /J` était parcouru, ses fichiers
comptés deux fois, et une arborescence pouvait pointer hors du périmètre.

S'y ajoutent les autres reparse points (liens OneDrive, points de montage de
volume, dossiers dédupliqués), tout aussi susceptibles de sortir du périmètre.

## Options envisagées

1. **Ignorer le problème** — inacceptable : c'est une évasion de périmètre et un
   double comptage silencieux, contraires aux critères de blocage (section 10.2).
2. **Utiliser `psutil`** — dépendance binaire externe pour un test d'attribut.
3. **Lire `st_file_attributes` via `ctypes`/`stat`** — aucun coût de dépendance,
   test binaire direct sur `FILE_ATTRIBUTE_REPARSE_POINT` (0x400).

## Décision

Adopter la solution 3. `diagnostics/filesystem.py` expose :

- `is_reparse_point(entry)` : teste `st_file_attributes & 0x400` (Windows
  uniquement) ;
- `is_link_like(entry)` : `is_symlink()` **ou** reparse point — prédicat unique
  à utiliser partout où une entrée ne doit pas être suivie ;
- `is_regular_file` / `is_regular_directory` : classification sans suivi.

Le scanner les utilise exclusivement ; `os.path.islink` et `entry.is_symlink()`
ne sont plus appelés directement dans le moteur.

## Conséquences

- Les junctions, liens symboliques et points d'analyse sont comptés comme
  entrées mais **jamais parcourus** : ni évasion, ni double comptage.
- Le coût est nul sur Linux (branche désactivée avant tout appel système).
- Le futur moteur de nettoyage (phase 4) réutilisera `is_link_like` pour ses
  revalidations de cible.
- Les tests correspondants s'exécutent désormais sous Windows grâce à un repli
  `mklink /J` (`tests/support/symlinks.py`), au lieu d'être ignorés.
