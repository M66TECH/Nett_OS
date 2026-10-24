# Sécurité et confidentialité

La sécurité est le critère de qualité premier de NettOS (cahier des charges,
section 5). Ce document décrit les règles en vigueur et l'état d'avancement des
protections dans le code.

> État actuel : **lecture seule**. Aucune suppression n'est encore possible, donc
> aucun risque destructif n'est exposé. Les protections ci-dessous préparent le
> moteur de nettoyage (Phases 3 et 4).

## Règles non négociables

1. **Lecture seule par défaut.** Toute fonction commence par détecter et expliquer.
2. **Simulation obligatoire.** Avant tout nettoyage : cibles, nombre de fichiers,
   taille estimée, catégorie, risques, raison de la sélection.
3. **Liste d'autorisation.** Chaque nettoyeur a des cibles précises et des
   exclusions. Aucune suppression sur un chemin fourni librement par l'UI.
4. **Privilèges minimaux.** Exécution avec les permissions de l'utilisateur.
5. **Traçabilité.** Journaliser l'opération demandée, les règles, le résultat et
   les erreurs — jamais le contenu des fichiers.
6. **Tests de sécurité.** Liens symboliques, espaces et caractères particuliers,
   fichiers modifiés pendant l'analyse, permissions refusées, tentatives de
   sortie du périmètre.

## Politique de journalisation (arbitrage traçabilité / vie privée)

Fixée par la section 5.2 :

- les chemins **concernés par une opération de nettoyage** (demandée, simulée,
  exécutée, ignorée, en échec) sont enregistrés ;
- les chemins **simplement parcourus lors d'une analyse** ne le sont pas : seuls
  des agrégats (volumes, totaux par catégorie) sont conservés ;
- le **contenu des fichiers n'est jamais** enregistré ;
- le journal reste dans la base locale, aucun export sans action explicite ;
- la rétention est paramétrable avec purge automatique, et la purge manuelle est
  toujours disponible.

## Classification par risque

| Niveau | Description |
|--------|-------------|
| Faible | Fichiers temporaires explicitement identifiés et non utilisés |
| Modéré | Caches applicatifs connus, reconstructibles (coût parfois élevé) |
| Élevé | Journaux utiles, caches partagés, données de gestionnaires de paquets |
| Interdit par défaut | Documents personnels, données persistantes, fichiers système critiques |

Une catégorie ne rend jamais un fichier supprimable à elle seule : la décision
dépend de l'emplacement, de l'usage et de la règle qui le cible.

## Menaces et défenses

| Risque | Défense prévue | État |
|--------|----------------|------|
| Chemin sortant de la cible | `resolve_no_symlinks` + revalidation | Partiel (Phase 1) |
| Lien symbolique verrouillé | Liens non suivis par défaut | ✅ scanner |
| Fichier remplacé après simulation | Revalidation juste avant suppression | À venir (Phase 4) |
| Suppression massive | Limites de quantité/taille, aperçu, confirmation | À venir |
| Faux sentiment de restauration | Quarantaine seulement si réellement prise en charge | À venir |
| Accès administrateur excessif | Moindre privilège, opérations séparées | À venir |
| Crash en cours de nettoyage | Journalisation + rapport d'état partiel | À venir |

Défenses spécifiques par système (section 5.5), à implémenter en Phase 4 :

- **Linux** : descripteurs ouverts avec `O_NOFOLLOW`, ou `openat2` avec
  `RESOLVE_NO_SYMLINKS` ; revalidation par `fstat` sur le descripteur.
- **Windows** : `FILE_FLAG_OPEN_REPARSE_POINT`, handles à modes de partage
  restrictifs, revalidation du numéro d'index et des attributs.

## Contraintes Windows à traiter

- Chemins longs : préfixe `\\?\` et manifeste `longPathAware`.
- Junction points et liens symboliques NTFS.
- Flux de données alternatifs (ADS).
- Corbeille via les API du shell.

## Tests de sécurité

`tests/security/test_path_security.py` couvre dès maintenant :

- rejet d'un lien symbolique qui sort du périmètre ;
- scanner qui ignore un lien vers une zone sensible ;
- chemins avec espaces et caractères Unicode ;
- permissions refusées signalées sans plantage ;
- vérification que le scanner n'écrit jamais.

Les scénarios d'arborescences piégées s'étendront au moteur de nettoyage.

## Critères de blocage de publication

Aucune publication ne sort si l'un de ces critères n'est pas respecté :

1. Taux de suppression hors liste d'autorisation **strictement nul**.
2. Taux d'erreur masquée **nul** (chaque erreur comptée et signalée).
3. Conformité aux budgets de performance de la section 8.1.

## Confidentialité

**Tout est local.** Aucune télémétrie, aucun envoi réseau du contenu des
analyses, aucun compte utilisateur, aucun service distant. Le seul export est
celui que l'utilisateur déclenche lui-même.

NettOS ne collecte pas de données d'usage à l'insu de l'utilisateur et n'exécute
aucune règle téléchargée dynamiquement.
