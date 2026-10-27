# 0006 — Pipeline d'exécution contrôlée et quarantaine

- Statut : acceptée
- Date : 2026-10-26

## Contexte

Les phases 1 à 3 n'autorisaient aucune suppression. La phase 4 introduit
enfin l'action destructive, sous les contraintes de la section 6.1 :
simulation obligatoire, points de décision bloquants, mesure du résultat
réel, et honnêteté sur les limites de la quarantaine (section 6.3).

Le risque principal n'est pas fonctionnel mais **temporel** : entre la
simulation, vue par l'utilisateur, et l'exécution, le système de fichiers
peut changer (course critique TOCTOU, section 5.3).

## Options envisagées

1. **Simulation puis suppression directe** — simple, mais ne protège pas
   contre un remplacement entre les deux phases, et ne permet aucune
   récupération.
2. **Copie vers une sauvegarde complète** — coûteux en espace et en temps,
   hors du périmètre du MVP.
3. **Revalidation sur référence de simulation + quarantaine** — compare
   l'état réel à l'état observé, puis déplace au lieu de supprimer.

## Décision

Adopter la solution 3, avec cinq garanties :

1. **Référence de simulation.** `CandidateFile` transporte l'identité du
   fichier observée pendant la simulation (`st_dev:st_ino` via `lstat`).
   La revalidation compare **cette** référence à l'état courant. Relire les
   métadonnées au moment de l'action reviendrait à comparer l'état présent à
   lui-même et annulerait toute protection.
2. **Revalidation multi-étapes** (`security/revalidation.py`) : résolution
   dans le périmètre, `lstat` (jamais `stat`), refus des liens et points
   d'analyse, comparaison identité/taille/date, ouverture `O_NOFOLLOW` sous
   POSIX, puis `fstat` sur le descripteur pour détecter une race pendant
   l'ouverture.
3. **Confirmation bloquante.** `execute()` exige `confirm=True` ; sinon il
   retourne `needs_confirmation` **sans rien toucher**. Ce n'est pas une
   convention d'interface : c'est une garde du service.
4. **Quarantaine honnête.** Renommage atomique sur le même volume ; repli
   copie + vérification d'empreinte + suppression ; si rien n'est sûr,
   l'entrée est marquée `deleted` et `reversible=False`, et l'interface doit
   l'annoncer comme irréversible avant confirmation.
5. **Mesure réelle.** `reclaimed_bytes` compte uniquement les cibles
   effectivement traitées, distinct de `theoretical_bytes`. L'écart est
   exposé (`space_difference`) au lieu d'être masqué.

## Conséquences

- Le pipeline est testé par `tests/security/test_clean_execution.py` :
  dry-run sans effet, refus sans confirmation, cible supprimée ou modifiée
  après simulation rejetée, lien substitué rejeté, restauration vérifiée.
- Le journal d'audit (SQLite) conserve l'opération, la version de règle et
  l'issue de chaque cible ; il ne stocke **jamais** le contenu des fichiers
  (section 5.2), et aucun import réseau n'y figure.
- La CLI impose `--confirm` ; `--dry-run` est le comportement par défaut,
  et `clean` sans règle ni confirmation retourne le code `5`.

## Bug critique découvert pendant l'implémentation

La première version capturait un **nouveau** snapshot au moment de
l'exécution, puis le comparait à lui-même. La protection TOCTOU était donc
neutralisée : un fichier modifié entre simulation et exécution était accepté.
Les tests de sécurité ont révélé le défaut ; la comparaison porte désormais
sur la référence transportée par la simulation.

Second défaut, plus discret : `DirEntry.stat()` ne renseigne pas `st_ino`
sous Windows (valeur `0:0`), ce qui rendait toute détection de remplacement
impossible sur cette plateforme. L'identité est désormais lue par `lstat`
sur les seuls candidats retenus.
