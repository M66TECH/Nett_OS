# 0005 — Règles déclaratives et simulation centralisée

- Statut : acceptée
- Date : 2026-10-25

## Contexte

La phase 3 doit livrer le contrat des nettoyeurs, le registre de règles et
les premières règles concrètes, **sans aucune suppression**. Le cahier des
charges impose deux contraintes fortes :

- règle 3 : « les règles de nettoyage décrivent leurs cibles, leurs risques
  et leurs conditions ; elles ne contiennent pas de commandes arbitraires » ;
- section 6.2 : chaque nettoyeur expose simulation, exécution et vérification.

Une implémentation naïve aurait donné à chaque nettoyeur son propre code de
parcours. On aurait alors dupliqué — et testé séparément — une logique de
sécurité critique, avec un risque élevé de divergence.

## Options envisagées

1. **Logique de parcours dans chaque nettoyeur** — souple, mais duplique les
   contrôles de sécurité (liens, exclusions, âge, périmètre) autant de fois
   qu'il y a de règles. Inacceptable.
2. **Classes de nettoyeurs autonomes + héritage** — réduit la duplication mais
   laisse chaque règle capable de faire n'importe quoi.
3. **Règle purement déclarative + moteur unique** — la règle ne fournit que
   des racines et des motifs ; un moteur unique applique tous les contrôles.

## Décision

Adopter la solution 3 :

- `CleanerRule`, `CleanTarget` : structures **immuables** décrivant cibles,
  exclusions, risque, plateformes, version, dates de validité et de revue ;
- `SimulationEngine` : **unique** parcours, appliquant dans l'ordre : refus
  des liens et points d'analyse, exclusions, correspondance de motif, filtre
  d'âge, validation de chemin, plafonds ;
- `DeclarativeCleaner` : un nettoyeur concret ne définit que `RULE` et
  `roots()` ;
- `CleanerRegistry` : liste **littérale** de classes, statut calculé, et
  instanciation refusée pour tout nettoyeur non actif.

## Conséquences

- Un seul endroit à auditer et à tester pour la sécurité (testé par
  `tests/security/test_simulation.py`).
- Une règle peut être relue sans lire de code : c'est un objet de données.
- Le registre refuse d'instancier une règle obsolète, désactivée ou propre à
  une autre plateforme : `execute()` lève toujours `NotImplementedError`
  jusqu'à la phase 4.
- Les motifs reposent sur une sémantique unique de `**` (zéro ou plusieurs
  segments), implémentée par un algorithme linéaire et testée sur 22 cas.

## Bug découvert pendant la mise en œuvre

La validation de chemin (`realpath`) était appelée pour **chaque** fichier
parcouru : ~1,5 ms par appel sous Windows, soit plusieurs minutes sur un
dossier temporaire. L'ordre des contrôles a été inversé (tests bon marché
d'abord) : 0,08 ms par entrée, tout en conservant la validation avant toute
proposition.

Un second défaut, plus grave, a été trouvé par les tests : `_relative`
comparait un chemin natif (`\`) à un préfixe POSIX (`/`) sans normaliser
avant la comparaison. Résultat : sur Windows, **aucun** chemin n'était
reconnu comme relatif et les exclusions ne s'appliquaient jamais. Corrigé et
couvert par des tests unitaires et d'intégration.
