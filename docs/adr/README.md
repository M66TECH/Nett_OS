# Registre des décisions d'architecture (ADR)

Chaque décision structurante est consignée ici, sur une page au plus, avec son
contexte, les options envisagées, la décision et ses conséquences.

Les enregistrements sont **immuables** : une décision révisée produit un nouvel
enregistrement qui annule explicitement le précédent.

| N° | Titre | Statut |
|----|-------|--------|
| [0001](0001-licence-agpl-3.0.md) | Licence AGPL-3.0 plutôt que GPL-3.0 | Acceptée |
| [0002](0002-python-3.10-minimum.md) | Python 3.10 comme version minimale | Acceptée |
| [0003](0003-package-layout-src.md) | Arborescence `src/` et découpage par couches | Acceptée |
| [0004](0004-junctions-non-suivies.md) | Ne jamais suivre les junctions et points d'analyse | Acceptée |

## Modèle d'un enregistrement

```
# NNNN — Titre

- Statut : proposée | acceptée | remplacée par ADR-XXXX
- Date : AAAA-MM-JJ

## Contexte
## Options envisagées
## Décision
## Conséquences
```
