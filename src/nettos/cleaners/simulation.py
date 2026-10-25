# SPDX-License-Identifier: AGPL-3.0-or-later
"""Moteur de simulation partagé par les nettoyeurs.

Toute la logique de sécurité vit ici, et non dans chaque règle : une règle
ne fournit que des racines et un motif. Ce choix rend la règle n°3
(« les règles décrivent, elles ne contiennent pas de commandes ») réelle et
permet de tester une seule fois un comportement critique.

Le module est **strictement en lecture seule** : il n'ouvre un fichier que
pour lire ses métadonnées.
"""

from __future__ import annotations

import fnmatch
import os
import re
import stat
import time
from pathlib import Path

from nettos.cleaners.base import CandidateFile, RejectedFile, SimulationResult
from nettos.cleaners.rules import CleanerRule, CleanTarget
from nettos.core.errors import PathOutsideAuthorizedRootError
from nettos.core.result import ErrorKind
from nettos.diagnostics.filesystem import is_link_like
from nettos.security.path_policy import resolve_no_symlinks

_MAX_DEPTH = 64
"""Profondeur maximale sous une racine (protège contre les structures folles)."""


def _error_kind(exc: OSError) -> ErrorKind:
    """Classe une erreur système pour le rapport de rejet."""
    if isinstance(exc, PermissionError):
        return ErrorKind.PERMISSION_DENIED
    if isinstance(exc, FileNotFoundError):
        return ErrorKind.NOT_FOUND
    return ErrorKind.IO_ERROR


def _normalize(pattern: str) -> str:
    """Uniformise les séparateurs de motif pour la comparaison."""
    return pattern.replace("\\", "/")


class CompiledPattern:
    """Motif pré-analysé, pour éviter de recalculer à chaque entrée.

    Sans cette compilation, chaque fichier parcouru redécoupe 18 motifs
    d'exclusion et recompile une expression régulière par appel : sur un
    dossier temporaire de plusieurs centaines de milliers d'entrées, cela
    représente plusieurs minutes de calcul pur.

    Optimisations décisives :

    - un motif **littéral** (aucun ``*``, ``?`` ou ``[``) est comparé par
      égalité de chaîne, sans expression régulière ;
    - un motif à un seul segment (``*.tmp``) est comparé au **nom** de
      fichier via une regex pré-compilée une fois pour toutes ;
    - un motif multi-segments garde l'algorithme itératif correct de
      ``**``, mais chaque segment est déjà traduit en regex.
    """

    __slots__ = ("_is_name_only", "_literal", "_pattern", "_segment_regexes", "_single_regex")

    def __init__(self, pattern: str) -> None:
        self._pattern = _normalize(pattern)
        self._is_name_only = "/" not in self._pattern
        has_wildcard = any(char in self._pattern for char in "*?[")

        self._literal: str | None = None
        self._single_regex: re.Pattern[str] | None = None
        self._segment_regexes: tuple[re.Pattern[str] | None, ...] = ()

        if not has_wildcard:
            self._literal = self._pattern
        elif self._is_name_only:
            self._single_regex = re.compile(_segment_to_regex(self._pattern) + r"\Z")
        else:
            segments = self._pattern.split("/")
            # « ** » en tête suivi d'un unique segment (``**/*.lock``) est
            # strictement équivalent à ce segment comparé au nom : c'est le
            # cas de loin le plus fréquent dans les exclusions.
            inner = [s for s in segments if s != "**"]
            if (
                len(segments) >= 2
                and segments[0] == "**"
                and len(inner) == 1
                and segments[-1] != "**"
            ):
                self._single_regex = re.compile(_segment_to_regex(inner[0]) + r"\Z")
                return
            self._segment_regexes = tuple(
                None if segment == "**" else re.compile(_segment_to_regex(segment) + r"\Z")
                for segment in segments
            )

    @property
    def pattern(self) -> str:
        """Motif d'origine, normalisé."""
        return self._pattern

    def matches(self, relative_path: str) -> bool:
        """Indique si ``relative_path`` correspond à ce motif."""
        candidate = _normalize(relative_path)

        if self._literal is not None:
            if self._is_name_only:
                return candidate.rsplit("/", 1)[-1] == self._literal
            return candidate == self._literal or candidate.endswith("/" + self._literal)

        if self._single_regex is not None:
            return self._single_regex.match(candidate.rsplit("/", 1)[-1]) is not None

        return _match_segments(candidate.split("/"), self._segment_regexes)


def _segment_to_regex(segment: str) -> str:
    """Traduit un segment (sans ``/``) en corps d'expression régulière ancré."""
    translated = fnmatch.translate(segment)
    if translated.startswith("(?s:"):
        translated = translated[4:]
    if translated.endswith(r")\Z"):
        translated = translated[:-3]
    return translated


def _match_segments(candidate: list[str], segments: tuple[re.Pattern[str] | None, ...]) -> bool:
    """Correspondance itérative de ``*`` (un segment) et ``**`` (zéro ou plus).

    Deux pointeurs avec un seul point de retour arrière pour le dernier
    ``**`` : complexité linéaire, jamais d'explosion combinatoire.
    """
    c_len, p_len = len(candidate), len(segments)
    c_index = p_index = 0
    star_pattern = -1
    star_candidate = 0

    while c_index < c_len:
        segment = segments[p_index] if p_index < p_len else None
        if p_index < p_len and segment is None:
            star_pattern = p_index
            star_candidate = c_index
            p_index += 1
        elif p_index < p_len and segment is not None and segment.match(candidate[c_index]):
            c_index += 1
            p_index += 1
        elif star_pattern != -1:
            star_candidate += 1
            c_index = star_candidate
            p_index = star_pattern + 1
        else:
            return False

    while p_index < p_len and segments[p_index] is None:
        p_index += 1
    return p_index == p_len


_COMPILED_CACHE: dict[str, CompiledPattern] = {}


def compile_pattern(pattern: str) -> CompiledPattern:
    """Retourne (et mémorise) la forme compilée d'un motif."""
    compiled = _COMPILED_CACHE.get(pattern)
    if compiled is None:
        compiled = CompiledPattern(pattern)
        _COMPILED_CACHE[pattern] = compiled
    return compiled


def matches_pattern(relative_path: str, pattern: str) -> bool:
    """Indique si ``relative_path`` correspond au motif de cible.

    Deux formes sont acceptées :

    - ``*.tmp`` : correspondance sur le nom de fichier ;
    - ``cache/**/*.log`` : correspondance sur le chemin relatif complet, où
      ``**`` traverse zéro ou plusieurs segments et ``*`` reste dans un
      segment.

    Le résultat est strictement équivalent à ``CompiledPattern.matches`` ;
    cette fonction est la façade pratique pour les tests et les appels
    ponctuels.
    """
    return compile_pattern(pattern).matches(relative_path)


def _match_parts(candidate: list[str], pattern: list[str]) -> bool:
    """Correspondance itérative de ``*`` (un segment) et ``**`` (zéro ou plus).

    Algorithme à deux pointeurs avec un seul point de retour arrière pour le
    dernier ``**`` rencontré : complexité linéaire en le nombre de segments,
    jamais d'explosion combinatoire sur ``**/*``.
    """
    c_len, p_len = len(candidate), len(pattern)
    c_index = p_index = 0
    star_pattern = -1
    star_candidate = 0

    while c_index < c_len:
        if p_index < p_len and pattern[p_index] == "**":
            star_pattern = p_index
            star_candidate = c_index
            p_index += 1
        elif p_index < p_len and fnmatch.fnmatchcase(candidate[c_index], pattern[p_index]):
            c_index += 1
            p_index += 1
        elif star_pattern != -1:
            # Le dernier ``**`` consomme un segment de plus, puis on réessaie.
            star_candidate += 1
            c_index = star_candidate
            p_index = star_pattern + 1
        else:
            return False

    while p_index < p_len and pattern[p_index] == "**":
        p_index += 1
    return p_index == p_len


def matches_exclusion(relative_path: str, exclusions: tuple[str, ...]) -> str | None:
    """Retourne l'exclusion qui frappe ce chemin, ou ``None``.

    Une exclusion gagne **toujours** : elle est inspectée avant toute cible,
    ce qui rend le comportement conservateur et prévisible.
    """
    for exclusion in exclusions:
        if compile_pattern(exclusion).matches(relative_path):
            return exclusion
    return None


_EXCLUSION_CACHE: dict[tuple[str, ...], tuple[CompiledPattern, ...]] = {}
_TargetKey = tuple[str, str, tuple[tuple[str, int | None], ...]]
_TARGET_CACHE: dict[_TargetKey, tuple[tuple[CompiledPattern, CleanTarget], ...]] = {}


def compiled_exclusions(exclusions: tuple[str, ...]) -> tuple[CompiledPattern, ...]:
    """Formes compilées des exclusions d'une règle, mémorisées."""
    compiled = _EXCLUSION_CACHE.get(exclusions)
    if compiled is None:
        compiled = tuple(compile_pattern(pattern) for pattern in exclusions)
        _EXCLUSION_CACHE[exclusions] = compiled
    return compiled


def _compiled_targets(rule: CleanerRule) -> tuple[tuple[CompiledPattern, CleanTarget], ...]:
    """Cibles compilées d'une règle, mémorisées par contenu exact.

    La clé inclut les motifs eux-mêmes, pas seulement l'identifiant : deux
    règles portant le même identifiant mais des cibles différentes (cas des
    tests et d'une future surcharge utilisateur) ne doivent jamais partager
    une entrée de cache. Un cache erroné ici ferait appliquer un filtre
    d'âge d'une règle à une autre — exactement le genre de bug silencieux
    que la sécurité du produit ne tolère pas.
    """
    key = (
        rule.identifier,
        rule.version,
        tuple((t.pattern, t.max_age_days) for t in rule.targets),
    )
    compiled = _TARGET_CACHE.get(key)
    if compiled is None:
        compiled = tuple((compile_pattern(t.pattern), t) for t in rule.targets)
        _TARGET_CACHE[key] = compiled
    return compiled


def _first_exclusion(relative_path: str, exclusions: tuple[str, ...]) -> str | None:
    """Variante rapide de :func:`matches_exclusion` sur motifs pré-compilés.

    Tous les motifs sont testés : une optimisation qui écarterait des motifs
    sur un chemin plat risquerait de manquer une vraie exclusion (``**/pip/**``
    matche aussi le nom seul ``pip``), et un faux négatif d'exclusion est un
    défaut de sécurité, pas une simple lenteur.
    """
    for compiled in compiled_exclusions(exclusions):
        if compiled.matches(relative_path):
            return compiled.pattern
    return None


class SimulationEngine:
    """Énumère les fichiers ciblés par une règle, sans rien modifier."""

    MAX_ENTRIES = 500_000
    """Plafond d'entrées visitées : borne la durée d'une simulation.

    Une simulation doit rester interactive. Au-delà, le résultat est marqué
    ``truncated`` et l'utilisateur est invité à affiner la règle — jamais à
    subir une fenêtre figée.
    """

    def __init__(
        self,
        *,
        now: float | None = None,
        max_candidates: int = 100_000,
        max_entries: int | None = None,
    ) -> None:
        self._now = time.time() if now is None else now
        self._max_candidates = max_candidates
        self._max_entries = self.MAX_ENTRIES if max_entries is None else max_entries
        self._visited = 0

    def simulate(self, rule: CleanerRule, roots: list[Path]) -> SimulationResult:
        """Produit le résultat de simulation pour ``rule`` sur ``roots``."""
        result = SimulationResult(rule_identifier=rule.identifier)
        self._visited = 0

        for root in roots:
            resolved_root = Path(os.path.realpath(root))
            if not resolved_root.exists():
                result.missing_roots.append(str(root))
                continue
            self._walk_root(rule, resolved_root, result)
            if result.truncated:
                return result
        return result

    def _walk_root(self, rule: CleanerRule, root: Path, result: SimulationResult) -> None:
        """Parcourt une racine et collecte les candidats autorisés."""
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    for entry in iterator:
                        self._visited += 1
                        if self._visited > self._max_entries:
                            result.truncated = True
                            return
                        if result.truncated:
                            return
                        self._consider_entry(rule, root, entry, depth, result, stack)
            except OSError as exc:
                result.rejected.append(
                    RejectedFile(
                        path=str(current),
                        reason=f"répertoire illisible : {exc}",
                        kind=_error_kind(exc),
                    )
                )

    def _consider_entry(
        self,
        rule: CleanerRule,
        root: Path,
        entry: os.DirEntry[str],
        depth: int,
        result: SimulationResult,
        stack: list[tuple[Path, int]],
    ) -> None:
        """Traite une entrée : rejet, descente ou candidat."""
        relative = self._relative(entry.path, root)

        try:
            if is_link_like(entry):
                result.rejected.append(
                    RejectedFile(path=entry.path, reason="lien ou point d'analyse non suivi")
                )
                return
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            result.rejected.append(
                RejectedFile(path=entry.path, reason=str(exc), kind=_error_kind(exc))
            )
            return

        is_directory = stat.S_ISDIR(info.st_mode)

        # Une exclusion est testée sur les répertoires **et** les fichiers :
        # une exclusion sur un répertoire n'empêche pas seulement d'y
        # descendre, elle interdit aussi de proposer un fichier portant ce
        # chemin.
        exclusion = _first_exclusion(relative, rule.excluded)
        if exclusion is not None:
            result.rejected.append(
                RejectedFile(path=entry.path, reason=f"exclu par la règle ({exclusion})")
            )
            return

        if is_directory:
            if depth < _MAX_DEPTH:
                stack.append((Path(entry.path), depth + 1))
            else:
                result.rejected.append(
                    RejectedFile(path=entry.path, reason="profondeur maximale atteinte")
                )
            return

        if not stat.S_ISREG(info.st_mode):
            return

        self._maybe_add_candidate(rule, root, entry.path, info, relative, result)

    def _maybe_add_candidate(
        self,
        rule: CleanerRule,
        root: Path,
        path: str,
        info: os.stat_result,
        relative: str,
        result: SimulationResult,
    ) -> None:
        """Ajoute le fichier s'il correspond à une cible et passe l'âge minimum.

        L'ordre des contrôles est délibéré : les tests **bon marché** (motif,
        âge) passent avant la validation de chemin, qui appelle
        ``realpath`` et coûte ~1,5 ms par appel sous Windows. Sur un dossier
        de plusieurs centaines de milliers de fichiers, inverser cet ordre
        transforme une simulation de quelques secondes en plusieurs minutes.
        """
        target = self._matching_target(rule, relative)
        if target is None:
            return

        age_days = max((self._now - info.st_mtime) / 86_400.0, 0.0)
        if target.max_age_days is not None and age_days < target.max_age_days:
            result.rejected.append(
                RejectedFile(
                    path=path,
                    reason=f"trop récent ({age_days:.0f} j < {target.max_age_days} j requis)",
                )
            )
            return
        if len(result.candidates) >= self._max_candidates:
            result.truncated = True
            return

        try:
            resolved = resolve_no_symlinks(Path(path), root=root)
        except PathOutsideAuthorizedRootError as exc:
            result.rejected.append(RejectedFile(path=path, reason=str(exc)))
            return

        result.candidates.append(
            CandidateFile(
                path=str(resolved),
                size_bytes=info.st_size,
                modified_at=info.st_mtime,
                age_days=round(age_days, 2),
            )
        )

    @staticmethod
    def _matching_target(rule: CleanerRule, relative: str) -> CleanTarget | None:
        for target in _compiled_targets(rule):
            compiled, original = target
            if compiled.matches(relative):
                return original
        return None

    @staticmethod
    def _relative(path: str, root: Path) -> str:
        """Chemin relatif à ``root``, par découpe de chaîne.

        ``Path.relative_to`` coûte ~90 µs par appel (parsing complet du
        chemin), soit près de deux secondes pour 20 000 entrées. La racine
        étant déjà résolue, une simple découpe de préfixe est équivalente.

        Attention à l'ordre : ``os.scandir`` renvoie des chemins avec le
        séparateur natif (``\\`` sous Windows) alors que ``as_posix`` produit
        des ``/``. Normaliser **avant** de comparer le préfixe est
        indispensable, sinon aucun chemin Windows ne serait reconnu comme
        relatif — les motifs et exclusions ne s'appliqueraient alors jamais.
        """
        normalized = _normalize(path)
        prefix = _normalize(root.as_posix()).rstrip("/") + "/"
        if normalized.startswith(prefix):
            return normalized[len(prefix) :]
        return normalized.rsplit("/", 1)[-1]


__all__ = [
    "SimulationEngine",
    "matches_exclusion",
    "matches_pattern",
]
