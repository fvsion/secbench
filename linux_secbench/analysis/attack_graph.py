"""Local privilege-escalation attack graph.

This is the layer that answers *"what is the actual attack vector?"* rather than
*"which configs are weak?"*. It is the security-domain application of **attack
graphs** (Sheyner & Wing; the MulVAL logic-programming approach of Ou et al.):
model the host as a directed graph whose nodes are privilege states and whose
edges are concrete exploitation steps, then reason over reachability.

Edges come from two places, with no new system access:

* **Escalation edges** — emitted by the EXT-PRIV-* checks in their ``actual``
  payload (`{"vectors": [...]}`): "as alice: sudo python (NOPASSWD)" → root,
  "alice ∈ docker" → group:docker → root, and so on.
* **Entry edges** — synthesized here from findings the attacker-value classifier
  marks as initial-access or credential-access (an exposed service, an empty
  password): attacker → a local foothold.

From the assembled graph we derive three things a single finding list cannot:

1. **Attack paths** — the end-to-end chains attacker → … → root.
2. **Chokepoints** — a max-flow/min-cut (Ford–Fulkerson) from the local foothold
   to root: the *smallest set of fixes* that makes root unreachable. When five
   users sit in the docker group, the cut is the one group capability, not five
   memberships — "fix this one thing."
3. **Edge-betweenness centrality** (Girvan–Newman) — which weaknesses the most
   attack paths route through, i.e. where remediation has the widest blast
   radius. (Betweenness, not PageRank, is the informative centrality on this
   source→sink topology — it measures path participation directly.)

Pure standard library; the graphs are tiny so exact enumeration is fine.
"""

from __future__ import annotations

import dataclasses
from collections import deque
from typing import Dict, List, Optional, Tuple

from ..core.model import CheckResult, ScanResult, Severity, Status

ATTACKER = "attacker"
LOCAL = "local"
ROOT = "root"

# A finding becomes an attacker→local *foothold* edge only when it is a genuine
# way onto the box *from the network* — a sensitive service exposed on a
# non-loopback socket (EXT-NET-1/2: "exposure"/"database") or a remotely
# brute-forceable login (missing lockout / no fail2ban: "brute-force").
#
# Deliberately EXCLUDED:
#   - Local credential access (world-readable keys, secrets in files, shell
#     history, /proc scraping, mimipenguin) — these require the attacker to
#     *already* have a shell, so they are escalation/lateral assets, not entry.
#   - A merely-enabled service (avahi, cups, rpcbind) — attack *surface* /
#     Discovery, not a guaranteed shell.
#   - An installed cleartext *client* (telnet/ftp) — a client tool is not a
#     listening entry point, so the generic "cleartext" tag must not enter here.
_FOOTHOLD_TAGS = frozenset({"exposure", "database", "brute-force"})


@dataclasses.dataclass(frozen=True)
class EscalationEdge:
    src: str
    dst: str
    technique: str
    finding_id: Optional[str] = None
    severity: str = "INFO"
    remediation: str = ""
    assumed: bool = False  # synthesized (e.g. assumed foothold), not a finding

    @property
    def phase(self) -> str:
        return "entry" if self.src == ATTACKER else "escalation"

    def key(self) -> Tuple[str, str, str]:
        return (self.src, self.dst, self.technique)

    def to_dict(self) -> Dict[str, object]:
        return {
            "src": self.src, "dst": self.dst, "technique": self.technique,
            "finding_id": self.finding_id, "severity": self.severity,
            "phase": self.phase, "assumed": self.assumed,
        }


@dataclasses.dataclass
class AttackPath:
    edges: List[EscalationEdge]

    @property
    def nodes(self) -> List[str]:
        out = [self.edges[0].src] if self.edges else []
        out.extend(e.dst for e in self.edges)
        return out

    @property
    def length(self) -> int:
        # Count only real exploitation steps, not the assumed foothold.
        return sum(1 for e in self.edges if not e.assumed)

    @property
    def max_severity(self) -> str:
        sevs = [Severity[e.severity] for e in self.edges if e.severity in Severity.__members__]
        return max(sevs).name if sevs else "INFO"

    def label(self) -> str:
        parts = [self.edges[0].src] if self.edges else []
        for e in self.edges:
            parts.append(f"──[{e.technique}]──▶ {e.dst}")
        return " ".join(parts)

    def to_dict(self) -> Dict[str, object]:
        return {
            "length": self.length,
            "max_severity": self.max_severity,
            "nodes": self.nodes,
            "steps": [e.to_dict() for e in self.edges],
        }


@dataclasses.dataclass
class AttackGraphAnalysis:
    root_reachable: bool
    assumed_foothold: bool
    paths: List[AttackPath]
    chokepoints: List[EscalationEdge]
    central_edges: List[Tuple[EscalationEdge, float]]
    edge_count: int
    node_count: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "root_reachable": self.root_reachable,
            "assumed_foothold": self.assumed_foothold,
            "edge_count": self.edge_count,
            "node_count": self.node_count,
            "paths": [p.to_dict() for p in self.paths],
            "chokepoints": [e.to_dict() for e in self.chokepoints],
            "central_edges": [{**e.to_dict(), "betweenness": round(score, 3)}
                              for e, score in self.central_edges],
        }


class AttackGraph:
    """A directed multigraph of escalation/entry edges with graph algorithms."""

    def __init__(self) -> None:
        self.edges: List[EscalationEdge] = []
        self._adj: Dict[str, List[EscalationEdge]] = {}
        self.nodes: set = set()
        self.assumed_foothold: bool = False

    def add(self, edge: EscalationEdge) -> None:
        self.edges.append(edge)
        self._adj.setdefault(edge.src, []).append(edge)
        self.nodes.update((edge.src, edge.dst))

    # -- reachability & paths ------------------------------------------------

    def reachable(self, source: str, target: str) -> bool:
        if source not in self.nodes:
            return False
        seen, queue = {source}, deque([source])
        while queue:
            node = queue.popleft()
            if node == target:
                return True
            for e in self._adj.get(node, []):
                if e.dst not in seen:
                    seen.add(e.dst)
                    queue.append(e.dst)
        return False

    def paths(self, source: str, target: str, max_depth: int = 8,
              max_paths: int = 200) -> List[AttackPath]:
        """Enumerate simple source→target paths (bounded for safety)."""
        found: List[AttackPath] = []

        def dfs(node: str, trail: List[EscalationEdge], visited: set) -> None:
            if len(found) >= max_paths or len(trail) > max_depth:
                return
            if node == target and trail:
                found.append(AttackPath(list(trail)))
                return
            for e in self._adj.get(node, []):
                if e.dst in visited:
                    continue
                trail.append(e)
                visited.add(e.dst)
                dfs(e.dst, trail, visited)
                trail.pop()
                visited.discard(e.dst)

        dfs(source, [], {source})
        # Shortest, most-severe first.
        found.sort(key=lambda p: (p.length, -Severity[p.max_severity].value))
        return found

    # -- min cut (max-flow, Edmonds–Karp) ------------------------------------

    def min_cut(self, source: str, target: str) -> List[EscalationEdge]:
        """Return a minimum edge cut separating source from target.

        Unit capacity per edge; parallel edges between the same pair sum. The
        returned edges are the concrete weaknesses that, fixed together, make
        ``target`` unreachable from ``source``.
        """
        if source not in self.nodes or not self.reachable(source, target):
            return []
        # Aggregate capacities and remember which edges back each arc.
        cap: Dict[str, Dict[str, int]] = {}
        backing: Dict[Tuple[str, str], List[EscalationEdge]] = {}
        for e in self.edges:
            cap.setdefault(e.src, {}).setdefault(e.dst, 0)
            cap.setdefault(e.dst, {}).setdefault(e.src, 0)  # residual reverse
            cap[e.src][e.dst] += 1
            backing.setdefault((e.src, e.dst), []).append(e)

        residual = {u: dict(v) for u, v in cap.items()}

        def bfs_augment() -> Optional[List[str]]:
            parent = {source: None}
            q = deque([source])
            while q:
                u = q.popleft()
                for v, c in residual.get(u, {}).items():
                    if c > 0 and v not in parent:
                        parent[v] = u
                        if v == target:
                            # Reconstruct path.
                            path, cur = [], target
                            while cur is not None:
                                path.append(cur)
                                cur = parent[cur]
                            return list(reversed(path))
                        q.append(v)
            return None

        while True:
            path = bfs_augment()
            if not path:
                break
            # Unit-ish augment: min residual along path.
            bottleneck = min(residual[path[i]][path[i + 1]] for i in range(len(path) - 1))
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                residual[u][v] -= bottleneck
                residual[v][u] = residual.get(v, {}).get(u, 0) + bottleneck

        # Source-side of the residual graph.
        s_side, q = {source}, deque([source])
        while q:
            u = q.popleft()
            for v, c in residual.get(u, {}).items():
                if c > 0 and v not in s_side:
                    s_side.add(v)
                    q.append(v)

        cut: List[EscalationEdge] = []
        for (u, v), edges in backing.items():
            if u in s_side and v not in s_side:
                cut.extend(edges)
        return cut

    # -- centrality ----------------------------------------------------------

    def edge_betweenness(self, paths: List[AttackPath]) -> Dict[Tuple[str, str, str], float]:
        """Fraction of the given attack paths that traverse each edge.

        A direct, interpretable betweenness over the enumerated source→sink
        paths: high score = many ways in route through this single weakness.
        """
        if not paths:
            return {}
        counts: Dict[Tuple[str, str, str], int] = {}
        for p in paths:
            seen = set()
            for e in p.edges:
                k = e.key()
                if k not in seen:  # count an edge once per path
                    counts[k] = counts.get(k, 0) + 1
                    seen.add(k)
        n = len(paths)
        return {k: c / n for k, c in counts.items()}


# --------------------------------------------------------------------------- #
# Building & analysing
# --------------------------------------------------------------------------- #

def build_attack_graph(scan: ScanResult) -> AttackGraph:
    """Assemble the attack graph from a scan's findings.

    Sets ``graph.assumed_foothold`` when a synthesized "attacker has a shell"
    entry edge was added because no explicit network entry vector was found.
    """
    graph = AttackGraph()
    has_entry = False
    has_escalation = False

    for r in scan.results:
        if r.status not in (Status.FAIL, Status.WARN, Status.MANUAL):
            continue
        vectors = _vectors_of(r)
        if vectors:
            for v in vectors:
                graph.add(EscalationEdge(
                    src=v.get("src", LOCAL), dst=v.get("dst", ROOT),
                    technique=v.get("technique", r.metadata.title),
                    finding_id=r.id, severity=r.severity.name,
                    remediation=r.metadata.remediation,
                ))
                if v.get("dst") == ROOT or v.get("src", LOCAL) != ATTACKER:
                    has_escalation = True
            continue
        # Otherwise, is this a genuine *foothold* vector? Gate on concrete
        # foothold tags, not the broad attacker-value tactic — an enabled
        # service is surface, not a shell.
        if set(r.metadata.tags) & _FOOTHOLD_TAGS:
            graph.add(EscalationEdge(
                src=ATTACKER, dst=LOCAL, technique=r.metadata.title,
                finding_id=r.id, severity=r.severity.name,
                remediation=r.metadata.remediation,
            ))
            has_entry = True

    # If there is a way to root from a local foothold but we found no explicit
    # network entry, assume the standard pentest premise: the attacker can get
    # *a* shell. This keeps local-privesc analysis meaningful on a host whose
    # entry vectors live elsewhere (phishing, a vulnerable app, stolen creds).
    if has_escalation and not has_entry:
        graph.add(EscalationEdge(
            src=ATTACKER, dst=LOCAL,
            technique="assumed local access (valid shell / foothold)",
            severity="INFO", assumed=True,
        ))
        graph.assumed_foothold = True
    return graph


def analyze(scan: ScanResult, max_paths: int = 25) -> AttackGraphAnalysis:
    """Run the full attack-graph analysis over a scan."""
    graph = build_attack_graph(scan)
    assumed = graph.assumed_foothold
    reachable = graph.reachable(ATTACKER, ROOT)
    paths = graph.paths(ATTACKER, ROOT, max_paths=max_paths) if reachable else []

    # Chokepoints: assume the foothold and ask what severs root. This is the
    # defensible question ("an attacker will get a shell — now what stops them").
    chokepoints = graph.min_cut(LOCAL, ROOT) if graph.reachable(LOCAL, ROOT) else []
    # Report each underlying finding once.
    chokepoints = _dedupe_by_finding(chokepoints)

    betweenness = graph.edge_betweenness(paths)
    central = sorted(
        ((e, betweenness.get(e.key(), 0.0)) for e in _dedupe_by_finding(graph.edges) if not e.assumed),
        key=lambda t: t[1], reverse=True,
    )[:5]

    return AttackGraphAnalysis(
        root_reachable=reachable,
        assumed_foothold=assumed,
        paths=paths,
        chokepoints=chokepoints,
        central_edges=[c for c in central if c[1] > 0.0],
        edge_count=len([e for e in graph.edges if not e.assumed]),
        node_count=len(graph.nodes),
    )


def _vectors_of(result: CheckResult) -> List[dict]:
    actual = result.actual
    if isinstance(actual, dict) and isinstance(actual.get("vectors"), list):
        return [v for v in actual["vectors"] if isinstance(v, dict)]
    return []


def _dedupe_by_finding(edges: List[EscalationEdge]) -> List[EscalationEdge]:
    """Collapse edges that share a finding id (keep the first), preserving order."""
    seen, out = set(), []
    for e in edges:
        marker = e.finding_id or e.key()
        if marker in seen:
            continue
        seen.add(marker)
        out.append(e)
    return out
