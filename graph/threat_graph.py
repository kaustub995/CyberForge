"""
graph/threat_graph.py - NetworkX threat graph for CyberForge.

Node types (EMail, URL, DOMAIN, IP) and typed relationships:

    EMAIL  --contains-->   URL
    URL    --belongs_to--> DOMAIN
    DOMAIN --resolves_to--> IP
    EMAIL  --received_from--> IP

Nodes are keyed by a stable id (type-prefixed) so duplicate nodes are never
added. The module is NetworkX-only (rendering is left to the Streamlit layer).
"""

from urllib.parse import urlparse

import networkx as nx

NODE_TYPES = ("EMAIL", "URL", "DOMAIN", "IP")
EDGE_RELATIONS = ("contains", "belongs_to", "resolves_to", "received_from")


def extract_domain(url: str) -> str:
    """Return the registrable-with-subdomain host of a URL (lowercased)."""
    raw = str(url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    host = urlparse(raw).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host


class ThreatGraph:
    """Typed multi-digraph of email -> url -> domain -> ip relationships."""

    def __init__(self):
        self.graph = nx.MultiDiGraph()

    # ── Node helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def node_id(node_type: str, value: str) -> str:
        return f"{node_type}:{value}"

    def has_node(self, node_type: str, value: str) -> bool:
        return self.node_id(node_type, value) in self.graph

    def add_node(self, node_type: str, value: str, **attrs) -> str:
        node_type = str(node_type).upper()
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unknown node type: {node_type}")
        nid = self.node_id(node_type, value)
        if nid not in self.graph:
            self.graph.add_node(nid, node_type=node_type, value=value, label=value)
        for key, val in attrs.items():
            if val is not None:
                self.graph.nodes[nid][key] = val
        return nid

    # ── Typed adders ─────────────────────────────────────────────────────────

    def add_email(self, email_id, subject=None, sender=None, **attrs) -> str:
        return self.add_node("EMAIL", email_id,
                             subject=subject, sender=sender, **attrs)

    def add_url(self, url, **attrs) -> str:
        return self.add_node("URL", url, **attrs)

    def add_domain(self, domain, **attrs) -> str:
        return self.add_node("DOMAIN", domain.lower(), **attrs)

    def add_ip(self, ip, **attrs) -> str:
        return self.add_node("IP", ip, **attrs)

    # ── Typed edges ──────────────────────────────────────────────────────────

    def add_edge(self, src_type, src_value, dst_type, dst_value,
                 relation: str, **attrs) -> None:
        if relation not in EDGE_RELATIONS:
            raise ValueError(f"Unknown relation: {relation}")
        source = self.add_node(src_type, src_value)
        target = self.add_node(dst_type, dst_value)
        existing = {(u, v, d.get("rel")) for u, v, d in
                    self.graph.edges(keys=False, data=True)}
        if (source, target, relation) in existing:
            return
        self.graph.add_edge(source, target, rel=relation, **attrs)

    def add_email_contains_url(self, email_id: str, url: str) -> None:
        self.add_edge("EMAIL", email_id, "URL", url, "contains")

    def add_url_belongs_to_domain(self, url: str, domain: str) -> None:
        domain = extract_domain(domain) or extract_domain(url)
        if not domain:
            return
        self.add_edge("URL", url, "DOMAIN", domain, "belongs_to")

    def add_domain_resolves_to_ip(self, domain: str, ip: str) -> None:
        self.add_domain(domain)
        self.add_edge("DOMAIN", domain, "IP", ip, "resolves_to")

    def add_email_received_from_ip(self, email_id: str, ip: str, **ip_attrs) -> None:
        nid = self.add_ip(ip, **ip_attrs)
        self.add_edge("EMAIL", email_id, "IP", ip, "received_from")
        return nid

    # ── Convenience builders ────────────────────────────────────────────────

    def build_from_ip_intel(self, email_id: str, ip_results, urls=None):
        """
        Ingest IP-intelligence results (from services/ip_analyzer) plus optional
        URLs found in the email body, wiring URL -> DOMAIN -> IP where possible.
        """
        self.add_email(email_id)

        ip_attrs = ("country", "region", "city", "isp", "asn",
                    "organization", "reputation", "risk_level", "type",
                    "type_label")
        for result in ip_results or []:
            geo = result.get("geo") or {}
            attrs = {}
            for key in ip_attrs:
                if key in ("country", "region", "city", "isp", "asn",
                           "organization"):
                    attrs[key] = geo.get(key)
                elif key == "reputation":
                    rep = (result.get("geo") or {}).get("reputation")
                    if isinstance(rep, dict) and rep.get("score") is not None:
                        attrs[key] = rep["score"]
                    elif rep and rep.get("markers"):
                        attrs[key] = rep["markers"][0] if rep.get("markers") else None
                else:
                    attrs[key] = result.get(key)
            attrs["risk_level"] = result.get("risk_level")
            self.add_email_received_from_ip(email_id, result["ip"], **attrs)

        for url in urls or []:
            self.add_url(url)
            self.add_email_contains_url(email_id, url)
            domain = extract_domain(url)
            if domain:
                self.add_url_belongs_to_domain(url, domain)

        return self

    # ── Introspection / serialization ────────────────────────────────────────

    def node_count(self, node_type=None) -> int:
        if node_type is None:
            return self.graph.number_of_nodes()
        return sum(1 for _, data in self.graph.nodes(data=True)
                   if data.get("node_type") == node_type)

    def summary(self) -> dict:
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "by_type": {nt: self.node_count(nt) for nt in NODE_TYPES},
            "relations": {rel: sum(1 for _, _, d in self.graph.edges(data=True)
                                   if d.get("rel") == rel) for rel in EDGE_RELATIONS},
        }

    def to_cytoscape_elements(self) -> list:
        """Return nodes/edges as Cytoscape-style element dicts (for JSON/UI)."""
        elements = []
        color_by_type = {
            "EMAIL": "#9333ea",
            "URL": "#00aaff",
            "DOMAIN": "#FFD700",
            "IP": "#FF4444",
        }
        for nid, data in self.graph.nodes(data=True):
            elements.append({
                "data": {
                    "id": nid,
                    "label": data.get("label", nid),
                    "node_type": data.get("node_type"),
                    "risk_level": data.get("risk_level"),
                    "color": color_by_type.get(data.get("node_type"), "#64748b"),
                },
            })
        for u, v, data in self.graph.edges(data=True):
            elements.append({
                "data": {
                    "source": u,
                    "target": v,
                    "relation": data.get("rel"),
                    "label": data.get("rel", ""),
                },
            })
        return elements