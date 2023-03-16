import logging
from pathlib import Path

from rdflib import Graph
from rdflib.namespace import RDF, RDFS

from kuberdf import NS_K8S

log = logging.getLogger(__name__)


class RDF2Mermaid:
    """Convert an RDF graph to a mermaid graph."""

    ICON_MAP = {
        "urn:k8s:Application": "fa:fa-cubes",
        "urn:k8s:Container": "fa:fa-cube",
        "urn:k8s:Deployment": "\N{CLOCKWISE GAPPED CIRCLE ARROW}",
        "urn:k8s:DeploymentConfig": "\N{CLOCKWISE GAPPED CIRCLE ARROW}",
        "urn:k8s:Image": "fa:fa-docker",
        "urn:k8s:Namespace": "\N{DOTTED SQUARE}",
        "urn:k8s:PersistentVolumeClaim": "fa:fa-database",
        "urn:k8s:Pod": "fa:fa-cube",
        "urn:k8s:Port": "fa:fa-ethernet",
        "urn:k8s:Secret": "fa:fa-key",
        "urn:k8s:Service": "fa:fa-network-wired",
        "urn:k8s:Registry": "fa:fa-docker fa:fa-database",
        "urn:k8s:Route": "fa:fa-route",
        "urn:k8s:Host": "fa:fa-globe",
    }
    DONT_RENDER_AS_NODES = (
        NS_K8S.Application,
        #        NS_K8S.Image,
        NS_K8S.Host,
        NS_K8S.Namespace,
        NS_K8S.Pod,
        NS_K8S.Job,
        NS_K8S.BuildConfig,
        NS_K8S.Registry,
    )

    def __init__(self, g: Graph):
        self.g = g
        self.lines = []
        self.subgraphs = {}

    @staticmethod
    def sanitize_uri(s):
        """Sanitize a URI to be used as a node name in mermaid."""
        ret = s.split("@", 1)[0].replace("/", "_").replace("@", "_")
        return ret
        if len(ret) < 64:
            return ret
        prefix, suffix = ret[:64], ret[64:]
        import zlib

        return f"{zlib.crc32(prefix.encode())}_{suffix}"

    @staticmethod
    def sanitize_label(label):
        """Sanitize a label to be used as a node name in mermaid."""
        label = label.strip()
        ret = ""
        offset = 0
        for token in label.split():
            if token in ret:
                continue
            ret += token + " "
            if len(ret) - offset > 20:
                ret += r"\n"
                offset += 20
        return ret.strip(r"\n").strip()

    def parse(self, match: str = ""):
        if self.lines:
            log.info(f"Already parsed {len(self.lines)} lines.")
            return
        for s, p, o in self.g:
            if p != RDF.type:
                continue
            if match not in str(s) and match not in str(o):
                continue
            type_ = o
            # Skip non-k8s resources.
            if not str(type_).startswith(("urn:k8s:", "d3f:")):
                continue

            log.debug("Processing %s", [s, p, o])
            icon = RDF2Mermaid.ICON_MAP.get(str(type_), "") or type_
            src = RDF2Mermaid.sanitize_uri(s)

            label = self.g.value(s, RDFS.label) or ""
            label_l = f"{icon} {Path(s).name} {label}"
            label_l = RDF2Mermaid.sanitize_label(label_l)
            label_l = f'"{label_l}"'
            # Create a tree of subgraph based on the
            # hasChild predicate.
            for child in self.g.objects(s, NS_K8S.hasChild) or []:
                child = RDF2Mermaid.sanitize_uri(child)
                self.subgraphs.setdefault(
                    src,
                    {
                        "children": [],
                        "label": f"[{label_l}]",
                        "type": type_,
                    },
                )["children"].append(child)

            # Some resources should not be rendered as nodes
            # Instead they are rendered as subgraphs.
            if type_ in RDF2Mermaid.DONT_RENDER_AS_NODES:
                log.warning("Skipping %s", s)
            else:
                if type_ == NS_K8S.Container:
                    left_p, right_p = "[[", "]]"
                elif type_ == NS_K8S.Service:
                    left_p, right_p = "((", "))"
                elif type_ in (NS_K8S.PersistentVolumeClaim, NS_K8S.Image):
                    left_p, right_p = "[(", ")]"
                else:
                    left_p, right_p = "[", "]"
                self.lines.append(
                    f"""{src}{left_p}{label_l}{right_p}""".replace("\n", "")
                )

            for link in (
                NS_K8S.executes,
                NS_K8S.exposes,
                NS_K8S.accesses,
            ):
                for dst in self.g.objects(s, link) or []:
                    dst = RDF2Mermaid.sanitize_uri(dst)
                    self.lines.append(f"""{src} --> |{str(link)[8:]}| {dst}""")
        log.info("Parsed %s lines.", len(self.lines))

    def render(self):
        self.parse()
        ret = "graph\n"
        ret += "\n".join(self.lines)
        ret += "\n"
        ret += "%%\n%% Subgraphs\n%%\n"
        ret += "\n".join(RDF2Mermaid.create_tree(self.subgraphs))
        return ret

    @staticmethod
    def create_tree(tree):
        """Create a tree of subgraphs according to mermaid syntax."""
        rendered = set()

        def _render_tree(parent, data):
            label = data.get("label") or ""
            parent_type = data.get("type")
            children = data.get("children") or []
            children = set(children)
            if not children:
                return
            log.warning("Rendering %s", parent)
            children_to_render = set()
            for child in children:
                if child in rendered:
                    continue
                if child == parent:
                    continue
                if parent_type == NS_K8S.Namespace:
                    # Namespace should be processed last.
                    if "_Deployment_" in child:
                        continue
                    if "_DeploymentConfig_" in child:
                        continue
                    if "_Service_" in child:
                        continue
                if parent_type == NS_K8S.DeploymentConfig:
                    continue
                log.warning("Rendering %s", child)
                children_to_render.add(f"  {child}")
                rendered.add(child)
            if not children_to_render:
                return
            yield f"subgraph {parent}{label}"
            yield from children_to_render
            yield "end"

        tree_namespace = []
        for parent, data in tree.items():
            parent_type = data.get("type")
            if parent_type == NS_K8S.Namespace:
                tree_namespace.append((parent, data))
                continue
            yield from _render_tree(parent, data)
        for parent, data in tree_namespace:
            yield from _render_tree(parent, data)
