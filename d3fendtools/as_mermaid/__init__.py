import logging
import uuid
from pathlib import Path

from rdflib import Graph
from rdflib.namespace import RDF, RDFS

from d3fendtools.kuberdf import NS_D3F, NS_K8S

log = logging.getLogger(__name__)


def render_in_chunks(items, chunk_size=6):
    """Render a list of items in chunks."""
    items = list(items)
    if len(items) <= chunk_size:
        yield from items
        return
    for i in range(0, len(items), chunk_size):
        yield f"subgraph {uuid.uuid4()} [ ]"
        yield from items[i : i + chunk_size]
        yield "end"


class RDF2Mermaid:
    """Convert an RDF graph to a mermaid graph."""

    ICON_MAP = {
        "urn:k8s:Application": "fa:fa-cubes",
        "urn:k8s:ConfigMap": "\N{EMPTY DOCUMENT}",
        "urn:k8s:Container": "fa:fa-cube",
        "urn:k8s:CronJob": "fa:fa-clock",
        "urn:k8s:Deployment": "\N{CLOCKWISE GAPPED CIRCLE ARROW}",
        "urn:k8s:DeploymentConfig": "\N{CLOCKWISE GAPPED CIRCLE ARROW}",
        "urn:k8s:Endpoint": "fa:fa-ethernet",
        "urn:k8s:Endpoints": "fa:fa-ethernet",
        "urn:k8s:Host": "fa:fa-globe",
        "urn:k8s:Image": "fab:fa-docker",
        "urn:k8s:ImageStream": "fab:fa-docker fa:fa-tags",
        "urn:k8s:ImageStreamTag": "fab:fa-docker fa:fa-tag",
        "urn:k8s:Namespace": "\N{DOTTED SQUARE}",
        "urn:k8s:PersistentVolumeClaim": "fa:fa-hard-drive",
        "urn:k8s:Pod": "fa:fa-cube",
        "urn:k8s:Port": "fa:fa-ethernet",
        "urn:k8s:Secret": "fa:fa-key",
        "urn:k8s:Service": "fa:fa-sitemap",
        "urn:k8s:Registry": "fab:fa-docker fa:fa-boxes-stacked",
        "urn:k8s:Route": "fa:fa-route",
    }
    # NB: A node connected with another is always rendered.
    DONT_RENDER = (
        # These are not nodes.
        NS_K8S.Pod,
        NS_K8S.Job,
        NS_K8S.BuildConfig,
        NS_K8S.Selector,
        # NS_K8S.Host,
        # # For now, skip these. XXX
        # NS_K8S.Image,
        # NS_K8S.ImageStream,
        # NS_K8S.ImageStreamTag,
    )
    RENDER_AS_SUBGRAPHS = (
        NS_K8S.Namespace,
        NS_K8S.Registry,
        NS_K8S.Application,
        # DC are groups.
        NS_K8S.DeploymentConfig,
        NS_K8S.Deployment,
    )
    DONT_RENDER_AS_NODES = DONT_RENDER + RENDER_AS_SUBGRAPHS

    def __init__(self, g: Graph):
        self.g = g
        g.bind("k8s", NS_K8S)
        g.bind("d3f", NS_D3F)
        self.lines = []
        self.nodes = []
        self.edges = []
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

    def parse(self, match: str = "", simplified_view=False):
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
            # Don't render unless connected.
            if type_ in self.DONT_RENDER:
                continue

            log.debug("Processing %s", [s, p, o])
            icon = RDF2Mermaid.ICON_MAP.get(str(type_), "") or type_
            src = RDF2Mermaid.sanitize_uri(s)

            label = self.g.value(s, RDFS.label) or ""
            label_l = f"{icon}"

            # Additional icons for some types.
            for needle, icn in {
                "nodejs": "fab:fa-node",
                "java": "fab:fa-java",
                "jdk": "fab:fa-java",
                "python": "fab:fa-python",
                "ruby": "fab:fa-ruby",
                "php": " fab:fa-php",
            }.items():
                if needle in str(src).lower():
                    label_l += f" {icn} "
            # Always render labels for subgraphs.
            if not simplified_view or type_ in self.RENDER_AS_SUBGRAPHS:
                label_l += f" {Path(s).name} {label}"
            label_l = RDF2Mermaid.sanitize_label(label_l)
            label_l = f'"{label_l}"'

            # Create a tree of subgraph based on the
            # hasChild predicate.
            for child in self.g.objects(s, NS_K8S.hasChild) or []:
                child = RDF2Mermaid.sanitize_uri(child)
                children_ = self.subgraphs.setdefault(
                    src,
                    {
                        "children": [],
                        "label": f"[{label_l}]",
                        "type": type_,
                    },
                )["children"]
                children_.append(child)
                children_ = None
                if False and type_ == NS_K8S.Namespace and child.startswith("TCP:__"):
                    controlplane = self.subgraphs.setdefault(
                        f"{src}_cp",
                        {
                            "children": [],
                            "label": f"[{label_l}]",
                            "type": type_,
                        },
                    )["children"]
                    controlplane.append(child)
                    child = f"{src}_cp"

            # Some resources should not be rendered as nodes
            # Instead they are rendered as subgraphs.
            if type_ in RDF2Mermaid.DONT_RENDER_AS_NODES:
                log.warning("Skipping %s", s)
            else:
                if type_ == NS_K8S.Container:
                    left_p, right_p = "[[", "]]"
                elif type_ == NS_K8S.Service:
                    left_p, right_p = "((", "))"
                elif type_ in (
                    NS_K8S.PersistentVolumeClaim,
                    NS_K8S.Image,
                    NS_K8S.ImageStream,
                    NS_K8S.ImageStreamTag,
                ):
                    left_p, right_p = "[(", ")]"
                elif type_ in (NS_K8S.Route,):
                    left_p, right_p = "([", "])"
                elif type_ in (NS_K8S.Deployment, NS_K8S.DeploymentConfig):
                    left_p, right_p = "[\\", "/]"
                elif type_ in (NS_K8S.ConfigMap, NS_K8S.Secret):
                    left_p, right_p = ">", "]"

                else:
                    left_p, right_p = "([", "])"

                line = f"""{src}{left_p}{label_l}{right_p}""".replace("\n", "")
                if line not in self.nodes:
                    self.nodes.append(line)

            #
            # Adjust link direction to improve readability.
            #
            for link, arrow in (
                (NS_K8S.exposes, "-.-o"),
                (NS_D3F.executes, "-->"),
                (NS_D3F.runs, "-->"),
                (NS_D3F.accesses, "-->"),
                (NS_D3F.reads, "-->"),
            ):
                for dst in self.g.objects(s, link) or []:
                    dst = RDF2Mermaid.sanitize_uri(dst)
                    if link == NS_K8S.exposes:
                        src, dst = dst, src
                        link = "exposed by"
                    elif link in (NS_D3F.executes, NS_D3F.runs):
                        pass
                        # src, dst = dst, src
                        # link = "executed by"
                    elif "configmap" in dst.lower() or "secret" in dst.lower():
                        # src, dst = dst, src
                        arrow = "-.->"

                    if link.startswith("urn:k8s:"):
                        link = str(link)[8:]

                    if hasattr(link, "fragment"):
                        link = link.fragment

                    line = f"""{src} {arrow} |{link}| {dst}"""
                    if line not in self.edges:
                        self.edges.append(line)
        log.info("Parsed %s lines.", len(self.nodes) + len(self.edges))
        self.lines = self.nodes + self.edges

    def render(self):
        self.parse()
        ret = "graph\n"
        ret += "\n".join(sorted(self.nodes) + sorted(self.edges))
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
                    # Deployment* and Service* should be processed
                    #   under Application.
                    if "_Deployment_" in child:
                        continue
                    if "_DeploymentConfig_" in child:
                        continue
                    if "_Service_" in child:
                        continue
                if parent_type == NS_K8S.Application:
                    # Application should be processed last.
                    # Deployment* and Service* should be processed
                    #   under Application.
                    if "_Container_" in child:
                        continue
                    if "_Volume_" in child:
                        continue
                # if parent_type == NS_K8S.DeploymentConfig:
                #     continue
                log.warning("Rendering %s", child)
                children_to_render.add(f"  {child}")
                rendered.add(child)
            if not children_to_render:
                return
            yield f"subgraph {parent}{label}"
            children_to_render = sorted(children_to_render)
            # if parent_type in (NS_K8S.Registry,):
            #     children_to_render = render_in_chunks(children_to_render, 6)
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
