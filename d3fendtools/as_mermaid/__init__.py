import logging
import uuid
import textwrap

from pathlib import Path
from rdflib import Graph
from rdflib.namespace import RDF, RDFS

from d3fendtools.kuberdf import D3F, K8S

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


RENDER_MAP = {
    K8S.Container: {
        "shape": "process",
    },
    K8S.Selector: {
        "shape": "odd",
    },
    K8S.Service: {
        "shape": "circle",
    },
    K8S.ServiceAccount: {
        "shape": "circle",
    },
    K8S.User: {
        "shape": "circle",
    },
    K8S.Image: {
        "shape": "lin-cyl",
    },
    K8S.ImageStream: {
        "shape": "lin-cyl",
    },
    K8S.ImageStreamTag: {
        "shape": "lin-cyl",
    },
    K8S.PersistentVolumeClaim: {
        "shape": "lin-cyl",
    },
    K8S.Volume: {
        "shape": "lin-cyl",
    },
    K8S.Route: {
        "shape": "delay",
    },
    K8S.Deployment: {
        "shape": "processes",
    },
    K8S.DeploymentConfig: {
        "shape": "processes",
    },
    K8S.ConfigMap: {
        "shape": "doc",
    },
    K8S.Secret: {
        "shape": "doc",
    },
    K8S.Endpoints: {
        "shape": "curv-trap",
    },
    K8S.Host: {
        "shape": "trap-b",
    },
    K8S.HorizontalPodAutoscaler: {
        "shape": "subproc",
    },
    K8S.RoleBinding: {
        "shape": "doc",
    },
    K8S.DeveloperAccount: {
        "shape": "circle",
    },
    K8S.DeveloperUser: {
        "shape": "circle",
    },
    K8S.ExternalSecret: {
        "shape": "process",
    },
}


class RDF2Mermaid:
    """Convert an RDF graph to a mermaid graph."""

    ICON_MAP = {
        "urn:k8s:Application": "fa:fa-cubes",
        "urn:k8s:ConfigMap": "\N{EMPTY DOCUMENT}",
        "urn:k8s:Container": "fa:fa-cube",
        "urn:k8s:CronJob": "fa:fa-clock",
        "urn:k8s:HorizontalPodAutoscaler": "fa:fa-clock",
        "urn:k8s:Deployment": "\N{CLOCKWISE GAPPED CIRCLE ARROW}",
        "urn:k8s:DeploymentConfig": "\N{CLOCKWISE GAPPED CIRCLE ARROW}",
        "urn:k8s:StatefulSet": "\N{CLOCKWISE GAPPED CIRCLE ARROW}",
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
        "urn:k8s:ServiceAccount": "fa:fa-user-shield",
        "urn:k8s:Registry": "fab:fa-docker fa:fa-boxes-stacked",
        "urn:k8s:Route": "fa:fa-route",
        "urn:k8s:RoleBinding": "fa:fa-id-badge",
    }
    # NB: A node connected with another is always rendered.
    DONT_RENDER = (
        # These are not nodes.
        K8S.Pod,
        K8S.Job,
        K8S.BuildConfig,
        #        NS_K8S.Selector,
        # NS_K8S.Host,
        # # For now, skip these. XXX
        # NS_K8S.Image,
        # NS_K8S.ImageStream,
        # NS_K8S.ImageStreamTag,
    )
    RENDER_AS_SUBGRAPHS = (
        K8S.Namespace,
        K8S.Registry,
        K8S.Application,
        # DC are groups.
        K8S.DeploymentConfig,
        K8S.Deployment,
        K8S.StatefulSet,
    )
    DONT_RENDER_AS_NODES = DONT_RENDER + RENDER_AS_SUBGRAPHS

    def __init__(self, g: Graph):
        self.g = g
        g.bind("k8s", K8S)
        g.bind("d3f", D3F)
        self.lines = []
        self.nodes = []
        self.edges = []
        self.subgraphs = {}

    @staticmethod
    def sanitize_uri(s):
        """Sanitize a URI to be used as a node name in mermaid."""
        ret = s.split("@", 1)[0].replace("/", "_").replace("@", "_").replace("=", "_")
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
        return ret.strip(r"\n").strip().replace("=", "_")

    def _format_link(self, link):
        import re

        def _replace_curie(match: str | re.Match):
            needle = match.group(0) if isinstance(match, re.Match) else match
            return self.g.namespace_manager.curie(needle)

        ret = re.sub(r"http[^ ]+", _replace_curie, link)
        return ret

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
            for child in self.g.objects(s, K8S.hasChild) or []:
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
                if False and type_ == K8S.Namespace and child.startswith("TCP:__"):
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
                shape = RENDER_MAP.get(type_, {}).get("shape", "")

                if shape:
                    shape = '@{shape: "' + shape + '"}'
                line = f"""{src}[{label_l}]{shape}""".replace("\n", "")
                if line not in self.nodes:
                    self.nodes.append(line)

            #
            # Adjust link direction to improve readability.
            #
            for link, arrow in (
                (K8S.exposes, "-.-o"),
                (D3F.executes, "x@{ animate: true}==>"),
                (D3F.runs, "==>"),
                (D3F.accesses, "-->"),
                (D3F.reads, "-.-o"),
                (D3F.creates, "-->"),
                (D3F.authorizes, "-.-o"),
            ):
                for dst in self.g.objects(s, link) or []:
                    dst = RDF2Mermaid.sanitize_uri(dst)
                    if link == K8S.exposes:
                        src, dst = dst, src
                        link = "exposed by"
                    elif link == D3F.reads:
                        line = f"""{dst} ~~~ {dst}"""
                        if line not in self.edges:
                            self.edges.append(line)

                    elif link in (D3F.executes, D3F.runs):
                        pass
                        # src, dst = dst, src
                        # link = "executed by"
                    elif "configmap" in dst.lower() or "secret" in dst.lower():
                        # src, dst = dst, src
                        arrow = "-.->"

                    if link.startswith("urn:k8s:"):
                        link = str(link)[8:]

                    # if hasattr(link, "fragment"):
                    #     link = link.fragment

                    line = f"""{src} {arrow} |{self._format_link(link)}| {dst}"""
                    if line not in self.edges:
                        self.edges.append(line)
        log.info("Parsed %s lines.", len(self.nodes) + len(self.edges))
        self.lines = self.nodes + self.edges

    def render(self):
        self.parse()

        ret = "graph LR\n"
        ret += textwrap.dedent(
            """
        %% Style
        classDef namespace fill:none, stroke-dasharray: 5 5, stroke-width: 5px;
        classDef workload fill:none, stroke: blue;
        classDef network fill:none, stroke: green;
        """
        )
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
                if parent_type == K8S.Namespace:
                    # Namespace should be processed last.
                    # Deployment* and Service* should be processed
                    #   under Application.
                    if "_Deployment_" in child:
                        continue
                    if "_DeploymentConfig_" in child:
                        continue
                    if "_Service_" in child:
                        continue
                if parent_type == K8S.Application:
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
            if parent_type == K8S.Namespace:
                yield f"class {parent} namespace;"
            elif parent_type in (
                K8S.Application,
                K8S.DeploymentConfig,
                K8S.Deployment,
                K8S.StatefulSet,
            ):
                yield f"class {parent} workload;"
            elif parent_type in (K8S.Service, K8S.Endpoints):
                yield f"class {parent} network;"

        tree_namespace = []
        for parent, data in tree.items():
            parent_type = data.get("type")
            if parent_type == K8S.Namespace:
                tree_namespace.append((parent, data))
                continue
            yield from _render_tree(parent, data)
        for parent, data in tree_namespace:
            yield from _render_tree(parent, data)
