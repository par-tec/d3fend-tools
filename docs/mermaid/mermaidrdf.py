import logging
import re
from collections import defaultdict
from pathlib import Path

import yaml
from rdflib import Graph, Namespace
from rdflib.namespace import RDF, RDFS

from kuberdf import NS_K8S

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

MERMAID_KEYWORDS = (
    "subgraph",
    "end",
    "classDef",
    "class",
)
PAT_LABEL = r"(.*?)"
PAT_OPEN = r"|".join((r"\[\[", r"\[\(", r"\(\(", r"\{\{", r"\[\/"))
PAT_CLOSE = r"|".join((r"\]\]", r"\)\]", r"\)\)", r"\}\}", r"\/\]"))
PAT_NODE = (
    r"([a-zA-Z0-9_:/.]+(?:[-=][a-zA-Z0-9_:/.]+)*)"
    r"(([\(\[\{\/]{1,2})" + PAT_LABEL + r"([\)\]\}\/]{1,2}))?"
)
PAT_ARROW = r"\s*(-->|--o|-[.-]+-[>ox]?)" + r"\s*" + r"(?:\|(.*)?\|)?\s*"
PAT_LINE = rf"{PAT_NODE}({PAT_ARROW}{PAT_NODE})*"
RE_ARROW = re.compile(PAT_ARROW)
RE_LINE = re.compile(PAT_LINE)
RE_NODE = re.compile(PAT_NODE)

NS_DEFAULT = Namespace("https://par-tec.it/example#")
NS_D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
DATAFILE = Path(__file__).parent / "mermaidrdf.yaml"
DATA = yaml.safe_load(DATAFILE.read_text())
SW_MAP = {tuple(x["labels"]): x["artifacts"] for x in DATA["SW_MAP"]}
FONTAWESOME_MAP = {tuple(x["labels"]): x["artifacts"] for x in DATA["FONTAWESOME_MAP"]}
D3F_PROPERTIES = set(DATA["D3F_PROPERTIES"])
D3F_INFERRED_RELATIONS = defaultdict(
    list, **{x["relation"]: x["predicates"] for x in DATA["INFERRED_RELATIONS"]}
)


def mermaid_to_rdf(mermaid):
    mermaid = mermaid.strip()
    # Ensure that the mermaid text starts with "graph "
    if not mermaid.startswith(("graph ", "graph")):
        raise ValueError("The mermaid text must start with 'graph'")
    # Split the mermaid text into lines, skipping the first line.
    lines = mermaid.splitlines()[1:]

    for line in lines:
        for sentence in parse_line(line):
            yield sentence


def parse_mermaid(mermaid: str):
    g = Graph()
    g.bind("", NS_DEFAULT)
    g.bind("d3f", NS_D3F)
    g.bind("rdfs", "http://www.w3.org/2000/01/rdf-schema#")
    turtle = """@prefix : <https://par-tec.it/example#> .
    @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
    @prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
    """ + "\n".join(
        mermaid_to_rdf(mermaid)
    )
    g.parse(data=turtle, format="turtle")
    return g.serialize(format="turtle")


def render_node(id_, label, sep):
    type_ = ":Node"
    rdf = [f":{id_} a {type_} ."]

    if sep == "[(":
        type_ = "d3f:DatabaseServer"
    elif sep == "[[":  # FIXME: is this ok?
        type_ = "d3f:Server"
    rdf.append(f":{id_} a {type_} .")
    if label:
        rdf += [f':{id_} rdfs:label """{label}""" .']

    label = label or id_
    for softwares, d3f_classes in SW_MAP.items():
        if any((x in label.lower() for x in softwares)):
            log.info("Found property %s in label %s", softwares, label)
            rdf += [f":{id_} a {','.join(d3f_classes)} ."]
    for needles, d3f_classes in FONTAWESOME_MAP.items():
        if any((x in label.lower() for x in needles)):
            log.info("Found relation %s in label %s", needles, label)
            rdf += [f":{id_} d3f:related {','.join(d3f_classes)} ."]
    for needle in re.findall("(d3f:[a-zA-Z-0-9]+)", label):
        log.info("Found class %s in label %s", needle, label)
        rdf += [f":{id_} a {needle} ."]
    return id_, rdf


def parse_line2(line):
    """Parse a mermaid line in the possible forms:
    1. x[label]
    2. x[label]-->y
    3. x[label]-->|comment| y
    4. x --> y --> z
    """
    ret = RE_ARROW.split(line)
    # Pad the list with None to make sure we have a multiple of 3 length.
    ret = ret + [None] * (3 - len(ret) % 3)
    return [tuple(ret[i : i + 3]) for i in range(0, len(ret), 3)]


def parse_line(line):
    """Parse a mermaid line consisting of two nodes and an arrow.
    If the line is not valid, skip it."""
    # Skip empty lines
    line = line.strip()
    if not line or len(line) < 5 or line.startswith("%%"):
        return

    if line.startswith(MERMAID_KEYWORDS):
        log.warning(f"Unsupported KEYWORD: {line}")
        return
    # if the line doesn't match x-->y, skip it
    if not RE_LINE.match(line):
        log.warning(f"Unsupported RE_LINE: {line}")
        return
    # Split the line into the two nodes and the arrow
    # according to the mermaid syntax. The resulting line will be
    # something like 5-1-5
    parsed_line = parse_line2(line)
    log.info(f"Parsed line: {line} to: {parsed_line}")

    node_id0, arrow0, relation0 = None, None, None
    for node, arrow, relation in parsed_line:
        id_, _, sep, label, _ = RE_NODE.match(node).groups()
        # Remove the trailing and leading quotes from the nodes
        node_id, node1_rdf = render_node(id_=id_, label=label, sep=sep)
        yield from node1_rdf
        if node_id0:
            # TODO handle the relation.

            if not (node and arrow0):
                raise NotImplementedError
            # Create the RDF
            if arrow0.endswith("->"):
                predicate = "d3f:accesses"
            elif arrow0.endswith("-o"):
                predicate = "d3f:reads"
            elif arrow0.endswith("-"):
                predicate = ":connected"
            else:
                raise NotImplementedError(f"Unsupporte predicate: {arrow}")

            yield from _parse_relation(node_id0, node_id, predicate, relation0)

        node_id0, arrow0, relation0 = node_id, arrow, relation


def _parse_relation(src, dst, predicate, relation):
    """Parse a relation between two nodes."""
    if not relation:
        yield f":{src} {predicate} :{dst} ."
        return
    if relation.startswith("d3f:") and relation[4:] in D3F_PROPERTIES:
        yield f":{src} {relation} :{dst} ."

        for predicate in D3F_INFERRED_RELATIONS[relation]:
            yield predicate.format(subject=src, object=dst)
        return

    # Explicit the relationship.
    yield f":{src} {predicate} :{dst} ."

    # Introduces a relation based on a specific d3f:DigitalArtifact,
    # e.g. :App --> |via d3f:DatabaseQuery| :Database
    for needle in re.findall(r"(d3f:[A-Za-z0-9._\.-]+)", relation):
        # TODO verify that the relation is a valid d3f:DigitalArtifact.
        yield f":{src} d3f:produces {needle} ."
        yield f":{dst} d3f:uses {needle} ."
        return

    # Introduces a relation based on a specific d3f:DigitalArtifact,
    # e.g. :Client --> |via fa:fa-envelope| :MTA
    for rel in re.findall(r"(?:fab?:(fa-[a-z0-9-]+))", relation):
        for needles, d3f_classes in FONTAWESOME_MAP.items():
            if rel not in needles:
                continue
            for d3f_class in d3f_classes:
                yield f":{src} d3f:produces {d3f_class} ."
                yield f":{dst} d3f:uses {d3f_class} ."
        return


def extract_mermaid(text: str):
    re_mermaid = re.compile("```mermaid\n.*?\n```", re.DOTALL | re.MULTILINE)
    return [graph[10:-3].strip() for graph in re_mermaid.findall(text)]


def flip_mermaid(text):
    if "graph LR" in text:
        text = text.replace("graph LR", "graph TB")
        text = re.sub(r"subgraph\s+(.*?)\n", r"subgraph \1\n\ndirection LR\n\n", text)
    else:
        text = text.replace("graph TB", "graph LR")
        text = re.sub(r"subgraph\s+(.*?)\n", r"subgraph \1\n\ndirection TB\n\n", text)
    return text


def filter_mermaid(text, mermaid_filter, skip_filter=None):
    # Assumes that subgraphs are not nested
    # and that they are at the end of the text.
    log.warning(f"Filtering mermaid text with {mermaid_filter}")
    re_mermaid_filter = re.compile(f"""^.*({mermaid_filter}).*""", re.I)
    ret = []
    subgraphs = re.findall(r"(\nsubgraph.*?\nend)", text, re.DOTALL)
    matching_subgraphs = []
    for subgraph in subgraphs:
        if re.match(".*" + mermaid_filter + ".*", subgraph, re.DOTALL):
            subgraph_name = re.search(r"subgraph\s+([^[]+)\s*", subgraph).group(1)
            matching_subgraphs.append(subgraph_name)
    nodes = set()
    for line in text.splitlines():
        if skip_filter and re.match(".*" + skip_filter + ".*", line):
            log.debug("Skipping line: " + line)
            continue

        s_p_o = RE_LINE.match(line)
        s_p_o = s_p_o.groups() if s_p_o else [None] * 9
        s, o = s_p_o[0], s_p_o[8]
        items = {s, o}
        log.debug(f"Extracting resources from line: (s={s}, o={o}")

        if s in ("subgraph", "graph", "classDef", "class", "click"):
            ret.append(line)
            continue

        # Don't render empty subgraphs.
        if s == "end":
            if ret[-1].startswith("subgraph "):
                ret.pop()
            else:
                ret.append(line)
            continue

        is_required = re_mermaid_filter.match(line)
        is_inferred = items & nodes
        if is_required or is_inferred:
            log.debug(
                f"Found matching line: {line} (is_required={is_required}, is_inferred={is_inferred})"
            )
            ret.append(line)
            if s:
                nodes.add(s)
            if o:
                nodes.add(o)
            continue
        # If a subgraph contains the filter, include any line that contains the subgraph name.
        if any((x for x in matching_subgraphs if "_" in x and x in line)):
            log.debug("Found matching subgraph: " + line)
            ret.append(line)
            continue

        log.debug(f"Filtering out {line}")

    text_mmd = "\n".join(ret)
    log.info(f"Filtered mermaid text:\n{text_mmd}")
    return text_mmd


class MermaidRDF:
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
            icon = MermaidRDF.ICON_MAP.get(str(type_), "") or type_
            src = MermaidRDF.sanitize_uri(s)

            label = self.g.value(s, RDFS.label) or ""
            label_l = f"{icon} {Path(s).name} {label}"
            label_l = MermaidRDF.sanitize_label(label_l)
            label_l = f'"{label_l}"'
            # Create a tree of subgraph based on the
            # hasChild predicate.
            for child in self.g.objects(s, NS_K8S.hasChild) or []:
                child = MermaidRDF.sanitize_uri(child)
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
            if type_ in MermaidRDF.DONT_RENDER_AS_NODES:
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
                    dst = MermaidRDF.sanitize_uri(dst)
                    self.lines.append(f"""{src} --> |{str(link)[8:]}| {dst}""")
        log.info("Parsed %s lines.", len(self.lines))

    def render(self):
        self.parse()
        ret = "graph\n"
        ret += "\n".join(self.lines)
        ret += "\n"
        ret += "%%\n%% Subgraphs\n%%\n"
        ret += "\n".join(MermaidRDF.create_tree(self.subgraphs))
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
