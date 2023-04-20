import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import List

import yaml
from rdflib import RDFS, Graph, Namespace

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

MERMAID_KEYWORDS = (
    #   "subgraph",
    r"%%",
    "end",
    "direction",
    "classDef",
    "class",
    "linkStyle",
)
PAT_LABEL = r"(.*?)"
PAT_OPEN = r"|".join((r"\[\[", r"\[\(", r"\(\(", r"\{\{", r"\[\/"))
PAT_CLOSE = r"|".join((r"\]\]", r"\)\]", r"\)\)", r"\}\}", r"\/\]"))
PAT_NODE = (
    r"^([a-zA-Z0-9_:/.µ]+(?:[-=][a-zA-Z0-9_:/.µ]+)*)"
    r"("
    r"([\(\[\{\/]{1,2})" + PAT_LABEL + r"([\)\]\}\/]{1,2})"
    r")?$"
)
PAT_ARROW = r"\s*(-->|--o|-[.-]+-[>ox]?)" + r"\s*" + r"(?:\|(.*)?\|)?\s*"
PAT_LINE = rf"{PAT_NODE}({PAT_ARROW}{PAT_NODE})*"
RE_ARROW = re.compile(PAT_ARROW)
RE_LINE = re.compile(PAT_LINE)
RE_NODE = re.compile(PAT_NODE)

NS_DEFAULT = Namespace("https://par-tec.it/example#")
NS_D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

# Data from mermaidrdf.yaml
DATAFILE = Path(__file__).parent / "mermaidrdf.yaml"
DATA = yaml.safe_load(DATAFILE.read_text())
D3F_PROPERTIES = set(DATA["D3F_PROPERTIES"])
D3F_DIGITAL_ARTIFACTS = set(DATA["D3F_DIGITAL_ARTIFACTS"])
D3F_DEFENSIVE_TECHNIQUES = set(DATA["D3F_DEFENSIVE_TECHNIQUES"])
D3F_OFFENSIVE_TECHNIQUES = set(DATA["D3F_OFFENSIVE_TECHNIQUES"])
SW_MAP = {tuple(x["labels"]): x["artifacts"] for x in DATA["SW_MAP"]}
FONTAWESOME_MAP = {tuple(x["labels"]): x["artifacts"] for x in DATA["FONTAWESOME_MAP"]}
D3F_INFERRED_RELATIONS = defaultdict(
    list, **{x["relation"]: x["predicates"] for x in DATA["INFERRED_RELATIONS"]}
)


class D3fendMermaid:
    """A class to generate a d3fend graph from a mermaid/markdown text."""

    def __init__(self, text, ontology=None) -> None:
        self.text = text
        self.ontology = ontology or Graph()
        self.annotations = None
        self.hypergraph = None
        self.g = Graph()
        self.g.bind("", NS_DEFAULT)
        self.g.bind("d3f", NS_D3F)
        self.g.bind("rdfs", RDFS)
        self._turtle = None
        self._out = None

    @staticmethod
    def _extract(text):
        if text.strip().startswith("graph"):
            return [text]
        return extract_mermaid(text)

    def parse(self):
        turtle = """
        @prefix : <https://par-tec.it/example#> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
        @prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
        """
        for mermaid_text in self._extract(self.text):
            triples = mermaid_to_triples(mermaid_text)
            turtle += "\n".join(triples)
        self.g.parse(data=turtle, format="turtle")
        return None

    def serialize(self, format="turtle"):
        if self._turtle is None:
            self._turtle = self.g.serialize(format=format)
        return self._turtle

    def annotate(self):
        if self.hypergraph is None:
            g = Graph()
            g = self.g | self.ontology
            annotations = g.query(
                """
                PREFIX : <https://par-tec.it/example#>

                CONSTRUCT {
                ?s a ?parent
                } WHERE {
                    ?s a :Node, ?typ .
                    ?typ rdfs:subClassOf* d3f:DigitalArtifact .
                    ?typ rdfs:subClassOf ?parent
                }
            """,
                initNs={
                    "d3f": NS_D3F,
                },
            )
            self.annotations = annotations.graph
            g = self.g | annotations.graph
            log.info("Annotated graph has %s triples", len(g) - len(self.g))
            self.hypergraph = g | self.ontology
        return self.hypergraph

    def mermaid(self):
        """Replace every mermaid node with a more readable one."""
        if self._out is None:
            out = ""
            text = self._extract(self.text)[0]
            for line in text.splitlines():
                out += "\n"
                line = line.strip()
                if not line:
                    continue

                if line.startswith(MERMAID_KEYWORDS):
                    out += line
                    continue

                if line.startswith("graph"):
                    out += line
                    continue

                # Strip %% comments after line.
                line = line.split(r"%%")[0].strip()

                parsed_line = parse_line2(line)
                for node, arrow, relation in parsed_line:
                    if node.startswith("subgraph "):
                        node = node[9:]
                        out += "subgraph "

                    parsed_node = RE_NODE.match(node)
                    if not parsed_node:
                        raise NotImplementedError(f"Cannot parse node {node}")
                        out += line
                        continue

                    id_, _, sep_l, label, sep_r = parsed_node.groups()

                    label = (
                        visualize_d3fend(label).strip("'").strip('"') if label else ""
                    )
                    label = f'"{label}"' if label else ""
                    arrow = arrow or ""
                    sep_l = sep_l or ""
                    sep_r = sep_r or ""
                    relation = (
                        visualize_d3fend(relation).strip("'").strip('"')
                        if relation
                        else ""
                    )
                    relation = f'|"{relation}"|' if relation else ""

                    out += f"""{id_}{sep_l}{label}{sep_r} {arrow} {relation} """
                out = out.strip(" ")
            self._out = out.strip()
        return self._out


def visualize_d3fend(mermaid_text):
    """Replace every occurrence of a d3f: entity with a fontawesome icon
    from FONTAWESOME_MAP."""
    lines = []
    for line in mermaid_text.splitlines():
        for needle in set(re.findall("(d3f:[a-zA-Z-0-9]+)", line)):
            for label, icons in FONTAWESOME_MAP.items():
                if needle in D3F_DIGITAL_ARTIFACTS:
                    url = f"https://next.d3fend.mitre.org/dao/artifact/{needle}/"
                elif needle in D3F_DEFENSIVE_TECHNIQUES:
                    url = f"https://next.d3fend.mitre.org/dao/technique/{needle}/"
                else:
                    url = ""

                tooltip_label = f"""<a title='{needle}' href='{url}' target='_blank'  rel='noopener noreferrer'>{label[0]}</a>"""
                if needle in icons:
                    line = line.replace(needle, tooltip_label)
        lines.append(line)
    return "\n".join(lines)


def parse_resources(resources: List[Path], outfile=None, **options):
    """This is the core function that parses a list of files and returns
    a turtle string. If outfile is specified, the turtle string is also."""
    turtle = ""
    for f in resources:
        mermaid_graphs = extract_mermaid(f.read_text())
        for graph in mermaid_graphs:
            turtle += "\n" + parse_mermaid(graph, **options)
    if outfile:
        Path(outfile).with_suffix(".ttl").write_text(turtle)
    return turtle


def mermaid_to_triples(mermaid):
    """Parse a mermaid text and return a yields RDF triples."""
    mermaid = mermaid.strip()
    # Ensure that the mermaid text starts with "graph "
    if not mermaid.startswith(("graph ", "graph")):
        raise ValueError("The mermaid text must start with 'graph'")
    # Split the mermaid text into lines, skipping the first line.
    lines = mermaid.splitlines()[1:]

    for line in lines:
        for sentence in parse_line(line):
            yield sentence


def parse_mermaid(text: str):
    mermaid = D3fendMermaid(text)
    mermaid.parse()
    return mermaid.serialize()


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
    # Split the line into the two nodes and the arrow
    # according to the mermaid syntax. The resulting line will be
    # something like 5-1-5
    try:
        parsed_line = parse_line2(line)
        log.info(f"Parsed line: {line} to: {parsed_line}")
    except Exception:
        log.warning(f"Unsupported line: {line}")
        return

    node_id0, arrow0, relation0 = None, None, None
    for node, arrow, relation in parsed_line:
        parsed_node = RE_NODE.match(node)
        if not parsed_node:
            continue

        id_, _, sep, label, _ = parsed_node.groups()
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
    """Parse a relation between two nodes.
    @param src: the source node
    @param dst: the destination node
    @param predicate: the predicate inferred by the arrow shape
    @param relation: the relation enclosed by pipes,
                     e.g. a -->|| b.
    """
    relation = relation.strip() if relation else None
    if not relation:
        yield f":{src} {predicate} :{dst} ."
        return
    if relation in D3F_PROPERTIES or "d3f:" + relation in D3F_PROPERTIES:
        yield f":{src} {relation} :{dst} ."

        for predicate in D3F_INFERRED_RELATIONS[relation]:
            yield predicate.format(subject=src, object=dst)
        log.warning(f"Stop processing relation: {relation}")
        return

    # Explicit the relationship.
    yield f":{src} {predicate} :{dst} ."

    # Introduces a relation based on a specific d3f:DigitalArtifact,
    # e.g. :App --> |via d3f:DatabaseQuery| :Database
    for needle in re.findall(r"(d3f:[A-Za-z0-9._\.-]+)", relation):
        # TODO verify that the relation is a valid d3f:DigitalArtifact.
        if needle in D3F_DIGITAL_ARTIFACTS:
            yield f":{src} d3f:produces {needle} ."
            yield f":{dst} d3f:uses {needle} ."
            continue
        if needle in D3F_DEFENSIVE_TECHNIQUES:
            yield f":{src} d3f:implements {needle} ."
            yield f":{dst} d3f:implements {needle} ."
            continue

        if needle == relation:
            raise NotImplementedError(
                f"Unsupported relation: {relation} is not a D3FEND relation."
            )

        raise NotImplementedError(
            f"Unsupported relation: the relation {needle} cannot be used in {relation}"
        )

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
    subgraphs = re.findall(r"(\n\s*subgraph.*?\n\s*end\b)", text, re.DOTALL)
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

        if line.startswith(
            (
                "subgraph ",
                "graph",
                "classDef ",
                "class ",
                "click ",
            )
        ):
            ret.append(line)
            continue

        s_p_o = RE_LINE.match(
            line
        )  # FIXME: RE_LINE is broken and should be removed because it's too complex.
        s_p_o = s_p_o.groups() if s_p_o else [None] * 9
        s, o = s_p_o[0], s_p_o[8]
        items = {s, o}
        log.debug(f"Extracting resources from line: (s={s}, o={o}")

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
