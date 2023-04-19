import logging
import tempfile
from pathlib import Path

import pytest
import yaml
from rdflib import Graph

from d3fendtools.d3fend import attack_summary
from d3fendtools.mermaidrdf import (
    D3fendMermaid,
    extract_mermaid,
    mermaid_to_triples,
    parse_line2,
    parse_mermaid,
    parse_resources,
    visualize_d3fend,
)

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

TESTCASES = yaml.safe_load(
    (
        Path(__file__).parent / "data" / "mermaidrdf" / "testcases-mermaid.yaml"
    ).read_text()
)["testcases"]


@pytest.fixture
def d3fend_graph():
    g = Graph()
    g.parse(
        Path(__file__).parent.parent / "d3fendtools" / "d3fend-short.ttl",
        format="turtle",
    )
    return g


def test_render_mermaid():
    txt = """
    graph

    Client --> MySQL
    MySQL[(UserPreferences d3f:Process)] -->|d3f:Email| DataVolume[(Tablespace fa:fa-hard-drive d3f:Volume)]

    subgraph a
    end
    subgraph b[foo d3f:Server]
    end
    foo(("fa:fa-network-wired console-demo-plugin \\napp.kubernetes.io/component:"))
    bar({fa:fa-car})
    """
    m = D3fendMermaid(txt)
    m.parse()
    ret = m.mermaid()
    assert "Client" in m.g.serialize()
    assert "Client" in ret
    raise NotImplementedError


def test_visualize_d3fend():
    txt = """MySQL[(UserPreferences d3f:Process)] -->|d3f:Email| DataVolume[(Tablespace fa:fa-hard-drive d3f:Volume)]"""
    ret = visualize_d3fend(txt)
    assert "title='d3f:Email'" in ret


@pytest.mark.parametrize(
    "file_mmd", (Path(__file__).parent / "data" / "mermaidrdf").glob("*.md")
)
def test_can_generate_valid_rdf_from_mermaid(file_mmd):
    turtle = parse_resources([file_mmd], outfile=file_mmd.with_suffix(".deleteme.ttl"))
    g = Graph()
    g.parse(data=turtle, format="turtle")


"""
(Pdb) pp len(list(g.query("SELECT DISTINCT ?label ?attacks ?s ?artifact WHERE { ?s a :Node, ?q . ?q rdfs:subClassOf* ?artifact . ?attack ?attacks ?artifact ; d3f:attack-id ?aid; rdfs:label ?label } LIMIT 50")))
"""


def test_generate_reports(d3fend_graph):
    g = Graph()
    g.parse(
        data="""
@prefix : <https://par-tec.it/example#> .
@prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

:a a d3f:WebServerApplication,
        :Node ;
    rdfs:label "d3f:WebServerApplication" ;
    d3f:accesses :SMTP ;
    d3f:produces d3f:Email .

:SMTP a d3f:MailServer,
        :Node ;
    rdfs:label "d3f:MailServer" ;
    d3f:uses d3f:Email .

    """,
        format="turtle",
    )
    m = D3fendMermaid("a --> b", d3fend_graph)
    m.g = g

    raise NotImplementedError


@pytest.mark.parametrize(
    "file_mmd", (Path(__file__).parent / "data" / "mermaidrdf").glob("*.md")
)
def test_attack_summary_is_consistent(file_mmd, d3fend_graph):
    mermaid_text = extract_mermaid(file_mmd.read_text())
    # Given a mermaid graph...
    mermaid = D3fendMermaid(mermaid_text[0], d3fend_graph)
    mermaid.parse()

    # When we generate annotations.
    annotated_graph = mermaid.annotate()
    annotations = annotated_graph - mermaid.g

    # Annotations should be less than 100.
    assert len(annotations) < 100

    # When we generate a summary of the annotated graph.
    simple = set(tuple(x) for x in attack_summary(mermaid.g))
    annotated = set(tuple(x) for x in attack_summary(annotated_graph))

    # Then the summary of the annotated graph
    #    should be a superset of the one of the simple graph.
    added_stuff = annotated - simple
    assert added_stuff
    q1 = """
    SELECT DISTINCT ?label ?attacks ?s ?artifact WHERE {
        ?s a :Node .
        ?s ?r ?q .
        ?q rdfs:subClassOf ?artifact .
        ?attack ?attacks ?artifact ;
            d3f:attack-id ?aid;
            rdfs:label ?label
    } LIMIT 50
    """
    raise NotImplementedError


@pytest.mark.parametrize(
    "test_name,test_data", TESTCASES["test_mermaid_to_rdf"].items()
)
def test_mermaid_to_triples(test_name, test_data):
    mermaid = test_data["mermaid"]
    expected = set(test_data["expected"])
    rdf = set(mermaid_to_triples(mermaid))
    assert rdf == expected


@pytest.mark.parametrize("line, expected", TESTCASES["test_lines_are_split_correctly"])
def test_lines_are_split_correctly(line, expected):
    ret = parse_line2(line)
    assert ret == [tuple(x) for x in expected]


@pytest.mark.parametrize(
    "node,expected",
    [
        ("A", ("A", None, None, None, None)),
        ("A[label]", ("A", "[label]", "[", "label", "]")),
    ],
)
def test_parse_node(node, expected):
    from d3fendtools.mermaidrdf import RE_NODE

    m = RE_NODE.match(node)
    g = m.groups()
    assert g == expected


@pytest.mark.parametrize(
    "line, expected",
    [
        (
            "A",
            (
                "A",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        ),
        (
            "a[label]",
            (
                "a",
                "[label]",
                "[",
                "label",
                "]",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        ),
        ("nginx-->mysql", (None,)),
    ],
)
def test_parse_line_removeme(line, expected):
    from d3fendtools.mermaidrdf import parse_line

    ret = parse_line(line)
    assert next(ret) == expected
    raise NotImplementedError


# def test_render_node_docker():
#     """Test node parsing."""
#     id_, rdf = render_node(
#         "app", "fab:fa-docker fab:fa-angular Containerized Application", "(("
#     )
#     raise NotImplementedError


def test_extract_bash_blocks_from_markdown():
    """Extract bash blocks form a markdown text"""
    text = Path("README.md").read_text()
    ret = extract_mermaid(text)
    for block in ret:
        assert block.startswith("graph")


def test_m2d3f():
    text = Path("README.md").read_text()

    graphs = extract_mermaid(text)
    for graph in graphs:
        ret = mermaid_to_triples(graph)
        ret = set(ret)


def test_g1():
    text = Path("README.md").read_text()
    graphs = extract_mermaid(text)
    for graph in graphs:
        turtle = parse_mermaid(graph)
        # Create a temporary file.
        tmp_ttl = tempfile.NamedTemporaryFile(suffix=".ttl", delete=False).name
        Path(tmp_ttl).write_text(turtle)
        g = Graph()
        g.parse(tmp_ttl, format="turtle")


def test_all_referenced_icons_are_visible():
    """Create a mermaid text containing the icosn in FONTAWESOME_MAP."""
    from d3fendtools.mermaidrdf import FONTAWESOME_MAP

    out = ""
    for labels, artifacts in FONTAWESOME_MAP.items():
        artifact = artifacts[0].replace(":", "_")
        labels = labels[0]
        out += f"""{artifact}("{labels}")\n"""
    out = f"```mermaid\n\ngraph LR\n{out}\n\n```\n"
    Path("/tmp/icons.md").write_text(out)
