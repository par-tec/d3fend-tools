import logging
import os
from pathlib import Path
from time import time

import pytest
import yaml
from rdflib import Graph
from rdflib.namespace import RDF

from as_mermaid import RDF2Mermaid
from kuberdf import NS_K8S, parse_manifest_as_graph

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

TESTCASES = yaml.safe_load(
    (Path(__file__).parent / "data" / "as_mermaid" / "testcases-rdf.yaml").read_text()
)["testcases"]

TESTCASES_RENDER = yaml.safe_load(
    (
        Path(__file__).parent / "data" / "as_mermaid" / "testcases-render.yaml"
    ).read_text()
)["testcases"]

ICON_MAP = {
    "urn:k8s:Service": "fa:fa-network-wired",
    "urn:k8s:Port": "fa:fa-ethernet",
    "urn:k8s:Deployment": "fa:fa-cubes",
    "urn:k8s:Pod": "fa:fa-cube",
    "urn:k8s:Container": "fa:fa-cube",
    "urn:k8s:DeploymentConfig": "⟳",
    "urn:k8s:Namespace": "⬚",
    "urn:k8s:Image": "fa:fa-docker",
    "urn:k8s:Application": "fa:fa-cubes",
}


def test_file():

    TEST_KUBERDF_FILE = os.environ.get("TEST_KUBERDF_FILE")
    if not TEST_KUBERDF_FILE:
        pytest.skip("TEST_KUBERDF_FILE not set")
    kube_yaml = Path(TEST_KUBERDF_FILE)
    assert kube_yaml.is_file()
    t0 = time()
    log.info(f"Testing {kube_yaml}")
    g = parse_manifest_as_graph(
        manifest_text=kube_yaml.read_text(), manifest_format=kube_yaml.suffix[1:]
    )
    log.info(f"Loaded {kube_yaml} in {time()-t0}s")
    assert len(g) > 1000

    x = Graph()
    # Add all g triples to x
    for s, p, o in g:
        if (p, o) == (RDF.type, NS_K8S.Namespace):
            x.add((s, p, o))
        if "ws" in f"{s}{o}":
            x.add((s, p, o))
    assert len(x) < len(g)
    # convert x to mermaid
    mermaid = RDF2Mermaid(x)
    mermaid_text = mermaid.render()
    mermaid_text.splitlines()

    raise NotImplementedError


@pytest.mark.parametrize(
    "test_name,test_data", TESTCASES["test_rdf_to_mermaid"].items()
)
def test_rdf_to_mermaid(test_name, test_data):
    mermaid = test_data["turtle"]
    expected = test_data["expected"]
    g = Graph()
    g.parse(data=mermaid, format="turtle")
    mermaid = RDF2Mermaid(g)
    mermaid_text = mermaid.render().splitlines()
    missing_lines = set(expected) - set(mermaid_text)
    assert not missing_lines


@pytest.mark.parametrize(
    "test_name,test_data", TESTCASES["test_rdf_to_mermaid_contains"].items()
)
def test_rdf_to_mermaid_contains(test_name, test_data):
    mermaid = test_data["turtle"]
    contains = test_data["contains"]
    g = Graph()
    g.parse(data=mermaid, format="turtle")
    mermaid = RDF2Mermaid(g)
    mermaid_text = mermaid.render().splitlines()
    assert set(mermaid_text) >= set(contains)


def _wrap_md(mermaid_text, title=""):
    return f"# {title}\n\n\n```mermaid\n{mermaid_text}\n```\n"


@pytest.mark.parametrize("graph_ttl", Path(".").glob("**/*.ttl"))
def test_ttl_to_mermaid(graph_ttl):
    test_name = graph_ttl.stem
    g = Graph()
    g.parse(data=graph_ttl.read_text(), format="turtle")
    mermaid = RDF2Mermaid(g)
    mermaid_text = mermaid.render()
    dpath = (
        Path(__file__).parent / "data" / "as_mermaid" / f"deleteme-out-{test_name}.md"
    )
    dpath.write_text(_wrap_md(mermaid_text, title=test_name))


import kuberdf


def test_external_file():
    TEST_KUBERDF_FILE = os.environ.get("TEST_KUBERDF_FILE")
    if not TEST_KUBERDF_FILE:
        pytest.skip("TEST_KUBERDF_FILE not set")
    infile = Path(TEST_KUBERDF_FILE)
    test_name = infile.stem
    dpath = (
        Path(__file__).parent / "data" / "as_mermaid" / f"deleteme-out-{infile.stem}.md"
    )
    kuberdf.parse_resources((infile,), dpath)
    graph_ttl = dpath.with_suffix(".ttl")
    g = Graph()
    g.parse(data=graph_ttl.read_text(), format="turtle")
    mermaid = RDF2Mermaid(g)
    mermaid_text = mermaid.render()
    dpath.write_text(_wrap_md(mermaid_text, title=test_name))
