import logging
from pathlib import Path

import pytest
import yaml
from rdflib import Graph, URIRef

from d3fendtools.kuberdf import DC, K8Resource, parse_manifest_as_graph, parse_resources

log = logging.getLogger(__name__)


TESTCASES = yaml.safe_load(
    (Path(__file__).parent / "data" / "kuberdf" / "testcases-kube.yaml").read_text()
)["testcases"]


@pytest.mark.parametrize("test_name,test_data", TESTCASES["test_network"].items())
def test_network(test_name, test_data):
    harn_parse_manifests(test_name, test_data)


@pytest.mark.parametrize("test_name,test_data", TESTCASES["test_service"].items())
def test_service(test_name, test_data):
    harn_parse_manifests(test_name, test_data)


@pytest.mark.parametrize("test_name,test_data", TESTCASES["test_dc"].items())
def test_dc(test_name, test_data):
    harn_parse_manifests(test_name, test_data)


@pytest.mark.parametrize("test_name,test_data", TESTCASES["test_list"].items())
def test_list(test_name, test_data):
    harn_parse_manifests(test_name, test_data)


@pytest.mark.parametrize("test_name,test_data", TESTCASES["test_skip"].items())
def test_skip(test_name, test_data):
    actual = harn_parse_manifests(test_name, test_data)
    assert actual == []


def harn_parse_manifests(test_name, test_data):
    manifest = test_data["manifest"]
    expected = set(tuple(x) for x in test_data["expected"])
    g = parse_manifest_as_graph(manifest)
    triples = g.triples((None, None, None))
    actual = [tuple(map(str, x)) for x in triples]
    missing_lines = expected - set(actual)
    assert not missing_lines, f"Missing lines: {missing_lines}"

    return actual


@pytest.mark.parametrize("manifest_yaml", Path(".").glob("**/kuberdf/*.yaml"))
def test_parse_resource(manifest_yaml):
    """Parse an openshift manifest file
    and convert it to an RDF resource
    """
    g = Graph()
    manifests = yaml.safe_load_all(manifest_yaml.read_text())
    for manifest in manifests:
        if "kind" not in manifest:
            return
        for triple in K8Resource.parse_resource(manifest):
            g.add(triple)

    assert g is not None


@pytest.mark.parametrize("manifest_yaml", Path(".").glob("**/kuberdf/*.yaml"))
def test_parse_resources(manifest_yaml):
    dpath = (
        Path(__file__).parent
        / "data"
        / "as_mermaid"
        / f"deleteme-out-{manifest_yaml.stem}"
    )
    parse_resources((manifest_yaml,), dpath.as_posix())


def test_graph():
    manifests = Path("tests").glob("**/*.yaml")
    parse_resources(manifests, "deleteme")


@pytest.mark.parametrize(
    "image",
    [
        "image-registry.openshift-image-registry.svc:5000/foo-foo/bar-bars",
        "image-registry.openshift-image-registry.svc:5000/foo-foo/bar-bar@sha256:fafafa",
        "alpine",
        "library/alpine",
        "docker.io/library/alpine",
    ],
)
def test_image(image):
    g = Graph()
    for triple in DC.parse_image(image, URIRef("urn:k8s:Container/uri")):
        g.add(triple)

    assert "fafafa" not in g.serialize()
