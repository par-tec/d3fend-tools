import json
import logging
from pathlib import Path
from time import time
from typing import Iterable
from urllib.parse import urlparse
import re

import yaml
from rdflib import RDF, RDFS, Graph, Literal, Namespace, URIRef


log = logging.getLogger(__name__)

log = logging.getLogger(__name__)
K8S = Namespace("urn:k8s:")
D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
NS_DEFAULT = Namespace("https://par-tec.it/example#")


def dontyield(*a, **kw):
    yield from []


class SkipResource:
    def __init__(self, *a, **k):
        pass

    triples = dontyield


skip_resource_instances = dontyield
SELECTOR_LABELS = ("app.kubernetes.io/name", "app.kubernetes.io/instance", "deployment")
CLASSMAP = {
    ("kustomize.config.k8s.io/v1beta1", "Kustomization"): SkipResource,
    ("kustomize.config.k8s.io/v1alpha1", "Component"): SkipResource,
    ("v1", "Build"): SkipResource,
    ("v1", "ConsolePlugin"): None,
    ("v1", "Endpoint"): None,
    ("v1", "Endpoints"): None,
    ("v1", "Pod"): SkipResource,
    ("v1", "Project"): SkipResource,
    ("v1", "Secret"): None,
    ("autoscaling/v1", "HorizontalPodAutoscaler"): SkipResource,
    ("batch/v1", "Job"): SkipResource,
    ("image.openshift.io/v1", "ImageStream"): None,
    ("image.openshift.io/v1", "ImageStreamTag"): None,
}


def _register(cls):
    """Class decorator to register a class in the CLASSMAP"""
    if not hasattr(cls, "apiVersion") or not hasattr(cls, "kind"):
        raise ValueError(f"Class {cls} must have apiVersion and kind attributes")
    if not hasattr(cls, "triples"):
        raise ValueError(f"Class {cls} must have a triples method")
    if not hasattr(cls, "parse_resource"):
        raise ValueError(f"Class {cls} must have a parse_resource method")
    CLASSMAP[(cls.apiVersion, cls.kind)] = cls
    return cls


class D3fendKube:
    def __init__(self, text, ontology=None) -> None:
        self.text = text
        self.ontology = ontology or Graph()
        self.annotations = None
        self.hypergraph = None
        self.g = Graph()
        self.g.bind("", NS_DEFAULT)
        self.g.bind("d3f", D3F)
        self.g.bind("rdfs", RDFS)
        self._turtle = None
        self._out = None

    def parse(self):
        raise NotImplementedError

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
                    "d3f": D3F,
                },
            )
            self.annotations = annotations.graph
            g = self.g | annotations.graph
            log.info("Annotated graph has %s triples", len(g) - len(self.g))
            self.hypergraph = g | self.ontology
        return self.hypergraph

    def mermaid(self):
        raise NotImplementedError


def strip_oci_image_tag(image: str) -> str:
    """Strip the tag from an OCI image name"""
    return image.rsplit(":")[0].split("@sha256", 1)[0]


def parse_resources(
    resources: Iterable[Path], outfile: str, ns_from_file=False, jsonld_output=False
) -> Graph:
    g = Graph()
    g.parse(data=(Path(__file__).parent / "ontology.ttl").read_text(), format="turtle")
    g.bind("k8s", K8S)
    for f in resources:
        ns = f.stem if ns_from_file else None
        log.info(f"Parsing {f} with namespace {ns}")
        try:
            parse_manifest_as_graph(f.read_text(), g=g, manifest_format=f.suffix[1:])
        except Exception as e:
            log.exception(f"Error parsing {f}: {e}")
            raise  # continue
    dpath = Path(outfile)
    g.serialize(dpath.with_suffix(".ttl").as_posix(), format="turtle")
    if jsonld_output:
        g.serialize(
            dpath.with_suffix(".jsonld").as_posix(), format="application/ld+json"
        )
    return g


def parse_manifest(manifest_text: str) -> str:
    """Parse a manifest text and return a list of triples"""
    g = parse_manifest_as_graph(manifest_text)
    return g.serialize(format="turtle")


def parse_manifest_as_graph(
    manifest_text: str, manifest_format="yaml", g=None
) -> Graph:
    """Parse a manifest text and return a list of triples.
    If a graph is provided, the triples will be added to it,
    otherwise a new graph will be created.
    """

    def _json_loads_array(json_text):
        return (json.loads(json_text),)

    ts = time()
    log.info(f"Reading manifest with format {manifest_format}")
    manifest_text = manifest_text.strip()
    if manifest_format == "yaml":
        parser_f = yaml.safe_load_all
    elif manifest_format == "json" or manifest_text[0] == "{":
        parser_f = _json_loads_array
    else:
        raise ValueError(f"Unknown manifest format: {manifest_format}")
    log.warning(f"Read manifest in %d Using parser {parser_f}", (time() - ts))
    g = g or Graph()
    g.bind("k8s", K8S)
    for manifest in parser_f(manifest_text):
        if not manifest:
            continue
        if "kind" not in manifest:
            log.error(f"Invalid manifest without kind: {manifest}")
            continue
        log.error("Parsing manifest %s", manifest.get("kind"))
        for triple in K8Resource.parse_resource(manifest):
            g.add(triple)
    return g


def parse_url(url):
    url = url.strip("jdbc:")
    if "//" not in url:
        raise ValueError(f"Invalid URL: {url}")
    u = urlparse(url)
    if ":" not in u.netloc:
        if u.scheme == "mysql":
            u = u._replace(netloc=f"{u.netloc}:3306")
        elif u.scheme == "http":
            u = u._replace(netloc=f"{u.netloc}:80")
        elif u.scheme == "https":
            u = u._replace(netloc=f"{u.netloc}:443")
    return u.netloc


class K8Resource:
    # Define classmap as a static class constant

    @staticmethod
    def factory(manifest, ns=None):
        kind = manifest.get("kind")
        api_version = manifest.get("apiVersion")
        log.error(f"Parsing {kind} with apiVersion {api_version} in namespace {ns}")
        # Use CLASSMAP as the key to fetch the class
        clz = CLASSMAP.get((api_version, kind)) or K8Resource
        return clz(manifest, ns=ns)

    @staticmethod
    def parse_resource(manifest: dict, ns=None):
        """Parse an OpenShift manifest file
        and convert it to an RDF resource
        """
        resource = K8Resource.factory(manifest, ns=ns)
        try:
            if resource.namespace.startswith(("kube-system", "openshift-")):
                # Ignore kube-system and openshift- namespaces
                return
        except AttributeError:
            pass
        yield from resource.triples()

    def __init__(self, manifest: dict | None = None, ns: str = None) -> None:
        if ":" in str(ns):
            raise ValueError(f"Invalid namespace: {ns}")
        manifest = manifest or {}
        self.manifest = manifest
        self.kind = manifest["kind"]
        self.metadata = manifest["metadata"]
        self.name = self.metadata["name"]
        self.namespace = manifest["metadata"].get("namespace", ns or "default")
        self.ns = URIRef(f"https://k8s.local/{self.namespace}")
        self.spec = manifest.get("spec", {})
        if self.kind == "Namespace":
            self.uri = self.ns
        else:
            self.uri = self.ns + f"/{self.kind}/{self.name}"

        # Set the application.
        self.app = self.get_app_uri(self.metadata)

    @property
    def label(self):
        labelmap = {
            "BuildConfig": "bc",
            "Deployment": "dc",
            "DeploymentConfig": "dc",
            "ImageStream": "is",
            "ImageStreamTag": "ist",
            "Namespace": "ns",
            "PersistentVolumeClaim": "pvc",
            "RoleBinding": "rb",
            "Route": "route",
            "ServiceAccount": "sa",
            "StatefulSet": "ss",
            "Service": "svc",
        }
        if self.kind in labelmap:
            return f"{labelmap[self.kind]}/{self.name}"
        return f"{self.kind}:{self.name}"

    def triples_kind(self):
        yield (K8S[self.kind], RDF.type, K8S.Kind)

    def triples_ns(self):
        yield self.ns, RDF.type, K8S.Namespace
        yield self.ns, RDFS.label, Literal(self.namespace)
        yield K8S.cluster, K8S.hasChild, self.ns

    def triples_self(self):
        yield self.uri, RDF.type, K8S[self.kind]
        yield self.uri, K8S.hasNamespace, self.ns
        yield self.ns, K8S.hasChild, self.uri
        yield self.uri, RDFS.label, Literal(self.label)

        for k, v in self.metadata.get("labels", {}).items():
            if k not in SELECTOR_LABELS:
                continue
            yield self.uri, RDFS.label, Literal(f"{k}: {v}")
        if self.app:
            yield self.ns, K8S.hasChild, self.app
            yield self.app, RDF.type, K8S.Application
            yield self.app, K8S.hasChild, self.uri

    def get_app_uri(self, metadata):
        labels = metadata.get("labels", {})
        app = labels.get("app") or labels.get("application")
        return URIRef(self.ns + f"/Application/{app}") if app else None

    def triple_spec(self):
        yield from []

    def triples(self):
        yield from self.triples_ns()
        yield from self.triples_self()
        yield from self.triple_spec()


@_register
class K8List(K8Resource):
    apiVersion = "v1"
    kind = "List"

    def __init__(self, manifest: dict = None, ns: str = None) -> None:
        """A List is a special resource, don't call super.__init__"""
        self.kind = manifest["kind"]
        self.metadata = manifest["metadata"]
        self.namespace = manifest["metadata"].get("namespace", ns or "default_")
        self.ns = K8S[self.namespace]
        self.spec = manifest.get("spec", {})
        self.items = manifest["items"]
        # Set the application.
        self.app = self.get_app_uri(self.metadata)

    def triples(self):
        for item in self.items:
            yield from K8Resource.parse_resource(item, ns=self.namespace)


@_register
class Template(K8Resource):
    apiVersion = "template.openshift.io/v1"
    kind = "Template"

    def __init__(self, manifest: dict = None, ns: str = None) -> None:
        super().__init__(manifest, ns=ns)
        self.parameters = manifest.get("parameters", [])
        self.objects = manifest.get("objects", [])

    def triples(self):
        r = re.compile(r"\$\{+([a-zA-Z_]+)\}+")
        for item in self.objects:
            item = yaml.safe_dump(item)

            item = r.sub(lambda x: x.group(1).lower(), item)
            item = yaml.safe_load(item)
            yield from K8Resource.parse_resource(item, ns=self.namespace)
