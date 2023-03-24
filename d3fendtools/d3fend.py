import logging
import re
import unicodedata
from time import time

from rdflib import Graph

from . import mermaidrdf

log = logging.getLogger(__name__)
HEADERS = ["node", "relation", "artifact", "technique"]

QUERIES = {
    "kubernetes": {
        "attack": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
    ?node ?relation ?artifact ?attack_id ?attack_label ?attack
WHERE {
    ?node a ?kind .
    ?kind rdfs:subClassOf k8s:Kind .
    ?kind ?relation ?artifact .
    # boilerplate.
    ?attack d3f:attack-id ?attack_id .
    ?attack ?attacks ?artifact .
    ?attack rdfs:label ?attack_label .
}
""",
        "d3fend": """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
    ?node ?relation ?artifact ?attack_id ?attack_label ?attack
WHERE {
    ?node a ?kind .
    ?kind rdfs:subClassOf k8s:Kind .
    ?kind ?relation  ?artifact .
    # boilerplate.
    ?d3fend d3f:d3fend-id ?d3fend_id .
    ?d3fend ?defends ?artifact .
    ?d3fend rdfs:label ?d3fend_label .
}
""",
    },
    "mermaid": {
        "d3fend": """
prefix : <https://par-tec.it/example#>
prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
    ?node ?relation ?artifact ?d3fend_id ?d3fend_label ?d3fend
WHERE {
    ?node a :Node .
    ?node ?relation ?artifact .
    ?d3fend d3f:d3fend-id ?d3fend_id .
    ?d3fend ?defends ?artifact .
    ?d3fend rdfs:label ?d3fend_label .
    }
""",
        "attack": """
prefix : <https://par-tec.it/example#>
prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT DISTINCT
    ?node ?relation ?artifact ?attack_id ?attack_label ?attack
WHERE {
    ?node a :Node .
    ?node ?relation ?artifact .
    ?attack d3f:attack-id ?attack_id .
    ?attack ?attacks ?artifact .
    ?attack rdfs:label ?attack_label .
    }
""",
    },
}


def attack_summary(g: Graph, type="mermaid"):
    ret = list(g.query(QUERIES[type]["attack"]))
    return [HEADERS] + [render_row(row) for row in ret]


def d3fend_summary(g: Graph, type="mermaid"):
    ret = list(g.query(QUERIES[type]["d3fend"]))
    return [HEADERS] + [render_row(row) for row in ret]


def d3fend_summary_html(g: Graph, aggregate=False):
    return f_summary_html(g, aggregate, d3fend_summary)


def attack_summary_html(g: Graph, aggregate=False):
    return f_summary_html(g, aggregate, attack_summary)


def f_summary_html(g: Graph, aggregate=False, summary_function=d3fend_summary):
    try:
        import pandas as pd

        rows = summary_function(g)
        df = pd.DataFrame(data=rows[1:], columns=rows[0])
        if aggregate:
            df = df.groupby(["node", "artifact", "technique"], as_index=False).agg(
                ",".join
            )
        df = df[HEADERS]
        html = df.to_html(
            formatters=[markdown_link_to_html_link] * len(HEADERS), escape=False
        )
    except Exception as e:
        log.exception(e)
        html = "<pre>" + str(e) + "</pre>"
    return html


def list_as_html_table(rows):
    html = "<table>"
    for row in rows:
        html += "<tr>"
        try:
            cells = render_row(row)
            for cell in cells:
                cell = markdown_link_to_html_link(cell)
                html += f"<td>{cell}</td>"
        except Exception as e:
            log.exception(row + " " + str(e))
        html += "</tr>"
    html += "</table>"
    return html


def markdown_link_to_html_link(markdown_link):
    if markdown_link.startswith("["):
        label, url = markdown_link[1:].split("](")
        return f'<a href="{url[:-1]}" target="_blank" rel="noopener noreferrer">{label}</a>'
    return markdown_link


def render_row(row):
    """
    https://next.d3fend.mitre.org/technique/d3f:Client-serverPayloadProfiling/
    """

    def _fix_url(url):
        url = str(url).replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")
        url = str(url).replace("https://par-tec.it/example#", ":")
        url = str(url).replace("http://www.w3.org/1999/02/22-rdf-syntax-ns#", "rdf:")
        return url.rsplit("/", 1)[-1]

    def _get_technique_url(technique_id, technique_uri):
        if not technique_id or not technique_uri:
            return ""

        if technique_id.startswith("T"):
            attack_url = technique_id.replace(".", "/")
            return f"https://attack.mitre.org/techniques/{attack_url}"
        if technique_id.startswith("D3"):
            d3fend_url = technique_uri.split("#", 1)[-1]
            return f"https://next.d3fend.mitre.org/technique/d3f:{d3fend_url}"
        raise NotImplementedError(technique_id, technique_uri)

    node, relation, artifact, technique_id, technique_label, technique_uri = row
    artifact_name = artifact.split("#")[-1]
    artifact_url = f"https://next.d3fend.mitre.org/dao/artifact/d3f:{artifact_name}"

    technique_url = _get_technique_url(technique_id, technique_uri)
    return (
        _fix_url(node),
        _fix_url(relation),
        f"[{artifact_name}]({artifact_url})",
        f"[{technique_id} - {technique_label}]({technique_url})",
    )


def render_unicode_emojis(text):
    re_emoji = re.compile("u:u-([a-zA-Z0-9_-]+)")
    return re_emoji.sub(
        lambda match: unicodedata.lookup(
            match.group(1).upper().replace("_", " ").replace("-", " ")
        ),
        text,
    )


def initialize_graph(ontologies):
    ts = time()
    log.info("Loading ontologies..")
    g = Graph()
    g.bind("d3f", mermaidrdf.NS_D3F)
    for ontology in ontologies:
        g.parse(ontology, format="turtle")
    log.info(f"Ontologies loaded in {time()-ts}s")
    return g
