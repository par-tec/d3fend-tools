import logging
import re
import unicodedata
from time import time

import d3fend
import mermaidrdf
from rdflib import Graph

log = logging.getLogger(__name__)
HEADERS = ["node", "relation", "artifact", "technique"]

flip_mermaid = mermaidrdf.flip_mermaid
filter_mermaid = mermaidrdf.filter_mermaid


MERMAID_INIT_TEXT = """
graph

a[d3f:WebServerApplication] -->|d3f:Email| SMTP[d3f:MailServer]

"""

x = """
graph LR

%% 1. Design here your architecture using MermaidJS syntax.
%% 2. Click on the "D3FEND" tab to see the possible attack paths.
%% 3. Explore the other features selecting the other tabs!

%% The simple arrow maps to d3f:accesses
Client --> WebMail

%% Font-awesome icons can be used to indicate that
%%   a node is a class (e.g. fa-react maps to a WebUI)
WebMail[WebMail fab:fa-react fa:fa-envelope]

%% Font-Awesome icons can indicate that a node
%%   accesses specific resources
%%   (e.g. fa-envelope represent a d3f:Email)
WebMail -->|fa:fa-envelope| IMAP[IMAP fa:fa-envelope fa:fa-folder]
WebMail -->|fa:fa-envelope| SMTP[SMTP fa:fa-envelope fa:fa-folder]
IMAP --> Mailstore[Mailstore fa:fa-envelope fa:fa-folder]

%% Associated d3f:DigitalArtifacts can be referenced via URIs too.
Authorization[d3f:AuthorizationService fa:fa-user-secret] --> |d3f:authenticates| Client
IMAP --o Authorization
SMTP --o Authorization

%% You can detail the kind of traffic using d3f: entities.
WebMail --> |d3f:DatabaseQuery| MySQL

MySQL[(UserPreferences fa:fa-user-secret)] --> DataVolume[(Tablespace fa:fa-hard-drive d3f:Volume)]

"""


def initialize_graph(ontologies):
    ts = time()
    log.info("Loading ontologies..")
    g = Graph()
    g.bind("d3f", mermaidrdf.NS_D3F)
    for ontology in ontologies:
        g.parse(ontology, format="turtle")
    log.info(f"Ontologies loaded in {time()-ts}s")
    return g


def markdown_to_mermaid(text):
    mermaid_graphs = mermaidrdf.extract_mermaid(text)
    mermaid = "graph LR\n" + "\n".join(
        re.sub(r"^graph.*\n", "", graph) for graph in mermaid_graphs
    )
    return mermaid


def markdown_to_rdf(text):
    mermaid_graphs = mermaidrdf.extract_mermaid(text)
    turtle = ""
    for graph in mermaid_graphs:
        turtle += "\n" + mermaidrdf.parse_mermaid(graph)
    return turtle


def content_to_rdf(text):
    dispatch_table = {
        "mermaid": mermaidrdf.parse_mermaid,
        "markdown": markdown_to_rdf,
    }
    text_type = guess_content(text)
    if text_type not in dispatch_table:
        return f"Unsupported content type {text_type}"
    f = dispatch_table[text_type]
    return f(text)


def guess_content(text):
    """Guess the content type of the text: mermaid or markdown."""
    text = text.strip()
    if text.startswith("graph"):
        # XXX: we still need to strip '---\ntitle: ...\n---'
        return "mermaid"
    if "```mermaid" in text:
        return "markdown"
    return None


d3fend_summary = d3fend.d3fend_summary
d3fend_summary_html = d3fend.d3fend_summary_html
attack_summary = d3fend.attack_summary
attack_summary_html = d3fend.attack_summary_html


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
