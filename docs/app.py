import logging
import re
import unicodedata
from time import time

from rdflib import RDF, Graph

from d3fendtools import as_mermaid, d3fend, kuberdf, mermaidrdf

try:
    import js
    from pyodide.ffi import create_proxy
    from pyscript import Element
except ImportError:
    pass

log = logging.getLogger(__name__)
HEADERS = ["node", "relation", "artifact", "technique"]

flip_mermaid = mermaidrdf.flip_mermaid
filter_mermaid = mermaidrdf.filter_mermaid
d3fend_summary = d3fend.d3fend_summary
d3fend_summary_html = d3fend.d3fend_summary_html
attack_summary = d3fend.attack_summary
attack_summary_html = d3fend.attack_summary_html

MERMAID_INIT_TEXT = """graph LR

%% 1. Design here your architecture using MermaidJS syntax.
%% 2. Click on the "ATTACK" tab to see the possible attack paths.
%% 3. Explore the other features selecting the other tabs!

%% The simple arrow maps to d3f:accesses
Client --> WebMail

%% Font-awesome icons can be used to indicate that
%%   a node is a class (e.g. fa-react maps to a WebUI)
WebMail[WebMail fab:fa-react]

%% Discover digital artifacts using the completion feature.
%%   Type "d3f:" and press CTRL+space to see the list of available artifacts.
%%   Then use TAB to complete.
WebMail -->|d3f:Email| IMAP[IMAP d3f:MailServer]
WebMail -->|sends d3f:Email| SMTP[SMTP d3f:MailServer]
IMAP --> Mailstore[Mailstore d3f:Volume]

%% Associated d3f:DigitalArtifacts can be decorated with font-awesome too.
Authorization[d3f:AuthorizationService Identity] --> |d3f:authenticates| Client

%% You can detail the kind of traffic using d3f: entities.
WebMail --> |d3f:DatabaseQuery| MySQL

MySQL[(UserPreferences d3f:PasswordDatabase)] --> DataVolume[(Tablespace d3f:Volume)]

%% Subgraphs can be used to group nodes.
Client
subgraph Platform
WebMail
IMAP
SMTP
MySQL
DataVolume
Mailstore
Authorization
end

%% You can use the "classDef" directive to define the style of a class.
classDef boundary fill:none, stroke-dasharray: 5
class Platform boundary

"""


def rdf_to_mermaid_filtered(g, match=""):
    x = Graph()
    # Add all g triples to x
    for s, p, o in g:
        if (p, o) == (RDF.type, kuberdf.K8S.Namespace):
            x.add((s, p, o))
        if match in f"{s}{o}":
            x.add((s, p, o))
    return rdf_to_mermaid(x)


def rdf_to_mermaid(g: Graph):
    mermaid = as_mermaid.RDF2Mermaid(g)
    return mermaid.render()


def initialize_graph(ontologies):
    ts = time()
    log.info("Loading ontologies..")
    g = Graph()
    g.bind("d3f", mermaidrdf.NS_D3F)
    for ontology in ontologies:
        g.parse(ontology, format="turtle")
    log.info(f"Ontologies loaded in {time() - ts}s")
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


def _copy_element_to_clipboard_with_js(element_id):
    """Copy text to clipboard using javascript.

    :param id_: id of the element to copy
     When a js object is not available in pyodide, we can use
     the inherited `proxy.new` method to call the constructor.

     Dictionaries are passed as keyword arguments using the `**` syntax.
    """
    type_ = "text/html"
    text = Element(element_id).element.innerHTML
    log.info(f"Copying to clipboard: {text[:100]}..")
    blob = js.Blob.new([text], **{"type": type_})
    ci = js.ClipboardItem.new(**{type_: blob})
    js.navigator.clipboard.write([ci])


def _copy_text_to_clipboard(text):
    """Copy text to clipboard using javascript.

    :param id_: id of the element to copy
     When a js object is not available in pyodide, we can use
     the inherited `proxy.new` method to call the constructor.

     Dictionaries are passed as keyword arguments using the `**` syntax.
    """
    type_ = "text/plain"
    log.info(f"Copying to clipboard: {text[:100]}..")
    blob = js.Blob.new([text], **{"type": type_})
    ci = js.ClipboardItem.new(**{type_: blob})
    ret = js.navigator.clipboard.write([ci])
    log.info(ret.then(log.info, log.info))


def event_listener(element_id, event_type):
    def decorator(callback):
        Element(element_id).element.addEventListener(event_type, create_proxy(callback))

    return decorator


# when pressing mermaid-btn-fullscreen set the mermaid-graph class to full
def mermaid_toggle_fullscreen(event):
    log.warning("Toggle fullscreen")
    mermaid_graph = Element("mermaid-graph")
    input_panel = Element("input-panel")
    tools_panel = Element("tools-panel")
    if "diagram-normal" in mermaid_graph.element.classList:
        mermaid_graph.remove_class("diagram-normal")
        mermaid_graph.add_class("diagram-full")
        input_panel.add_class("visually-hidden")
        tools_panel.remove_class("mw-50")
    else:
        mermaid_graph.add_class("diagram-normal")
        mermaid_graph.remove_class("diagram-full")
        input_panel.remove_class("visually-hidden")
        tools_panel.add_class("mw-50")


def alert(text):
    Element("error-panel").clear()
    Element("error-panel").add_class("alert-danger")
    Element("error-panel").remove_class("alert-success")
    Element("error-panel").element.append(text)


def alert_clear():
    Element("error-panel").clear()
    Element("error-panel").add_class("alert-success")
    Element("error-panel").element.append("Mermaid parsed successfully.")


def generate_diagram_mmd(text: str, filter_: str, flip: str, mermaidAPI):
    content_type = guess_content(text)
    if content_type == "markdown":
        log.info("Markdown detected.")
        text_mmd = markdown_to_mermaid(text)
    elif content_type == "mermaid":
        log.info("Mermaid detected.")
        text_mmd = text
    else:
        log.warning("Unknown content.")
        text_mmd = text

    log.info(f"pre-filter {text_mmd}")
    if filter_:
        text_mmd = filter_mermaid(text_mmd, filter_)

    # Format the graph.
    text_mmd = mermaidrdf.D3fendMermaid(text_mmd).mermaid()
    if flip:
        text_mmd = flip_mermaid(text_mmd)
    log.warning(f"mermaid text: {text_mmd[:100]}")

    return _render_mermaid_v10(text_mmd, mermaidAPI)


def _render_mermaid_v9(text_mmd, mermaidAPI):
    mermaid_svg = mermaidAPI.render("mermaid-diagram-svg", text_mmd)
    return text_mmd, mermaid_svg


def _render_mermaid_v10(text_mmd, mermaidAPI):
    ret = {"v": None}
    mermaidAPI.render("mermaid-diagram-svg", text_mmd).then(
        lambda svg: ret.update({"v": svg}),
        lambda err: ret.update({"v": f"Error: {err}"}),
    )
    log.warning(f"coro: {ret}")
    return text_mmd, ret["v"]


def test_generate_diagram_mmd():
    text = """
    graph TD

    a["{ciao fa:fa-car}"]
    µs3 --> smtp
    mysql
    """

    class MermaidAPI:
        def render(self, id, text):
            return text

    mermaidAPI = MermaidAPI()
    text_mmd, mermaid_svg = generate_diagram_mmd(text, None, None, mermaidAPI)
    raise NotImplementedError
