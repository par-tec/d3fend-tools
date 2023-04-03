import json
import shlex
import shutil
import subprocess
from pathlib import Path

import yaml
from rdflib import Graph  # pip install rdflib pyld


def generate_monaco_completion(items):
    def _item(label, documentation, insert_text, rdf_type):
        if rdf_type == "d3f:DefensiveTechnique":
            kind = "Interface"
        elif rdf_type == "d3f:OffensiveTechnique":
            kind = "Event"
        elif rdf_type == "d3f:DigitalArtifact":
            kind = "Class"
        elif rdf_type == "d3f:d3fend-object-property":
            kind = "Property"
        else:
            raise ValueError(f"Unknown rdf_type: {rdf_type}")

        return f"""
        {{
            label: '{label}',
            kind: monaco.languages.CompletionItemKind.{kind},
            documentation: {json.dumps(documentation)},
            insertText: '{insert_text}',
            range: range,
        }}
        """

    js_text = f"""
    function createD3fCompletion(range) {{
        return [{','.join(_item(**x) for x in items)}];
        }}
    """
    return js_text


def _monaco_completion(g):
    items = []
    for rdf_type, rdf_predicate in [
        ("d3f:DefensiveTechnique", "rdfs:subClassOf*"),
        ("d3f:OffensiveTechnique", "rdfs:subClassOf*"),
        ("d3f:DigitalArtifact", "rdfs:subClassOf*"),
        ("d3f:d3fend-object-property", "rdfs:subPropertyOf*"),
    ]:
        ret = g.query(
            f"""
            SELECT DISTINCT ?s ?label ?documentation
            WHERE {{
                ?s {rdf_predicate} {rdf_type};
                    rdfs:label ?label;
                    d3f:definition ?documentation
                    . }}
            """
        )
        items.extend(
            [
                {
                    "label": x[1],
                    "documentation": x[2],
                    "insert_text": x[0].fragment,
                    "rdf_type": rdf_type,
                }
                for x in ret
            ]
        )

    js_text = generate_monaco_completion(items)
    Path("docs/mermaid/monaco-completion.js").write_text(
        js_text
        + """
function provideCompletionItems(model, position) {
    var textUntilPosition = model.getValueInRange({
        startLineNumber: 1,
        startColumn: 1,
        endLineNumber: position.lineNumber,
        endColumn: position.column,
    });
    var match = textUntilPosition.match(
        /d3f:/
    );
    if (!match) {
        return { suggestions: [] };
    }
    var word = model.getWordUntilPosition(position);
    var range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
    };
    return {
        suggestions: createD3fCompletion(range),
    };
}
    """
    )


def _d3fend_short(g):
    subset = tuple(
        g.query(
            f"CONSTRUCT {{ ?s ?p ?q . }}  WHERE {{ ?s rdfs:subClassOf* d3f:{rdf_type}; ?p ?q . }}"
        )
        for rdf_type in ("DigitalArtifact", "DefensiveTechnique", "OffensiveTechnique")
    )
    short_graph = Graph()
    for x in subset:
        for t in x:
            short_graph.add(t)
    short_graph.serialize("docs/mermaid/d3fend-short.ttl")


def _mermaidrdf_yaml(g):
    properties = g.query(
        "SELECT ?relation  WHERE {{ ?relation rdfs:subPropertyOf* d3f:d3fend-object-property . }}"
    )
    defensive_techniques = g.query(
        "SELECT ?defensive_technique  WHERE {{ ?defensive_technique rdfs:subClassOf* d3f:DefensiveTechnique . }}"
    )
    offensive_techniques = g.query(
        "SELECT ?offensive_technique  WHERE {{ ?offensive_technique rdfs:subClassOf* d3f:OffensiveTechnique . }}"
    )
    artifacts = g.query(
        "SELECT ?artifact  WHERE {{ ?artifact rdfs:subClassOf* d3f:DigitalArtifact . }}"
    )
    data = yaml.safe_load(
        Path("d3fendtools/mermaidrdf/mermaidrdf-template.yaml").read_text()
    )
    data.update(
        {
            "D3F_PROPERTIES": sorted(f"d3f:{x[0].fragment}" for x in properties),
            "D3F_DIGITAL_ARTIFACTS": sorted(f"d3f:{x[0].fragment}" for x in artifacts),
            "D3F_DEFENSIVE_TECHNIQUES": sorted(
                f"d3f:{x[0].fragment}" for x in defensive_techniques
            ),
            "D3F_OFFENSIVE_TECHNIQUES": sorted(
                f"d3f:{x[0].fragment}" for x in offensive_techniques
            ),
        }
    )
    Path("d3fendtools/mermaidrdf/mermaidrdf.yaml").write_text(yaml.dump(data))


def generate_files():
    g = Graph()
    g.parse("https://next.d3fend.mitre.org/ontologies/d3fend.ttl")

    _d3fend_short(g)
    _mermaidrdf_yaml(g)
    _monaco_completion(g)
    subprocess.run(shlex.split("python setup.py bdist_wheel"))


if __name__ == "__main__":

    generate_files()
    FILES = (
        {
            "src": "dist/d3fendtools-0.0.1-py3-none-any.whl",
            "dst": "docs/kube/static/d3fendtools-0.0.1-py3-none-any.whl",
        },
        {"src": "d3fendtools/kuberdf/__init__.py", "dst": "docs/mermaid/kuberdf.py"},
        {"src": "d3fendtools/kuberdf/ontology.ttl", "dst": "docs/mermaid/ontology.ttl"},
        {
            "src": "d3fendtools/mermaidrdf/__init__.py",
            "dst": "docs/mermaid/mermaidrdf.py",
        },
        {
            "src": "d3fendtools/mermaidrdf/mermaidrdf.yaml",
            "dst": "docs/mermaid/mermaidrdf.yaml",
        },
        {
            "src": "d3fendtools/d3fend.py",
            "dst": "docs/mermaid/d3fend.py",
        },
        {"src": "d3fendtools/kuberdf/__init__.py", "dst": "docs/kube/kuberdf.py"},
        {"src": "d3fendtools/kuberdf/ontology.ttl", "dst": "docs/kube/ontology.ttl"},
        {
            "src": "d3fendtools/mermaidrdf/__init__.py",
            "dst": "docs/kube/mermaidrdf.py",
        },
        {
            "src": "d3fendtools/mermaidrdf/mermaidrdf.yaml",
            "dst": "docs/kube/mermaidrdf.yaml",
        },
        {
            "src": "d3fendtools/d3fend.py",
            "dst": "docs/kube/d3fend.py",
        },
        {
            "src": "d3fendtools/as_mermaid/__init__.py",
            "dst": "docs/kube/as_mermaid.py",
        },
    )
    for f in FILES:
        shutil.copy(f["src"], f["dst"])
