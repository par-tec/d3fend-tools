from itertools import product
from pathlib import Path

import pandas as pd
import pytest

from d3fendtools import d3fend

INIT_FILE = f"{Path(d3fend.__file__).parent}/d3fend-short.ttl"


@pytest.mark.parametrize(
    "fpath,framework",
    product(Path("tests/data/as_mermaid").glob("*.ttl"), "attack d3fend".split()),
)
def test_summary_pd(fpath, framework):
    turtle_text = fpath.read_text()
    type_ = "kubernetes" if "urn:k8s:" in turtle_text else "mermaid"
    f = d3fend.d3fend_summary if framework == "d3fend" else d3fend.attack_summary
    g = d3fend.initialize_graph([INIT_FILE])
    g.parse(data=turtle_text, format="turtle")
    rows = f(g, type=type_)
    df = pd.DataFrame(rows[1:], columns=rows[0])
    html = df.to_html(formatters=[d3fend.markdown_link_to_html_link] * 4, escape=False)
    assert html
    Path(
        f"tests/data/as_mermaid/deleteme-out-{framework}-{fpath.stem}.html"
    ).write_text(str(html))
