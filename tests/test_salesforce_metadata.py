import json
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1] / "integrations/salesforce"


def test_salesforce_project_metadata_is_well_formed():
    project = json.loads((ROOT / "sfdx-project.json").read_text())
    assert (ROOT / project["packageDirectories"][0]["path"]).is_dir()
    files = list(ROOT.rglob("*.cls-meta.xml"))
    assert files
    for path in files:
        element = ElementTree.parse(path).getroot()
        assert element.tag == "{http://soap.sforce.com/2006/04/metadata}ApexClass"
        assert path.with_name(path.name.removesuffix("-meta.xml")).exists()
