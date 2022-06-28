import pip_audit._format as format


def test_markdown(vuln_data):
    markdown_format = format.MarkdownFormat(True)
    expected_markdown = """Name | Version | ID | Fix Versions | Description
--- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | The first vulnerability
foo | 1.0 | VULN-1 | 1.0 | The second vulnerability
bar | 0.1 | VULN-2 |  | The third vulnerability"""
    assert markdown_format.format(vuln_data, list()) == expected_markdown
