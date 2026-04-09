"""
XML loading and validation utilities for FATCA files.

Handles large XML files with stream parsing to avoid memory overflow.
"""

import re
from pathlib import Path

from lxml import etree

from fatca_utils.errors import XMLError

# GIIN format: XXXXXX.XXXXX.XX.XXX
_GIIN_PATTERN = re.compile(r"[A-Z0-9]{6}\.[A-Z0-9]{5}\.[A-Z]{2}\.\d{3}")


def load_xml(path: str | Path) -> etree._ElementTree:
    """
    Load and parse an XML file.

    For very large files, consider using stream_parse_xml() instead.

    Args:
        path: Path to the XML file.

    Returns:
        Parsed ElementTree.

    Raises:
        XMLError: If parsing fails.
    """
    path = Path(path).resolve()
    if not path.is_file():
        raise XMLError(f"XML file not found: {path}")

    try:
        parser = etree.XMLParser(
            remove_blank_text=False,
            huge_tree=True,  # Allow large documents
        )
        return etree.parse(str(path), parser)
    except etree.XMLSyntaxError as e:
        raise XMLError(f"XML syntax error in '{path.name}': {e}") from e
    except Exception as e:
        raise XMLError(f"Failed to load XML '{path.name}': {e}") from e


def validate_xml_wellformed(path: str | Path) -> bool:
    """
    Check if an XML file is well-formed (parseable).

    Args:
        path: Path to the XML file.

    Returns:
        True if well-formed.

    Raises:
        XMLError: If the file is not well-formed XML.
    """
    load_xml(path)
    return True


def validate_xml_against_xsd(
    xml_path: str | Path,
    xsd_path: str | Path,
) -> list[str]:
    """
    Validate XML against an XSD schema.

    Args:
        xml_path: Path to the XML file to validate.
        xsd_path: Path to the XSD schema file.

    Returns:
        List of validation error messages. Empty list = valid.

    Raises:
        XMLError: If files cannot be loaded.
    """
    xml_tree = load_xml(xml_path)

    xsd_path = Path(xsd_path).resolve()
    if not xsd_path.is_file():
        raise XMLError(f"XSD schema file not found: {xsd_path}")

    try:
        xsd_tree = etree.parse(str(xsd_path))
        schema = etree.XMLSchema(xsd_tree)
    except Exception as e:
        raise XMLError(f"Failed to load XSD schema: {e}") from e

    is_valid = schema.validate(xml_tree)
    if is_valid:
        return []

    return [str(err) for err in schema.error_log]


def get_xml_info(path: str | Path) -> dict:
    """
    Extract basic information from an XML file without loading it fully.

    Uses iterparse for memory efficiency.

    Returns:
        Dict with root tag, namespace, and element count estimate.
    """
    path = Path(path).resolve()

    info = {
        "file": str(path),
        "size_bytes": path.stat().st_size,
        "root_tag": None,
        "root_namespace": None,
        "element_count": 0,
    }

    try:
        for event, element in etree.iterparse(str(path), events=("start",)):
            info["element_count"] += 1
            if info["root_tag"] is None:
                qname = etree.QName(element.tag)
                info["root_tag"] = qname.localname
                info["root_namespace"] = qname.namespace
            # Stop after counting a reasonable sample
            if info["element_count"] > 10000:
                info["element_count_note"] = "truncated at 10000"
                break
            element.clear()
    except Exception as e:
        info["parse_error"] = str(e)

    return info


def stream_parse_xml(
    path: str | Path,
    target_tag: str,
):
    """
    Generator that streams XML elements matching target_tag.

    Memory-efficient for large files — only one matching element
    is in memory at a time.

    Args:
        path: Path to the XML file.
        target_tag: Local tag name to extract (without namespace).

    Yields:
        Each matching etree._Element. Elements are cleared after yielding
        to free memory — process each element before requesting the next.
    """
    path = Path(path).resolve()

    context = etree.iterparse(
        str(path),
        events=("end",),
        huge_tree=True,
    )

    for event, element in context:
        local_tag = etree.QName(element.tag).localname
        if local_tag == target_tag:
            yield element
            element.clear()
        # Also clear ancestors to free memory
        while element.getprevious() is not None:
            del element.getparent()[0]


def extract_giin_from_xml(path: str | Path) -> str | None:
    """
    Extract the sender GIIN from a FATCA XML file.

    Looks for GIIN values in these common FATCA XML locations:
    - <GIIN> elements (e.g. under <ReportingFI> or <MessageSpec>)
    - <SendingCompanyIN> under <MessageSpec>
    - Any element whose text matches the GIIN pattern

    Args:
        path: Path to the FATCA XML file.

    Returns:
        The first GIIN found, or None if not found.
    """
    path = Path(path).resolve()
    if not path.is_file():
        return None

    try:
        tree = load_xml(path)
        root = tree.getroot()

        # Search for GIIN in known element names (namespace-agnostic)
        giin_tag_names = {"GIIN", "SendingCompanyIN"}

        for element in root.iter():
            local_tag = etree.QName(element.tag).localname
            if local_tag in giin_tag_names and element.text:
                text = element.text.strip().upper()
                match = _GIIN_PATTERN.search(text)
                if match:
                    return match.group(0)

        # Fallback: scan all text content for GIIN pattern
        for element in root.iter():
            if element.text:
                match = _GIIN_PATTERN.search(element.text.strip().upper())
                if match:
                    return match.group(0)

    except Exception:
        pass

    return None
