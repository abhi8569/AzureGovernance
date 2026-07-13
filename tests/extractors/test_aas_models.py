"""Tests for Analysis Services extractor."""
from __future__ import annotations

import pytest

from src.extractors.aas.models import AnalysisServicesExtractor


@pytest.fixture
def aas_extractor():
    return AnalysisServicesExtractor(
        server_url="asazure://westus.asazure.windows.net/myserver",
        token="fake-token",
        tenant_id="tenant-1",
        snapshot_id=1,
    )


@pytest.fixture
def pbi_extractor():
    return AnalysisServicesExtractor(
        server_url="powerbi://api.powerbi.com/v1.0/myorg/MyWorkspace",
        token="fake-token",
        tenant_id="tenant-1",
        snapshot_id=1,
    )


class TestXmlaEndpoint:
    """Tests for XMLA endpoint URL conversion."""

    def test_aas_endpoint(self, aas_extractor) -> None:
        assert aas_extractor.xmla_endpoint == "https://westus.asazure.windows.net/myserver/xmla"

    def test_pbi_endpoint(self, pbi_extractor) -> None:
        assert pbi_extractor.xmla_endpoint == "https://api.powerbi.com/v1.0/myorg/MyWorkspace"

    def test_raw_url_passthrough(self) -> None:
        ext = AnalysisServicesExtractor("https://custom.endpoint/xmla", "t", "t", 1)
        assert ext.xmla_endpoint == "https://custom.endpoint/xmla"


class TestParseXmlaRowset:
    """Tests for XMLA XML response parsing."""

    def test_basic_rowset(self) -> None:
        xml = """<?xml version="1.0"?>
        <return xmlns="urn:schemas-microsoft-com:xml-analysis">
            <root xmlns="urn:schemas-microsoft-com:xml-analysis:rowset">
                <row>
                    <CATALOG_NAME>SalesModel</CATALOG_NAME>
                    <DESCRIPTION>Sales data model</DESCRIPTION>
                </row>
                <row>
                    <CATALOG_NAME>HRModel</CATALOG_NAME>
                    <DESCRIPTION>HR data</DESCRIPTION>
                </row>
            </root>
        </return>"""
        result = AnalysisServicesExtractor._parse_xmla_rowset(xml)
        assert len(result) == 2
        assert result[0]["CATALOG_NAME"] == "SalesModel"
        assert result[1]["CATALOG_NAME"] == "HRModel"

    def test_empty_response(self) -> None:
        xml = """<?xml version="1.0"?><return><root/></return>"""
        result = AnalysisServicesExtractor._parse_xmla_rowset(xml)
        assert len(result) == 0

    def test_malformed_xml(self) -> None:
        result = AnalysisServicesExtractor._parse_xmla_rowset("not xml at all")
        assert len(result) == 0

    def test_namespaced_rows(self) -> None:
        xml = """<?xml version="1.0"?>
        <return xmlns="urn:schemas-microsoft-com:xml-analysis">
            <root xmlns:rs="urn:schemas-microsoft-com:xml-analysis:rowset">
                <rs:row>
                    <rs:Name>TestRole</rs:Name>
                    <rs:ModelPermission>read</rs:ModelPermission>
                </rs:row>
            </root>
        </return>"""
        result = AnalysisServicesExtractor._parse_xmla_rowset(xml)
        assert len(result) == 1
        assert result[0]["Name"] == "TestRole"


class TestHeaders:
    """Tests for XMLA request headers."""

    def test_auth_header(self, aas_extractor) -> None:
        headers = aas_extractor.headers
        assert headers["Authorization"] == "Bearer fake-token"
        assert headers["Content-Type"] == "text/xml"
