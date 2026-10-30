"""Dependency-free checks for the Android and FOFA catalog additions.

These tests exercise only pure helpers: catalog metadata, FOFA query encoding,
Android argv parsing, APK manifest parsing helpers, and the native-tool
categorizer. Nothing here needs adb, androguard, frida, objection, mitmproxy,
a network connection, or the FOFA_KEY environment variable.
"""

from __future__ import annotations

import base64
import unittest
import xml.etree.ElementTree as ElementTree

from drost_ai import android_cli, android_scan, fofa_cli
from drost_ai.catalog import CATALOG, SPECIAL_DESCRIPTIONS, category_counts
from drost_ai.server import FIXED_MCP_TOOL_COUNT, _native_category


class CatalogAdditionTests(unittest.TestCase):
    def test_android_and_fofa_are_catalog_executables(self) -> None:
        by_name = {spec.name: spec for spec in CATALOG}
        self.assertIn("drost_android", by_name)
        self.assertIn("drost_fofa", by_name)
        self.assertEqual(by_name["drost_android"].executable, "drost-android")
        self.assertEqual(by_name["drost_fofa"].executable, "drost-fofa")
        self.assertEqual(by_name["drost_android"].category, "android")
        self.assertEqual(by_name["drost_fofa"].category, "enumeration")

    def test_new_categories_have_descriptions(self) -> None:
        self.assertIn("android", SPECIAL_DESCRIPTIONS)
        self.assertIn("fofa", SPECIAL_DESCRIPTIONS)
        by_name = {spec.name: spec for spec in CATALOG}
        self.assertIn("adb", by_name["drost_android"].description)
        self.assertIn("FOFA", by_name["drost_fofa"].description)

    def test_category_counts_include_android_and_grown_enumeration(self) -> None:
        counts = category_counts()
        self.assertEqual(counts["android"], 1)
        self.assertEqual(counts["enumeration"], 17)
        self.assertEqual(sum(counts.values()), len(CATALOG))

    def test_native_tool_count_is_unchanged(self) -> None:
        # android and fofa are executable-backed, so the Drost-native budget
        # must stay at 64 (23 legacy + 29 other native + 12 blockchain).
        self.assertEqual(FIXED_MCP_TOOL_COUNT, 64)


class NativeCategoryTests(unittest.TestCase):
    def test_blockchain_bucketing_still_works(self) -> None:
        self.assertEqual(_native_category("drost_evm_chain_info"), "blockchain")
        self.assertEqual(_native_category("drost_evm_selector_lookup"), "blockchain")
        self.assertEqual(_native_category("drost_solidity_audit"), "blockchain")

    def test_other_buckets_are_not_shadowed(self) -> None:
        self.assertEqual(_native_category("drost_bash"), "execution")
        self.assertEqual(_native_category("drost_engagement_create"), "engagement")
        self.assertEqual(_native_category("drost_http_repeater"), "http_workbench")
        self.assertEqual(_native_category("drost_openapi_audit"), "api_audit")
        self.assertEqual(_native_category("drost_workspace_list"), "workspace")


class FofaEncodingTests(unittest.TestCase):
    def test_encode_query_is_plain_base64_of_the_stripped_query(self) -> None:
        query = 'domain="example.com" && port="443"'
        encoded = fofa_cli.encode_query(f"  {query}  ")
        self.assertEqual(encoded, base64.b64encode(query.encode("utf-8")).decode("ascii"))
        self.assertEqual(base64.b64decode(encoded).decode("utf-8"), query)

    def test_encode_query_rejects_blank_queries(self) -> None:
        with self.assertRaises(fofa_cli.FofaError):
            fofa_cli.encode_query("   ")

    def test_parse_fields_defaults_and_splits(self) -> None:
        self.assertEqual(fofa_cli.parse_fields(None), list(fofa_cli.DEFAULT_FIELDS))
        self.assertEqual(fofa_cli.parse_fields("  "), list(fofa_cli.DEFAULT_FIELDS))
        self.assertEqual(fofa_cli.parse_fields("ip, port ,,"), ["ip", "port"])

    def test_parser_exposes_the_four_subcommands(self) -> None:
        parser = fofa_cli.build_parser()
        for argv in (["info"], ["search", 'domain="example.com"'], ["host", "192.0.2.10"], ["stats", "port=443"]):
            with self.subTest(argv=argv):
                self.assertTrue(callable(parser.parse_args(argv).func))


class AndroidCliTests(unittest.TestCase):
    def test_parser_keeps_the_documented_subcommands(self) -> None:
        parser = android_cli.build_parser()
        self.assertEqual(parser.parse_args(["devices"]).command, "devices")
        args = parser.parse_args(["--serial", "emulator-5554", "connect", "192.0.2.10:5555"])
        self.assertEqual(args.serial, "emulator-5554")
        self.assertEqual(args.address, "192.0.2.10:5555")
        self.assertEqual(parser.parse_args(["pair", "192.0.2.10:37000", "123456"]).code, "123456")
        self.assertEqual(parser.parse_args(["tap", "10", "20"]).y, 20)

    def test_parse_devices_reads_adb_l_device_output(self) -> None:
        output = (
            "List of devices attached\n"
            "emulator-5554 device product:sdk_gphone64 model:Pixel_7 device:emu64\n"
            "192.0.2.10:5555 unauthorized\n"
            "\n"
        )
        devices = android_cli._parse_devices(output)
        self.assertEqual([item["serial"] for item in devices], ["emulator-5554", "192.0.2.10:5555"])
        self.assertEqual(devices[0]["state"], "device")
        self.assertEqual(devices[0]["model"], "Pixel_7")
        self.assertEqual(devices[1]["state"], "unauthorized")


class AndroidManifestParsingTests(unittest.TestCase):
    MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <uses-permission android:name="android.permission.INTERNET" />
  <permission android:name="com.example.CUSTOM" android:protectionLevel="signature" />
  <application android:label="Example">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:name=".HiddenActivity" android:exported="false" />
    <activity android:name=".ImplicitActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="https" android:host="example.com" android:pathPrefix="/open" />
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

    def setUp(self) -> None:
        self.manifest = ElementTree.fromstring(self.MANIFEST)
        self.application = self.manifest.find("application")

    def test_components_report_declared_and_effective_export(self) -> None:
        activities = android_scan._components(self.application, "activity")
        by_name = {item["name"]: item for item in activities}
        self.assertTrue(by_name[".MainActivity"]["exported_declared"])
        self.assertTrue(by_name[".MainActivity"]["effectively_exported"])
        self.assertFalse(by_name[".HiddenActivity"]["effectively_exported"])
        # No android:exported and an intent filter means implicitly exported.
        self.assertFalse(by_name[".ImplicitActivity"]["exported_declared"])
        self.assertTrue(by_name[".ImplicitActivity"]["effectively_exported"])

    def test_main_activity_and_deep_links(self) -> None:
        activities = android_scan._components(self.application, "activity")
        self.assertEqual(android_scan._main_activity(activities), ".MainActivity")
        self.assertEqual(
            android_scan._deep_links(activities, "activity"),
            [{"component": ".ImplicitActivity", "kind": "activity", "scheme": "https", "host": "example.com", "pathPrefix": "/open"}],
        )

    def test_declared_permissions(self) -> None:
        # Only declared custom permissions are reported; uses-permission grants
        # are intentionally not part of the report.
        self.assertEqual(
            android_scan._declared_permissions(self.manifest),
            [{"kind": "permission", "name": "com.example.CUSTOM", "protection_level": "signature"}],
        )


if __name__ == "__main__":
    unittest.main()
