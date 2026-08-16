import contextlib
import io
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import tls_auditor


EMPTY_NMAP_XML = "<nmaprun />"

TLS11_NMAP_XML = """\
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.0.2.10" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" />
        <script id="ssl-enum-ciphers">
          <table key="TLSv1.1">
            <table key="ciphers">
              <table>
                <elem key="name">TLS_RSA_WITH_AES_128_GCM_SHA256</elem>
                <elem key="strength">A</elem>
              </table>
            </table>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TemporaryFileTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def write(self, name, contents):
        path = self.root / name
        path.write_text(contents)
        return path


class InputParsingTests(TemporaryFileTestCase):
    def test_detects_and_parses_mixed_hostport_input(self):
        input_file = self.write(
            "targets.txt",
            "example.com:8443\n"
            "[2001:db8::1]:9443\n"
            "2001:db8::2\n"
            "bare.example\n"
            "example.com:8443\n",
        )

        self.assertEqual(tls_auditor.detect_input_format(str(input_file)), "hostport")
        self.assertEqual(
            tls_auditor.parse_hostport_input(str(input_file)),
            [
                {
                    "ip": "example.com",
                    "hostname": "",
                    "port": "8443",
                    "service": "",
                },
                {
                    "ip": "2001:db8::1",
                    "hostname": "",
                    "port": "9443",
                    "service": "",
                },
                {
                    "ip": "2001:db8::2",
                    "hostname": "",
                    "port": "443",
                    "service": "",
                },
                {
                    "ip": "bare.example",
                    "hostname": "",
                    "port": "443",
                    "service": "",
                },
            ],
        )

    def test_bare_ipv6_only_input_is_simple(self):
        input_file = self.write("targets.txt", "2001:db8::10\n")
        self.assertEqual(tls_auditor.detect_input_format(str(input_file)), "simple")

    def test_malformed_explicit_endpoint_reports_line(self):
        input_file = self.write("targets.txt", "example.com:not-a-port\n")
        with self.assertRaisesRegex(ValueError, r"targets\.txt:1: invalid port"):
            tls_auditor.detect_input_format(str(input_file))

    def test_ipv6_endpoint_round_trips(self):
        formatted = tls_auditor.format_host_port("2001:db8::15", "443")
        self.assertEqual(formatted, "[2001:db8::15]:443")
        self.assertEqual(
            tls_auditor.parse_host_port(formatted),
            ("2001:db8::15", "443"),
        )


class FindingAndMergeTests(TemporaryFileTestCase):
    def test_tls11_is_deprecated_and_reported_as_all(self):
        xml_file = self.write("tls11.xml", TLS11_NMAP_XML)

        self.assertTrue(
            tls_auditor.is_cipher_insecure("ANY_CIPHER", "A", "TLSv1.1")
        )
        results = tls_auditor.parse_nmap_xml(str(xml_file))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["TLSv1.1"], "All")

    def test_malformed_xml_raises(self):
        xml_file = self.write("broken.xml", "<nmaprun>")
        with self.assertRaises(ET.ParseError):
            tls_auditor.parse_nmap_xml(str(xml_file))

    def test_scan_jobs_preserve_host_port_pairs(self):
        targets = [
            {"ip": "a.example", "port": "443"},
            {"ip": "b.example", "port": "8443"},
            {"ip": "a.example", "port": "443"},
        ]
        self.assertEqual(
            tls_auditor.build_scan_jobs(targets),
            [("443", ["a.example"]), ("8443", ["b.example"])],
        )

    def test_xml_paths_are_unique_across_jobs_and_rounds(self):
        paths = {
            tls_auditor.scan_xml_path("audit", port, round_number, 2, 2)
            for port in ("443", "8443")
            for round_number in (1, 2)
        }
        self.assertEqual(
            paths,
            {
                "audit_port443_round1.xml",
                "audit_port443_round2.xml",
                "audit_port8443_round1.xml",
                "audit_port8443_round2.xml",
            },
        )

    def test_merge_result_row_handles_sentinels_and_deduplicates(self):
        existing = {
            "TLSv1.0": "All",
            "TLSv1.1": "-",
            "TLSv1.2": "CIPHER_B",
        }
        new = {
            "TLSv1.0": "CIPHER_IGNORED",
            "TLSv1.1": "All",
            "TLSv1.2": "CIPHER_A\nCIPHER_B",
        }

        tls_auditor.merge_result_row(existing, new)

        self.assertEqual(existing["TLSv1.0"], "All")
        self.assertEqual(existing["TLSv1.1"], "All")
        self.assertEqual(existing["TLSv1.2"], "CIPHER_A\nCIPHER_B")

    def test_cipher_csv_uses_shared_ipv6_endpoint_parser(self):
        csv_file = self.write(
            "audit.csv",
            'Host:Port,TLSv1.2\n"[2001:db8::20]:443",CIPHER_A\n',
        )

        results = tls_auditor.read_cipher_csv(str(csv_file))

        self.assertEqual(results[0]["ip"], "2001:db8::20")
        self.assertEqual(results[0]["port"], "443")


class CliOrchestrationTests(TemporaryFileTestCase):
    def run_main(self, arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["tls_auditor.py", *arguments]):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                tls_auditor.main()
        return stdout.getvalue(), stderr.getvalue()

    def test_simple_input_keeps_one_global_port_list(self):
        input_file = self.write("targets.txt", "b.example\na.example\n")
        output_prefix = self.root / "audit"
        calls = []

        def fake_run_nmap(input_file, ports, xml_output, timing=None):
            calls.append((Path(input_file).read_text().splitlines(), ports))
            Path(xml_output).write_text(EMPTY_NMAP_XML)
            return True

        with mock.patch.object(tls_auditor, "run_nmap", side_effect=fake_run_nmap):
            self.run_main(
                [
                    "-i",
                    str(input_file),
                    "-p",
                    "443,636",
                    "-o",
                    str(output_prefix),
                ]
            )

        self.assertEqual(calls, [(["a.example", "b.example"], "443,636")])

    def test_scan_uses_exact_jobs_and_cleans_temporary_files(self):
        input_file = self.write("targets.txt", "a.example:443\nb.example:8443\n")
        output_prefix = self.root / "audit"
        calls = []

        def fake_run_nmap(input_file, ports, xml_output, timing=None):
            calls.append(
                {
                    "input_file": input_file,
                    "hosts": Path(input_file).read_text().splitlines(),
                    "ports": ports,
                    "xml_output": xml_output,
                    "timing": timing,
                }
            )
            Path(xml_output).write_text(EMPTY_NMAP_XML)
            return True

        with mock.patch.object(tls_auditor, "run_nmap", side_effect=fake_run_nmap):
            self.run_main(["-i", str(input_file), "-o", str(output_prefix)])

        self.assertEqual(
            [(call["ports"], call["hosts"]) for call in calls],
            [("443", ["a.example"]), ("8443", ["b.example"])],
        )
        self.assertEqual(
            [Path(call["xml_output"]).name for call in calls],
            ["audit_port443.xml", "audit_port8443.xml"],
        )
        self.assertTrue(all(not Path(call["input_file"]).exists() for call in calls))
        self.assertTrue(all(not Path(call["xml_output"]).exists() for call in calls))

    def test_failed_port_group_exits_and_cleans_all_xml(self):
        input_file = self.write("targets.txt", "a.example:443\nb.example:8443\n")
        output_prefix = self.root / "audit"
        attempted_xml = []

        def fake_run_nmap(input_file, ports, xml_output, timing=None):
            attempted_xml.append(xml_output)
            Path(xml_output).write_text(
                EMPTY_NMAP_XML if ports == "443" else "partial"
            )
            return ports == "443"

        with mock.patch.object(tls_auditor, "run_nmap", side_effect=fake_run_nmap):
            with self.assertRaisesRegex(SystemExit, "1"):
                self.run_main(["-i", str(input_file), "-o", str(output_prefix)])

        self.assertTrue(all(not Path(path).exists() for path in attempted_xml))
        self.assertFalse(output_prefix.with_suffix(".csv").exists())

    def test_malformed_generated_xml_is_fatal_and_cleaned(self):
        input_file = self.write("targets.txt", "a.example:443\n")
        output_prefix = self.root / "audit"
        generated_xml = []

        def fake_run_nmap(input_file, ports, xml_output, timing=None):
            generated_xml.append(xml_output)
            Path(xml_output).write_text("<nmaprun>")
            return True

        with mock.patch.object(tls_auditor, "run_nmap", side_effect=fake_run_nmap):
            with self.assertRaisesRegex(SystemExit, "1"):
                self.run_main(["-i", str(input_file), "-o", str(output_prefix)])

        self.assertTrue(all(not Path(path).exists() for path in generated_xml))
        self.assertFalse(output_prefix.with_suffix(".csv").exists())

    def test_malformed_user_xml_is_fatal_but_not_removed(self):
        xml_file = self.write("broken.xml", "<nmaprun>")
        output_prefix = self.root / "audit"

        with self.assertRaisesRegex(SystemExit, "1"):
            self.run_main(["--xml", str(xml_file), "-o", str(output_prefix)])

        self.assertTrue(xml_file.exists())
        self.assertFalse(output_prefix.with_suffix(".csv").exists())

    def test_valid_user_xml_with_no_findings_succeeds_without_reports(self):
        xml_file = self.write("empty.xml", EMPTY_NMAP_XML)
        output_prefix = self.root / "audit"

        stdout, stderr = self.run_main(
            ["--xml", str(xml_file), "-o", str(output_prefix)]
        )

        self.assertIn("No SSL/TLS services with issues found", stdout)
        self.assertEqual(stderr, "")
        self.assertTrue(xml_file.exists())
        self.assertFalse(output_prefix.with_suffix(".csv").exists())


if __name__ == "__main__":
    unittest.main()
