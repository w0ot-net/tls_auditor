# TLS Cipher Auditor

`tls_auditor.py` wraps Nmap's `ssl-enum-ciphers` and `sslv2` scripts and writes
CSV reports for services that offer deprecated protocols or insecure cipher
suites. It can scan target lists, parse an existing Nmap XML file, or merge
previous cipher-report CSVs.

Only scan systems you own or are explicitly authorized to assess.

## Requirements

- Python 3.8 or newer
- Nmap with the `ssl-enum-ciphers` and `sslv2` NSE scripts

No third-party Python packages are required.

```sh
python3 tls_auditor.py --help
```

## Input formats

Simple input contains one host per line and requires a global `-p` list. Every
listed port is scanned on every host.

```text
192.168.1.10
example.com
2001:db8::10
```

```sh
python3 tls_auditor.py -i hosts.txt -p 443,636
```

Host-port input supplies ports inline. If at least one line has an explicit
port, bare hosts in the same file default to 443. IPv6 addresses with explicit
ports must use brackets; bare IPv6 addresses must not.

```text
192.168.1.10:443
example.com:8443
[2001:db8::10]:9443
bare.example.com
2001:db8::20
```

```sh
python3 tls_auditor.py -i endpoints.txt
```

Rich input uses an IP, hostname, and service description separated by tabs or
two or more spaces. The port is read from the final `(port/tcp)` value.

```text
172.16.1.10    ad02.example.com    ldaps (636/tcp)
172.16.1.41    web.example.com     www (443/tcp)
172.16.1.42    -                   https (8443/tcp)
```

```sh
python3 tls_auditor.py -i rich-targets.txt
```

Rich and host-port inputs retain the supplied host/port pairs. Internally,
hosts are grouped by port, so the example above does not cause every port to be
scanned on every host. This can require more than one Nmap invocation.

## Other modes

Parse an existing Nmap XML file without scanning:

```sh
python3 tls_auditor.py --xml existing-scan.xml -o results
```

Merge cipher-report CSVs produced by this tool:

```sh
python3 tls_auditor.py --merge scan1.csv scan2.csv -o combined
```

Run each requested scan up to three times and aggregate successful findings:

```sh
python3 tls_auditor.py -i endpoints.txt --rounds 3 -T 4
```

`--rounds` accepts 1 through 10. A port group must complete successfully at
least once; otherwise the command fails instead of reporting partial coverage
as complete. `-T` accepts Nmap timing templates 0 through 5.

## Output

By default, scan output uses the prefix `ssl_audit_YYYYMMDD_HHMMSS`. `-o`
selects another prefix; a trailing `.csv` is removed before suffixes are added.

- `<prefix>.csv` contains `Host:Port` plus only the protocol columns that have
  findings. Multiple cipher names occupy separate lines within a CSV cell.
- `<prefix>_affected.csv` contains IP, hostname, and `service (port/tcp)` rows
  without a header, matching the rich input shape.

Reports are written only when findings exist. A valid scan with no findings
prints a clean summary and does not create empty CSV reports. Unreadable or
malformed XML is an error and never counts as a clean result.

Nmap XML is removed after parsing unless `--keep-xml` is used. A single
job/round uses `<prefix>.xml`; multiple rounds use `_roundN`, multiple port
groups use `_portPORT`, and both suffixes are used when necessary.
User-supplied `--xml` files are never removed.

## Finding policy

The auditor reports:

- all ciphers when SSLv2, SSLv3, TLS 1.0, or TLS 1.1 is present (`All` in the
  CSV), consistent with [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996.html)
  for TLS 1.0 and TLS 1.1;
- ciphers graded B through F by `ssl-enum-ciphers`;
- CBC suites; and
- known RC4, DES, 3DES, NULL-encryption, and anonymous-key-exchange suites
  listed in the script.

This is a focused protocol/cipher audit, not a complete TLS assessment. It does
not evaluate certificate trust or expiry, key sizes, application headers, or
every possible server-specific weakness. Its static policy should be reviewed
when organizational requirements or cryptographic guidance change.

## Tests

The regression suite uses only the Python standard library and mocks Nmap; it
does not contact network targets.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```
