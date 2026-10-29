"""Coverage tests for tools/binary_analyzer.py and tools/kali_capture.py.

Binary analysis runs against in-memory crafted PE/ELF byte buffers; capture
runs against a fake Kali executor. No real binaries, tcpdump, tshark or
network access.

源码侧历史缺陷已修复并在此固化正确行为:
  * _calc_entropy 改为标准 Shannon 熵
  * 截断的可选头不再触发 UnboundLocalError
  * packer 名称按 bytes 比较
  * ELF e_phoff 按 32/64 位规范偏移读取
"""

import json
import struct
from unittest import mock

import pytest

from tools import binary_analyzer as ba
from tools import kali_capture as kc

# ---------------------------------------------------------------------------
# binary_analyzer helpers
# ---------------------------------------------------------------------------


def build_pe(machine=0x14C, num_sections=1, extra=b"", magic=0x10B):
    pe_off = 0x80
    opt_size = 0xE0
    buf = bytearray(b"\x00" * 2048)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 60, pe_off)
    buf[pe_off : pe_off + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, pe_off + 4, machine)
    struct.pack_into("<H", buf, pe_off + 6, num_sections)
    struct.pack_into("<H", buf, pe_off + 20, opt_size)
    struct.pack_into("<H", buf, pe_off + 22, 0x0102 | 0x0040 | 0x0020)
    opt = pe_off + 24
    struct.pack_into("<H", buf, opt, magic)
    struct.pack_into("<I", buf, opt + 56, 0x4000)
    struct.pack_into("<I", buf, opt + 60, 0x400)
    struct.pack_into("<I", buf, opt + 68, 0x100000)
    sec = pe_off + 24 + opt_size
    buf[sec : sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", buf, sec + 8, 0x200)
    struct.pack_into("<I", buf, sec + 12, 0x1000)
    struct.pack_into("<I", buf, sec + 16, 0x200)
    struct.pack_into("<I", buf, sec + 20, 0x400)
    struct.pack_into("<I", buf, sec + 36, 0x60000020)
    buf[0x600 : 0x600 + len(extra)] = extra
    return bytes(buf)


def build_elf64(flags=0, extra=b""):
    buf = bytearray(b"\x00" * 512)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2  # 64-bit
    buf[5] = 1
    buf[6] = 1
    buf[7] = 3  # Linux
    struct.pack_into("<Q", buf, 32, 64)  # e_phoff (ELF64: 偏移 32)
    struct.pack_into("<H", buf, 56, 1)
    struct.pack_into("<I", buf, 64, 2)  # PT_LOAD
    struct.pack_into("<I", buf, 68, flags)
    buf[128 : 128 + len(extra)] = extra
    return bytes(buf)


def build_elf32():
    buf = bytearray(b"\x00" * 512)
    buf[0:4] = b"\x7fELF"
    buf[4] = 1  # 32-bit
    buf[5] = 1
    buf[6] = 1
    buf[7] = 0  # System V
    struct.pack_into("<I", buf, 28, 52)
    struct.pack_into("<H", buf, 44, 0)
    return bytes(buf)


def make_analyzer(paths=None):
    return ba.BinaryAnalyzer(paths or [], threads=1)


def patch_entropy(monkeypatch, value=0.0):
    monkeypatch.setattr(ba.BinaryAnalyzer, "_calc_entropy", lambda self, data: value)


# ---------------------------------------------------------------------------
# pure logic
# ---------------------------------------------------------------------------


def test_calc_entropy_empty_is_zero():
    assert make_analyzer()._calc_entropy(b"") == 0.0


def test_calc_entropy_shannon():
    # 修复: 标准 Shannon 熵 (此前 float.bit_length() 直接崩溃)
    assert make_analyzer()._calc_entropy(b"hello world") == pytest.approx(2.8454, abs=0.001)
    assert make_analyzer()._calc_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_extract_strings_min_length_and_offsets():
    data = b"\x00ab\x00hello world\x00hi\x00"
    strings = make_analyzer()._extract_strings(data, min_len=6)
    assert strings == [{"text": "hello world", "offset": 4}]


def test_extract_strings_truncates_long_strings():
    strings = make_analyzer()._extract_strings(b"A" * 300, min_len=6)
    assert len(strings[0]["text"]) == 200


def test_to_dict_truncates_suspicious_imports():
    info = ba.BinaryInfo(filepath="x", file_size=1)
    info.suspicious_imports = ["i%d" % i for i in range(15)]
    d = info.to_dict()
    assert len(d["suspicious_imports"]) == 10
    assert d["string_count"] == 0
    assert d["entropy"] == 0.0


# ---------------------------------------------------------------------------
# PE parsing
# ---------------------------------------------------------------------------

PE_STRINGS = b"kernel32.dll\x00CreateRemoteThread\x00cmd -e\x00http://10.0.0.1/x\x00UPX\x00"


def test_check_pe_full_parse(monkeypatch):
    patch_entropy(monkeypatch, 1.23)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    info = make_analyzer()._check_pe("t.exe", build_pe(extra=PE_STRINGS))
    assert info.format_type == "PE"
    assert info.arch == "x86"
    assert info.os_type == "Windows"
    assert info.protections["executable"] is True
    assert info.protections["aslr"] is True
    assert info.protections["nx"] is True
    assert info.protections["size_of_headers"] == 1024
    assert info.protections["image_size"] == 16384
    assert info.sections == [
        {
            "name": ".text",
            "virtual_size": 512,
            "virtual_address": "0x1000",
            "raw_size": 512,
            "raw_offset": "0x400",
            "executable": True,
            "writable": False,
        }
    ]
    assert info.suspicious_imports == ["kernel32.dll!CreateRemoteThread"]
    labels = {s["label"] for s in info.strings_found}
    assert "shell_command" in labels
    assert "hardcoded_ip_url" in labels
    assert info.entropy == 1.23


def test_check_pe_x64_machine(monkeypatch):
    patch_entropy(monkeypatch)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    info = make_analyzer()._check_pe("t.exe", build_pe(machine=0x8664))
    assert info.arch == "x64"


def test_check_pe_unknown_machine(monkeypatch):
    patch_entropy(monkeypatch)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    info = make_analyzer()._check_pe("t.exe", build_pe(machine=0x9999))
    assert info.arch == "unknown"


def test_check_pe_packer_detection(monkeypatch):
    patch_entropy(monkeypatch)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", ["UPX"])
    info = make_analyzer()._check_pe("t.exe", build_pe(extra=b"UPX\x00" + PE_STRINGS))
    assert info.is_packed is True
    assert info.protections["packer"] == "UPX"


def test_check_pe_real_packer_loop_detects_upx(monkeypatch):
    # 修复: str packer 名称按 bytes 查找, 真实 KNOWN_PACKERS 正常工作
    patch_entropy(monkeypatch)
    info = make_analyzer()._check_pe("t.exe", build_pe(extra=b"UPX\x00" + PE_STRINGS))
    assert info.is_packed is True
    assert info.protections["packer"] == "UPX"


def test_check_pe_too_short_returns_partial_info():
    info = make_analyzer()._check_pe("t.exe", b"MZ" + b"\x00" * 30)
    assert info.format_type == "PE"
    assert info.arch == ""


def test_check_pe_bad_signature(monkeypatch):
    data = bytearray(build_pe())
    data[0x80:0x84] = b"XX\x00\x00"
    info = make_analyzer()._check_pe("t.exe", bytes(data))
    assert info.arch == ""


def test_check_pe_pe_offset_out_of_range():
    buf = bytearray(b"\x00" * 128)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 60, 0xFFFF)
    info = make_analyzer()._check_pe("t.exe", bytes(buf))
    assert info.arch == ""


def test_check_pe_truncated_optional_header_is_safe():
    # 修复: 可选头截断不再使用未赋值的 magic, 返回已解析部分
    buf = bytearray(b"\x00" * 125)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 60, 100)
    buf[100:104] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 104, 0x14C)
    struct.pack_into("<H", buf, 106, 1)
    struct.pack_into("<H", buf, 122, 0x0102)
    info = make_analyzer()._check_pe("t.exe", bytes(buf))
    assert info.arch == "x86"
    assert "size_of_headers" not in info.protections


# ---------------------------------------------------------------------------
# ELF parsing
# ---------------------------------------------------------------------------


def test_check_elf64_parses_header_and_segments():
    info = make_analyzer()._check_elf("t", build_elf64())
    assert info.format_type == "ELF"
    assert info.arch == "x64"
    assert info.os_type == "Linux"
    assert info.protections["nx"] is True


def test_check_elf32_parses_header():
    info = make_analyzer()._check_elf("t", build_elf32())
    assert info.format_type == "ELF"
    assert info.arch == "x86"
    assert info.os_type == "System V"


def test_check_elf_truncated_is_safe():
    info = make_analyzer()._check_elf("t", b"\x7fELF\x02\x01\x01\x03")
    assert info.format_type == "ELF"


# ---------------------------------------------------------------------------
# file dispatch / scan
# ---------------------------------------------------------------------------


def test_analyze_file_pe_works_in_production(monkeypatch, tmp_path):
    # 修复: entropy 正常计算, PE 文件不再恒返回 None
    p = tmp_path / "a.exe"
    p.write_bytes(build_pe(extra=PE_STRINGS))
    result = make_analyzer()._analyze_file(str(p))
    assert result["format"] == "PE"
    assert result["suspicious_imports"] == ["kernel32.dll!CreateRemoteThread"]


def test_analyze_file_pe_with_patched_entropy(monkeypatch, tmp_path):
    patch_entropy(monkeypatch)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    p = tmp_path / "a.exe"
    p.write_bytes(build_pe(extra=PE_STRINGS))
    result = make_analyzer()._analyze_file(str(p))
    assert result["format"] == "PE"
    assert result["suspicious_imports"] == ["kernel32.dll!CreateRemoteThread"]


def test_analyze_file_too_short(tmp_path):
    p = tmp_path / "tiny.bin"
    p.write_bytes(b"MZ")
    assert make_analyzer()._analyze_file(str(p)) is None


def test_analyze_file_unknown_extension(tmp_path):
    p = tmp_path / "data.dat"
    p.write_bytes(b"not a binary at all")
    assert make_analyzer()._analyze_file(str(p)) is None


def test_analyze_file_mz_with_bin_extension(monkeypatch, tmp_path):
    patch_entropy(monkeypatch)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    p = tmp_path / "payload.bin"
    p.write_bytes(build_pe())
    assert make_analyzer()._analyze_file(str(p))["format"] == "PE"


def test_analyze_file_elf_dispatch(tmp_path):
    # 修复: ELF 分发不再因 struct.error 返回 None
    p = tmp_path / "lib.elf"
    p.write_bytes(build_elf64())
    assert make_analyzer()._analyze_file(str(p))["format"] == "ELF"


def test_analyze_file_extension_fallback_to_pe(monkeypatch, tmp_path):
    patch_entropy(monkeypatch)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    p = tmp_path / "fake.exe"
    p.write_bytes(b"not a real binary, just text" * 4)
    result = make_analyzer()._analyze_file(str(p))
    assert result["format"] == "PE"
    assert result["arch"] == ""


def test_analyze_file_io_error(tmp_path):
    assert make_analyzer()._analyze_file(str(tmp_path)) is None


def test_scan_directory_filters_and_aggregates(monkeypatch, tmp_path):
    patch_entropy(monkeypatch)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    (tmp_path / "a.exe").write_bytes(build_pe(extra=PE_STRINGS))
    (tmp_path / "b.txt").write_bytes(b"not binary")
    (tmp_path / "c.dll").write_bytes(build_pe())
    sub = tmp_path / "node_modules"
    sub.mkdir()
    (sub / "ignored.exe").write_bytes(build_pe())
    result = ba.run_binary_scan([str(tmp_path)], threads=2)
    assert result["files_scanned"] == 2
    assert result["binaries_analyzed"] == 2
    assert result["suspicious_count"] == 1
    assert result["summary"]["has_suspicious_imports"] == 1
    assert result["summary"]["packed"] == 0
    assert len(result["suspicious"]) == 1


def test_scan_direct_file_path(monkeypatch, tmp_path):
    patch_entropy(monkeypatch)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    p = tmp_path / "one.exe"
    p.write_bytes(build_pe())
    result = make_analyzer([str(p)]).scan()
    assert result["files_scanned"] == 1
    assert result["binaries_analyzed"] == 1


def test_scan_missing_path_yields_nothing(tmp_path):
    result = make_analyzer([str(tmp_path / "missing")]).scan()
    assert result["files_scanned"] == 0
    assert result["binaries"] == []


def test_scan_high_entropy_summary(monkeypatch, tmp_path):
    patch_entropy(monkeypatch, 7.9)
    monkeypatch.setattr(ba, "KNOWN_PACKERS", [])
    p = tmp_path / "packed.exe"
    p.write_bytes(build_pe())
    result = make_analyzer([str(p)]).scan()
    assert result["summary"]["high_entropy"] == 1


# ---------------------------------------------------------------------------
# kali_capture
# ---------------------------------------------------------------------------


class FakeKali:
    def __init__(self):
        self.calls = []
        self.queue = []

    def run(self, cmd, timeout=120):
        self.calls.append({"cmd": cmd, "timeout": timeout})
        if self.queue:
            return self.queue.pop(0)
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}


@pytest.fixture
def cap(monkeypatch):
    fk = FakeKali()
    monkeypatch.setattr(kc, "get_kali", lambda: fk)
    return kc.KaliCapture(local=False), fk


def ok(stdout="", success=True):
    return {"success": success, "exit_code": 0 if success else 1, "stdout": stdout, "stderr": ""}


# resolve_interface ---------------------------------------------------------


def test_resolve_interface_ip_route(monkeypatch):
    with mock.patch(
        "subprocess.run",
        return_value=mock.Mock(stdout="default via 10.0.0.1 dev eth1 proto dhcp", returncode=0),
    ):
        assert kc.resolve_interface() == "eth1"


def test_resolve_interface_route_n_fallback(monkeypatch):
    first = mock.Mock(stdout="garbage output", returncode=0)
    second = mock.Mock(stdout="   route to: default\n  interface: wlan0\n", returncode=0)
    with mock.patch("subprocess.run", side_effect=[first, second]):
        assert kc.resolve_interface() == "wlan0"


def test_resolve_interface_default(monkeypatch):
    with mock.patch("subprocess.run", side_effect=OSError("no ip tool")):
        assert kc.resolve_interface() == "eth0"


def test_resolve_interface_empty_output(monkeypatch):
    with mock.patch("subprocess.run", return_value=mock.Mock(stdout="", returncode=0)):
        assert kc.resolve_interface() == "eth0"


# _install_tshark_json_deps -------------------------------------------------


def test_install_tshark_local_present():
    with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)):
        assert kc._install_tshark_json_deps(None, local=True) is True


def test_install_tshark_local_missing():
    with mock.patch("subprocess.run", return_value=mock.Mock(returncode=1)):
        assert kc._install_tshark_json_deps(None, local=True) is False


def test_install_tshark_remote():
    fk = FakeKali()
    fk.queue = [ok("tshark 4.0")]
    assert kc._install_tshark_json_deps(fk, local=False) is True
    fk.queue = [ok("", success=False)]
    assert kc._install_tshark_json_deps(fk, local=False) is False


# capture -------------------------------------------------------------------

JSON_PACKETS = json.dumps(
    [
        {
            "_index": "p1",
            "_source": {
                "layers": {
                    "frame.protocols": "eth:ip:tcp:http",
                    "ip.src": "10.0.0.1",
                    "ip.dst": "10.0.0.2",
                    "http.request.method": "GET",
                    "http.response.code": "200",
                }
            },
        },
        {
            "_index": "p2",
            "_source": {
                "layers": {
                    "frame.protocols": "eth:ip:tcp:tls",
                    "ip.src": ["10.0.0.3"],
                    "ip.dst": ["10.0.0.2"],
                    "tls.record.content.type": "22",
                }
            },
        },
    ]
)

PDML = (
    "<pdml><packet><proto name='ip'><field name='ip.src' show='1.2.3.4'/>"
    "</proto><proto name='tcp'><field name='tcp.srcport' show='80'/></proto>"
    "</packet></pdml>"
)


def test_capture_full_flow(cap):
    capture, fk = cap
    fk.queue = [
        ok("tshark 4.0"),  # which tshark
        ok(""),  # tcpdump
        ok("file\n1234"),  # _check_pcap
        ok(JSON_PACKETS),  # tshark -T json
    ]
    r = capture.capture(interface="eth0", count=10, bpf_filter="tcp port 80", timeout=5)
    assert r["success"] is True
    assert r["total_packets"] == 2
    assert r["pcap"].startswith("/tmp/aimy_cap_")
    assert r["summary"]["http_requests"] == 1
    assert r["summary"]["http_responses"] == 1
    assert r["summary"]["tls_handshakes"] == 1
    assert set(r["summary"]["unique_src_ips"]) == {"10.0.0.1", "10.0.0.3"}
    assert fk.calls[1]["cmd"].endswith("tcp port 80")
    assert "-c 10" in fk.calls[1]["cmd"]
    assert fk.calls[1]["timeout"] == 35


def test_capture_pdml_fallback(cap):
    capture, fk = cap
    fk.queue = [
        ok("tshark"),
        ok(""),
        ok("file\n1234"),
        ok("", success=False),
        ok(PDML),
    ]
    r = capture.capture(interface="eth0")
    assert r["success"] is True
    assert r["total_packets"] == 1
    assert r["packets"][0]["ip.ip.src"] == "1.2.3.4"


def test_capture_requires_tshark(cap):
    capture, fk = cap
    fk.queue = [ok("", success=False)]
    r = capture.capture(interface="eth0")
    assert r["success"] is False
    assert r["error"] == "tshark not available on Kali"


def test_capture_empty_pcap(cap):
    capture, fk = cap
    fk.queue = [ok("tshark"), ok(""), ok("file\n50")]
    r = capture.capture(interface="eth0")
    assert r["success"] is False
    assert r["error"] == "pcap file not created or empty"


def test_capture_continues_after_tcpdump_failure(cap):
    capture, fk = cap
    fk.queue = [
        ok("tshark"),
        ok("", success=False),
        ok("file\n999"),
        ok(JSON_PACKETS),
    ]
    r = capture.capture(interface="eth0")
    assert r["success"] is True


def test_capture_uses_resolved_interface_and_default_output(cap, monkeypatch):
    capture, fk = cap
    monkeypatch.setattr(kc, "resolve_interface", lambda: "eth9")
    fk.queue = [ok("tshark"), ok(""), ok("f\n200"), ok(JSON_PACKETS)]
    capture.capture()
    assert "-i eth9" in fk.calls[1]["cmd"]
    assert "/tmp/aimy_cap_" in fk.calls[1]["cmd"]


def test_capture_http_and_https_filters(monkeypatch):
    captured = {}

    def fake_capture(self, **kwargs):
        captured.update(kwargs)
        return {"success": True}

    monkeypatch.setattr(kc.KaliCapture, "capture", fake_capture)
    instance = kc.KaliCapture(local=False)
    instance.capture_http(count=7)
    assert captured["bpf_filter"] == "tcp port 80 or tcp port 8080"
    assert captured["count"] == 7
    instance.capture_https()
    assert captured["bpf_filter"] == "tcp port 443"


def test_live_http_parses_fields(cap):
    capture, fk = cap
    fk.queue = [
        ok("tshark"),
        ok(
            '1.5|10.0.0.1|10.0.0.2|1234|80|"GET"|"/index"|"200"|"example.com"\n'
            "2.0|10.0.0.1|10.0.0.2|1234|80\n"
            "short|line\n"
        ),
    ]
    entries = capture.live_http(interface="eth0", max_packets=5, timeout=3)
    assert entries[0] == {
        "time": "1.5",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": "1234",
        "dport": "80",
        "method": "GET",
        "uri": "/index",
        "status": "200",
        "host": "example.com",
    }
    assert entries[1] == {
        "time": "2.0",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": "1234",
        "dport": "80",
    }


def test_live_http_without_tshark(cap):
    capture, fk = cap
    fk.queue = [ok("", success=False)]
    assert capture.live_http(interface="eth0") == []


def test_live_http_run_failure(cap):
    capture, fk = cap
    fk.queue = [ok("tshark"), ok("", success=False)]
    assert capture.live_http(interface="eth0") == []


def test_live_http_uses_resolved_interface(cap, monkeypatch):
    capture, fk = cap
    monkeypatch.setattr(kc, "resolve_interface", lambda: "eth7")
    fk.queue = [ok("tshark"), ok("")]
    capture.live_http()
    assert "-i eth7" in fk.calls[1]["cmd"]


# parsing helpers -----------------------------------------------------------


def test_check_pcap_variants(cap):
    capture, fk = cap
    fk.queue = [ok("file\n123")]
    assert capture._check_pcap("/tmp/x.pcap") is True
    fk.queue = [ok("file\nabc")]
    assert capture._check_pcap("/tmp/x.pcap") is False
    fk.queue = [ok("", success=False)]
    assert capture._check_pcap("/tmp/x.pcap") is False


def test_parse_packets_variants(cap):
    capture, _ = cap
    assert capture._parse_packets("") == []
    assert capture._parse_packets("[]") == []
    assert capture._parse_packets('{"not": "a list"}') == []
    assert capture._parse_packets("plain line 1\nline 2") == [
        {"index": 0, "raw": "plain line 1"},
        {"index": 1, "raw": "line 2"},
    ]
    pdml = capture._parse_packets(PDML)
    assert pdml[0]["index"] == 0
    assert pdml[0]["ip.ip.src"] == "1.2.3.4"


def test_parse_fallback_limits_to_500(cap):
    capture, _ = cap
    packets = capture._parse_fallback("\n".join(str(i) for i in range(600)))
    assert len(packets) == 500


def test_flatten_packet_types(cap):
    capture, _ = cap
    flat = capture._flatten_packet(
        {
            "_index": "i1",
            "_source": {
                "layers": {
                    "http.request.uri": ["/a", "/b"],
                    "tcp.payload": {"x": 1},
                    "ip.src": "1.1.1.1",
                    "empty.list": [],
                }
            },
        }
    )
    assert flat["index"] == "i1"
    assert flat["http.request.uri"] == "/a"
    assert json.loads(flat["tcp.payload"]) == {"x": 1}
    assert flat["ip.src"] == "1.1.1.1"
    assert flat["empty.list"] == ""


def test_parse_pdml_bad_xml(cap):
    capture, _ = cap
    assert capture._parse_pdml("<not-closed") == []


def test_summarize_counts(cap):
    capture, _ = cap
    packets = [
        {
            "frame.protocols": "eth:ip:tcp:http",
            "ip.src": "1.1.1.1",
            "ip.dst": "2.2.2.2",
            "http.request.method": "GET",
        },
        {"frame.protocols": "eth:ip:tcp:http", "ip.src": "1.1.1.1", "http.response.code": "200"},
        {"tls.record.content.type": "22"},
    ]
    summary = capture._summarize(packets)
    assert summary["http_requests"] == 1
    assert summary["http_responses"] == 1
    assert summary["tls_handshakes"] == 1
    assert summary["unique_src_ips"] == ["1.1.1.1"]
    assert summary["unique_dst_ips"] == ["2.2.2.2"]
    assert summary["protocols"] == {"eth:ip:tcp:http": 2, "unknown": 1}


def test_kali_capture_local_flag_and_tag():
    instance = kc.KaliCapture(local=True)
    assert instance.local is True
    assert len(instance._tag) == 8
