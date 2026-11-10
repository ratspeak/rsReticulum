#!/usr/bin/env python3
"""USB serial setup golden from usbserial4a 0.4.0, the driver library upstream
RNS 1.6.0 uses for Android USB serial (RNS/Interfaces/Android/*Interface.py,
`from usbserial4a import serial4a`). Each driver is opened against a stubbed
Android USB stack and every controlTransfer it issues is recorded.

The usbserial4a tree is RATSPEAK_USBSERIAL4A_DIR if set; otherwise the sdist
is fetched with pip into a temporary directory.

Run: python3 generate.py [out.json]   (default: cases.json next to this file)
"""
import json, os, subprocess, sys, tarfile, tempfile, types
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "cases.json")
VERSION = "0.4.0"

src = os.environ.get("RATSPEAK_USBSERIAL4A_DIR")
if not src:
    tmp = tempfile.mkdtemp()
    subprocess.check_call([sys.executable, "-m", "pip", "download", "-q", "--no-deps", "--no-binary", ":all:",
                           "-d", tmp, f"usbserial4a=={VERSION}"])
    with tarfile.open(os.path.join(tmp, f"usbserial4a-{VERSION}.tar.gz")) as t:
        t.extractall(tmp, filter="data")
    src = os.path.join(tmp, f"usbserial4a-{VERSION}")

class UsbConstants:
    USB_DIR_IN = 0x80; USB_DIR_OUT = 0x00; USB_TYPE_VENDOR = 0x40; USB_TYPE_CLASS = 0x20
    USB_ENDPOINT_XFER_BULK = 2; USB_ENDPOINT_XFER_INT = 3; USB_CLASS_COMM = 2; USB_CLASS_CDC_DATA = 0x0A

class Endpoint:
    def __init__(s, d, t, mps=64): s.d, s.t, s.mps = d, t, mps
    def getDirection(s): return s.d
    def getType(s): return s.t
    def getMaxPacketSize(s): return s.mps

class Interface:
    def __init__(s, number, cls, eps): s.number, s.cls, s.eps = number, cls, eps
    def getId(s): return s.number
    def getInterfaceClass(s): return s.cls
    def getEndpointCount(s): return len(s.eps)
    def getEndpoint(s, i): return s.eps[i]

class Device:
    def __init__(s, vid, pid, ifaces, bcd=0x0600): s.vid, s.pid, s.ifaces, s.bcd = vid, pid, ifaces, bcd
    def getVendorId(s): return s.vid
    def getProductId(s): return s.pid
    def getInterfaceCount(s): return len(s.ifaces)
    def getInterface(s, i): return s.ifaces[i]

class Connection:
    def __init__(s, device): s.device = device; s.log = []
    def getRawDescriptors(s):
        d = bytearray(18); d[12] = s.device.bcd & 0xFF; d[13] = s.device.bcd >> 8; return d
    def claimInterface(s, iface, force): return True
    def controlTransfer(s, rt, req, value, index, buf, length, timeout):
        # jnius hands Java an int; usbserial4a passes a float SET_BAUDDIV value.
        s.log.append([rt, req, int(value) & 0xFFFF, index & 0xFFFF, bytes(buf[:length]).hex() if buf is not None and not rt & 0x80 else "", length])
        if rt & 0x80:
            if req == 0x95 and value == 0x0706: buf[0:2] = bytes([0x9F, 0xEE])
            return length
        return 0 if length == 0 else length
    def close(s): pass

CURRENT = {}
usb = types.ModuleType("usb4a.usb")
usb.UsbConstants = UsbConstants
usb.USB_RECIPIENT_DEVICE = 0x00
usb.build_usb_control_request_type = lambda d, t, r: d | t | r
usb.get_usb_device = lambda name: CURRENT["device"]
usb.has_usb_permission = lambda d: True
usb.get_usb_manager = lambda: types.SimpleNamespace(openDevice=lambda d: CURRENT.setdefault("conn", Connection(d)))
usb.USBError = IOError
pkg = types.ModuleType("usb4a"); pkg.usb = usb
sys.modules["usb4a"] = pkg; sys.modules["usb4a.usb"] = usb
sys.path.insert(0, src)
from usbserial4a import serial4a, __version__
from usbserial4a.cdcacmserial4a import CdcAcmSerial
assert __version__ == VERSION, __version__

BULK = lambda: [Endpoint(0x80, 2), Endpoint(0x00, 2)]
DEVICES = {
    "ftdi_ft232r": lambda: Device(0x0403, 0x6001, [Interface(0, 0xFF, BULK())], bcd=0x0600),
    "ftdi_ft2232h": lambda: Device(0x0403, 0x6010, [Interface(0, 0xFF, BULK())], bcd=0x0700),
    "ch340": lambda: Device(0x1A86, 0x7523, [Interface(0, 0xFF, [Endpoint(0x80, 3)] + BULK())]),
    "ch9102_forced_cdc": lambda: Device(0x1A86, 0x55D4, [Interface(0, 2, [Endpoint(0x80, 3)]), Interface(1, 0x0A, BULK())]),
}
# Line settings the Android interfaces pass: speed, databits, parity "N"/"E"/"O", stopbits.
LINES = [(115200, 8, "N", 1), (9600, 8, "N", 1), (57600, 7, "E", 2), (1200, 8, "O", 1)]

cases = []
for name, make in DEVICES.items():
    for baud, bits, parity, stop in LINES:
        CURRENT.clear(); CURRENT["device"] = make()
        # Upstream forces the CDC driver for 1a86:55d4 (Android/*Interface.py open_port).
        cls = CdcAcmSerial if name == "ch9102_forced_cdc" else serial4a.get_serial_port
        try:
            port = cls("dev", baudrate=baud, bytesize=bits, parity=parity, stopbits=stop,
                       xonxoff=False, rtscts=False, timeout=None, dsrdtr=False)
            cases.append({"device": name, "vid": CURRENT["device"].vid, "pid": CURRENT["device"].pid,
                          "bcd": CURRENT["device"].bcd, "driver": type(port).__name__,
                          "baud": baud, "databits": bits, "parity": parity, "stopbits": stop,
                          "requests": CURRENT["conn"].log})
        except Exception as e:
            cases.append({"device": name, "baud": baud, "databits": bits, "parity": parity, "stopbits": stop, "error": str(e)})

head = {"generator": "crates/rns-interface/tests/fixtures/android_usb_serial/generate.py", "usbserial4a_version": VERSION,
        "request_fields": ["request_type", "request", "value", "index", "payload_hex", "length"]}
with open(OUT, "w") as f:
    f.write("{\n" + ",\n".join(f" {json.dumps(k)}: {json.dumps(v)}" for k, v in head.items()))
    f.write(',\n "cases": [\n' + ",\n".join("  " + json.dumps(c, separators=(",", ":")) for c in cases) + "\n ]\n}\n")
print("wrote", len(cases), "cases")
