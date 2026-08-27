# Shared serial helpers for the sensmos ESP8266 WiFi debug run.
# Port is resolved dynamically by USB VID:PID on EVERY invocation (FTDI 0403:6001) —
# never hardcode a COM number: FTDI re-enumerates after erase_flash / repeated resets.
import sys, time
import serial
import serial.tools.list_ports as lp

FTDI_VID = 0x0403
FTDI_PID = 0x6001
PREFERRED_SER = "A50285BIA"   # this board's FTDI serial (tiebreaker only)


def resolve_port(verbose=True):
    cands = []
    for p in lp.comports():
        if p.vid == FTDI_VID and p.pid == FTDI_PID:
            cands.append(p)
    if not cands:
        # description fallback (some drivers hide vid/pid)
        for p in lp.comports():
            d = (p.description or "") + " " + (p.hwid or "")
            if "FT232" in d or "FTDI" in d or "0403:6001" in d:
                cands.append(p)
    if not cands:
        raise RuntimeError("no FTDI 0403:6001 port found; ports=" +
                           ", ".join(p.device for p in lp.comports()))
    # prefer the known serial if present
    for p in cands:
        if PREFERRED_SER in (p.serial_number or "") or PREFERRED_SER in (p.hwid or ""):
            if verbose:
                print("[port] resolved %s (SER match)" % p.device)
            return p.device
    if verbose:
        print("[port] resolved %s (vid:pid match; %d candidate(s))" % (cands[0].device, len(cands)))
    return cands[0].device


def open_no_reset(port, baud):
    # Configure DTR/RTS de-asserted BEFORE open so opening the port does not pulse
    # the ESP8266 reset lines. Proven by cap.py --proof-noreset.
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = 0.2
    ser.dtr = False
    ser.rts = False
    ser.open()
    # some Windows FTDI drivers only honor the state after open — re-assert de-assert
    try:
        ser.dtr = False
        ser.rts = False
    except Exception:
        pass
    return ser


def pulse_reset(ser):
    # Run-mode reset (NOT flash/bootloader): EN low while GPIO0 stays high.
    # DTR=False -> GPIO0 high; RTS=True -> EN low (reset held); RTS=False -> boot.
    ser.dtr = False
    ser.rts = True
    time.sleep(0.1)
    ser.rts = False


def open_with_retry(port_hint, baud, do_reset, retries=6, verbose=True):
    # Bounded self-heal on the FTDI VCP exclusive-open teardown race (Access Denied right after a
    # prior close) and on port-busy/missing. Escalating backoff; re-resolve every attempt (the COM
    # number can move after erase_flash / re-enumerate). Keeps baud (device app baud is fixed 115200);
    # a lower-baud fallback only helps esptool sync, not app-log capture.
    attempt = 0
    last = None
    while attempt <= retries:
        try:
            port = resolve_port(verbose=verbose)   # re-resolve every attempt
            ser = open_no_reset(port, baud)
            if do_reset:
                pulse_reset(ser)
            return ser
        except Exception as e:
            last = e
            wait = min(1.0 + attempt * 1.0, 5.0)   # 1,2,3,4,5,5s
            if verbose:
                print("[port] open attempt %d failed: %s (retry in %.0fs)" % (attempt + 1, e, wait))
            time.sleep(wait)
            attempt += 1
    raise RuntimeError("could not open serial after %d attempts: %s" % (retries + 1, last))
