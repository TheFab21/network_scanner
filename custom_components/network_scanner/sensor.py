
import logging
import nmap
import re
import socket
from datetime import timedelta
from homeassistant.helpers.entity import Entity
from .const import DOMAIN

SCAN_INTERVAL = timedelta(minutes=15)

_LOGGER = logging.getLogger(__name__)

class NetworkScanner(Entity):
    """Representation of a Network Scanner."""

    def __init__(self, hass, ip_range, mac_mapping):
        """Initialize the sensor."""
        self._state = None
        self.hass = hass
        self.ip_range = ip_range

        _LOGGER.debug("mac_mapping unparsed: %s", mac_mapping)
        self.mac_mapping = self.parse_mac_mapping(mac_mapping)
        _LOGGER.debug("mac_mapping parsed: %s", mac_mapping)

        self.nm = nmap.PortScanner()
        _LOGGER.info("Network Scanner initialized")


    # ---------------------- helpers (Option A) ----------------------
    @staticmethod
    def _short_label(name: str) -> str | None:
        """Return lowercase host label before first dot, cleaned, or None."""
        if not name:
            return None
        short = name.strip().rstrip(".").split(".", 1)[0].lower()
        short = re.sub(r"[^a-z0-9_-]", "", short)
        return short or None

    @staticmethod
    def _fast_rdns(ip: str, timeout: float = 0.3) -> str | None:
        """Reverse-DNS with a very short timeout; returns cleaned short label or None."""
        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return NetworkScanner._short_label(host)
        except Exception:
            return None
        finally:
            # restore previous default timeout to avoid impacting HA internals
            socket.setdefaulttimeout(old_to)


    @property
    def should_poll(self):
        """Return True as updates are needed via polling."""
        return True

    @property
    def unique_id(self):
        """Return unique ID."""
        return f"network_scanner_{self.ip_range}"

    @property
    def name(self):
        return 'Network Scanner'

    @property
    def state(self):
        return self._state

    @property
    def unit_of_measurement(self):
        return 'Devices'

    async def async_update(self):
        """Fetch new state data for the sensor."""
        try:
            _LOGGER.debug("Scanning network")
            devices = await self.hass.async_add_executor_job(self.scan_network)
            self._state = len(devices)
            self._attr_extra_state_attributes = {"devices": devices}
        except Exception as e:
            _LOGGER.error("Error updating network scanner: %s", e)

    def parse_mac_mapping(self, mapping_string):
        """Parse the MAC mapping string into a dictionary."""
        mapping = {}
        for line in mapping_string.split('\n'):
            parts = line.split(';')
            if len(parts) >= 3:
                mapping[parts[0].lower()] = (parts[1], parts[2])
        return mapping

    def get_device_info_from_mac(self, mac_address):
        """Retrieve device name and type from the MAC mapping."""
        return self.mac_mapping.get(mac_address.lower(), ("Unknown Device", "Unknown Device"))

    def scan_network(self):
        """Scan the network and return device information.
        Option A: fast discovery with -n, then resolve only active hosts with short timeout.
        """
        # Fast discovery: no DNS (-n), TCP SYN pings on common ports, aggressive timing
        # Adjust --min-rate to taste; keep it conservative for NAS CPUs
        args = '-sn -n -T4 --min-rate 800'
        try:
            self.nm.scan(hosts=self.ip_range, arguments=args)
        except Exception as e:
            _LOGGER.error("nmap scan failed with args '%s': %s", args, e)
            return []

        devices = []

        for host in self.nm.all_hosts():
            try:
                addrs = self.nm[host].get('addresses', {})
                if 'mac' not in addrs or 'ipv4' not in addrs:
                    continue

                ip = addrs['ipv4']
                mac = addrs['mac']

                # Vendor (from nmap OUI db if available)
                vendor = "Unknown"
                vendor_map = self.nm[host].get('vendor', {})
                if mac in vendor_map:
                    vendor = vendor_map[mac]

                # Hostname from nmap result (no DNS done here due to -n)
                raw_hostname = self.nm[host].hostname() or ""
                if not raw_hostname:
                    # Sometimes present in 'hostnames' list
                    for h in self.nm[host].get('hostnames', []):
                        n = h.get('name')
                        if n:
                            raw_hostname = n
                            break

                hostname = self._short_label(raw_hostname)

                # If still missing, do a very fast reverse-DNS just for this active IP
                if not hostname:
                    hostname = self._fast_rdns(ip, timeout=0.3)

                device_name, device_type = self.get_device_info_from_mac(mac)
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "name": device_name,
                    "type": device_type,
                    "vendor": vendor,
                    "hostname": hostname
                })
            except Exception as e:
                _LOGGER.debug("Error parsing host %s: %s", host, e)
                continue

        # Sort the devices by IP address
        try:
            devices.sort(key=lambda x: [int(num) for num in x['ip'].split('.')])
        except Exception:
            pass

        return devices

async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up the Network Scanner sensor from a config entry."""
    ip_range = config_entry.data.get("ip_range")
    _LOGGER.debug("ip_range: %s", config_entry.data.get("ip_range"))
    
    # Initialize mac_mappings list to ensure at least 25 entries
    mac_mappings_list = []

    # Ensure we have at least 25 entries, even if config is missing some
    for i in range(25):
        key = f"mac_mapping_{i+1}"
        mac_mapping = config_entry.data.get(key, "")
        mac_mappings_list.append(mac_mapping)
        _LOGGER.debug("mac_mapping_%s: %s", i+1, mac_mapping)

    # Continue adding additional mac mappings if present in the config
    i = 25
    while True:
        key = f"mac_mapping_{i+1}"
        if key in config_entry.data:
            mac_mapping = config_entry.data.get(key)
            mac_mappings_list.append(mac_mapping)
            _LOGGER.debug("mac_mapping_%s: %s", i+1, mac_mapping)
            i += 1
        else:
            break

    # Combine mac mappings into a newline-separated string
    mac_mappings = "\n".join(mac_mappings_list)
    _LOGGER.debug("mac_mappings: %s", mac_mappings)

    # Set up the network scanner entity
    scanner = NetworkScanner(hass, ip_range, mac_mappings)
    async_add_entities([scanner], True)
