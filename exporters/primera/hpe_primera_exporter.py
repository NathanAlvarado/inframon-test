#!/usr/bin/env python3
"""
HPE Primera Prometheus Exporter
================================
Polls the HPE Primera / 3PAR WSAPI REST API and exposes metrics for Prometheus.

Configuration is entirely via environment variables:

  HPE_PRIMERA_ARRAY_COUNT      Number of arrays to scrape (default: 1)
  HPE_PRIMERA_EXPORTER_PORT    Port to expose /metrics on (default: 9118)

  Per array (replace {i} with 0, 1, 2 ...):
  HPE_PRIMERA_{i}_HOST         IP or hostname of the Primera array (required)
  HPE_PRIMERA_{i}_USERNAME     WSAPI username (required)
  HPE_PRIMERA_{i}_PASSWORD     WSAPI password (required)
  HPE_PRIMERA_{i}_PORT         WSAPI port (default: 8080)
  HPE_PRIMERA_{i}_SCHEME       http or https (default: https)
  HPE_PRIMERA_{i}_VERIFY_SSL   true/false (default: false)
  HPE_PRIMERA_{i}_TIMEOUT      Request timeout in seconds (default: 30)

Usage:
  docker compose up hpe-primera-exporter
"""

import argparse
import logging
import os
import time
from typing import Any, Dict, Optional

import requests
import urllib3
from prometheus_client import CollectorRegistry, start_http_server
from prometheus_client.core import GaugeMetricFamily, InfoMetricFamily

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("hpe_primera_exporter")


# ---------------------------------------------------------------------------
# WSAPI client
# ---------------------------------------------------------------------------

class PrimeraAPIError(Exception):
    pass


class PrimeraClient:
    """Thin wrapper around the HPE Primera/3PAR WSAPI REST interface."""

    def __init__(self, host: str, username: str, password: str,
                 port: int = 8080, scheme: str = "https",
                 verify_ssl: bool = False, timeout: int = 30):
        self.base_url = f"{scheme}://{host}:{port}/api/v1"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session_key: Optional[str] = None
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def login(self):
        """Obtain a WSAPI session key."""
        url = f"{self.base_url}/credentials"
        payload = {"user": self.username, "password": self.password}
        resp = self._session.post(url, json=payload,
                                  verify=self.verify_ssl, timeout=self.timeout)
        if resp.status_code != 201:
            raise PrimeraAPIError(
                f"Login failed [{resp.status_code}]: {resp.text}"
            )
        self._session_key = resp.json()["key"]
        self._session.headers.update(
            {"X-HP3PAR-WSAPI-SessionKey": self._session_key}
        )
        log.debug("Logged in to %s", self.base_url)

    def logout(self):
        if not self._session_key:
            return
        url = f"{self.base_url}/credentials/{self._session_key}"
        try:
            self._session.delete(url, verify=self.verify_ssl,
                                 timeout=self.timeout)
        except Exception:
            pass
        self._session_key = None
        log.debug("Logged out")

    def _get(self, endpoint: str) -> Dict[str, Any]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        resp = self._session.get(url, verify=self.verify_ssl,
                                 timeout=self.timeout)
        if resp.status_code == 401:
            # Session expired — re-authenticate and retry once
            log.info("Session expired, re-authenticating …")
            self.login()
            resp = self._session.get(url, verify=self.verify_ssl,
                                     timeout=self.timeout)
        if not resp.ok:
            raise PrimeraAPIError(
                f"GET {endpoint} failed [{resp.status_code}]: {resp.text}"
            )
        return resp.json()

    # ------------------------------------------------------------------
    # API wrappers
    # ------------------------------------------------------------------

    def get_system(self) -> Dict:
        return self._get("system")

    def get_cpgs(self) -> list:
        return self._get("cpgs").get("members", [])

    def get_volumes(self) -> list:
        return self._get("volumes").get("members", [])

    def get_disks(self) -> list:
        return self._get("disks").get("members", [])

    def get_nodes(self) -> list:
        return self._get("nodes").get("members", [])

    def get_ports(self) -> list:
        return self._get("ports").get("members", [])

    def get_hosts(self) -> list:
        return self._get("hosts").get("members", [])


# ---------------------------------------------------------------------------
# Prometheus collector
# ---------------------------------------------------------------------------

class PrimeraCollector:
    """
    Custom Prometheus collector for a single HPE Primera array.

    All metrics are prefixed with ``hpe_primera_``.  The ``array`` label
    holds the configured host value so you can scrape multiple arrays from
    the same exporter instance by running multiple processes (or by using
    the multi-target pattern with a separate config per target).
    """

    def __init__(self, config: Dict):
        self.array_host = config["host"]
        self.client = PrimeraClient(
            host=config["host"],
            username=config["username"],
            password=config["password"],
            port=int(config.get("port", 8080)),
            scheme=config.get("scheme", "https"),
            verify_ssl=config.get("verify_ssl", False),
            timeout=int(config.get("timeout", 30)),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _labels(self, **extra) -> Dict[str, str]:
        return {"array": self.array_host, **extra}

    @staticmethod
    def _mib_to_bytes(mib: float) -> float:
        return mib * 1024 * 1024

    # ------------------------------------------------------------------
    # Collector entry point (called by Prometheus on every scrape)
    # ------------------------------------------------------------------

    def collect(self):  # noqa: C901  (complex but intentional)
        try:
            self.client.login()
        except Exception as exc:
            log.error("Login failed for %s: %s", self.array_host, exc)
            g = GaugeMetricFamily(
                "hpe_primera_up",
                "Whether the exporter could reach the HPE Primera WSAPI (1=up, 0=down)",
                labels=["array"],
            )
            g.add_metric([self.array_host], 0)
            yield g
            return

        try:
            yield from self._collect_up()
            yield from self._collect_system()
            yield from self._collect_cpgs()
            yield from self._collect_volumes()
            yield from self._collect_disks()
            yield from self._collect_nodes()
            yield from self._collect_ports()
        except Exception as exc:
            log.error("Collection error for %s: %s", self.array_host, exc)
        finally:
            self.client.logout()

    # ------------------------------------------------------------------
    # Per-domain collectors
    # ------------------------------------------------------------------

    def _collect_up(self):
        g = GaugeMetricFamily(
            "hpe_primera_up",
            "1 if the exporter can authenticate against the HPE Primera WSAPI.",
            labels=["array"],
        )
        g.add_metric([self.array_host], 1)
        yield g

    # ---- System -------------------------------------------------------

    def _collect_system(self):
        try:
            sys_data = self.client.get_system()
        except Exception as exc:
            log.warning("system: %s", exc)
            return

        # Expose string fields as info metric
        info = InfoMetricFamily(
            "hpe_primera_system",
            "Static information about the HPE Primera array.",
        )
        info.add_metric(
            [],
            {
                "array":        self.array_host,
                "name":         str(sys_data.get("name", "")),
                "model":        str(sys_data.get("model", "")),
                "serial_number": str(sys_data.get("serialNumber", "")),
                "system_version": str(sys_data.get("systemVersion", "")),
                "ip_address":   str(sys_data.get("IPv4Addr", "")),
                "location":     str(sys_data.get("location", "")),
                "owner_name":   str(sys_data.get("ownerName", "")),
                "contact":      str(sys_data.get("contact", "")),
            },
        )
        yield info

        # Numeric / capacity fields
        total_nodes = GaugeMetricFamily(
            "hpe_primera_system_total_nodes",
            "Total number of nodes in the array.",
            labels=["array"],
        )
        total_nodes.add_metric([self.array_host],
                               float(sys_data.get("totalNodes", 0)))
        yield total_nodes

        online_nodes = GaugeMetricFamily(
            "hpe_primera_system_online_nodes",
            "Number of online nodes in the array.",
            labels=["array"],
        )
        online_nodes.add_metric([self.array_host],
                                float(sys_data.get("onlineNodes", 0)))
        yield online_nodes

        degraded_nodes = GaugeMetricFamily(
            "hpe_primera_system_degraded_nodes",
            "Number of degraded nodes in the array.",
            labels=["array"],
        )
        degraded_nodes.add_metric([self.array_host],
                                  float(sys_data.get("degradedNodes", 0)))
        yield degraded_nodes

        failed_nodes = GaugeMetricFamily(
            "hpe_primera_system_failed_nodes",
            "Number of failed nodes in the array.",
            labels=["array"],
        )
        failed_nodes.add_metric([self.array_host],
                                float(sys_data.get("failedNodes", 0)))
        yield failed_nodes

        # Total raw capacity (MiB -> bytes)
        raw_capacity = GaugeMetricFamily(
            "hpe_primera_system_total_capacity_bytes",
            "Total raw capacity of the array in bytes.",
            labels=["array"],
        )
        raw_capacity.add_metric(
            [self.array_host],
            self._mib_to_bytes(float(sys_data.get("totalCapacityMiB", 0))),
        )
        yield raw_capacity

        alloc_capacity = GaugeMetricFamily(
            "hpe_primera_system_allocated_capacity_bytes",
            "Allocated capacity of the array in bytes.",
            labels=["array"],
        )
        alloc_capacity.add_metric(
            [self.array_host],
            self._mib_to_bytes(float(sys_data.get("allocatedCapacityMiB", 0))),
        )
        yield alloc_capacity

        free_capacity = GaugeMetricFamily(
            "hpe_primera_system_free_capacity_bytes",
            "Free capacity of the array in bytes.",
            labels=["array"],
        )
        free_capacity.add_metric(
            [self.array_host],
            self._mib_to_bytes(float(sys_data.get("freeCapacityMiB", 0))),
        )
        yield free_capacity

    # ---- CPGs ---------------------------------------------------------

    def _collect_cpgs(self):
        try:
            cpgs = self.client.get_cpgs()
        except Exception as exc:
            log.warning("cpgs: %s", exc)
            return

        # CPG state: 1=Normal, 2=Degraded, 3=Failed
        state_m = GaugeMetricFamily(
            "hpe_primera_cpg_state",
            "CPG state: 1=Normal, 2=Degraded, 3=Failed.",
            labels=["array", "cpg"],
        )
        # Space used / available (MiB → bytes)
        used_sa_m = GaugeMetricFamily(
            "hpe_primera_cpg_used_sa_bytes",
            "CPG used SA (Snapshot Admin) space in bytes.",
            labels=["array", "cpg"],
        )
        used_sd_m = GaugeMetricFamily(
            "hpe_primera_cpg_used_sd_bytes",
            "CPG used SD (Snapshot Data) space in bytes.",
            labels=["array", "cpg"],
        )
        used_usr_m = GaugeMetricFamily(
            "hpe_primera_cpg_used_usr_bytes",
            "CPG used USR (user data) space in bytes.",
            labels=["array", "cpg"],
        )
        total_m = GaugeMetricFamily(
            "hpe_primera_cpg_total_bytes",
            "CPG total allocated space in bytes.",
            labels=["array", "cpg"],
        )
        free_m = GaugeMetricFamily(
            "hpe_primera_cpg_free_bytes",
            "CPG free (available) space in bytes.",
            labels=["array", "cpg"],
        )
        fpvv_m = GaugeMetricFamily(
            "hpe_primera_cpg_fpvv_count",
            "Number of Fully Provisioned Virtual Volumes in the CPG.",
            labels=["array", "cpg"],
        )
        tpvv_m = GaugeMetricFamily(
            "hpe_primera_cpg_tpvv_count",
            "Number of Thinly Provisioned Virtual Volumes in the CPG.",
            labels=["array", "cpg"],
        )
        tdvv_m = GaugeMetricFamily(
            "hpe_primera_cpg_tdvv_count",
            "Number of Thin Dedup Virtual Volumes in the CPG.",
            labels=["array", "cpg"],
        )

        for cpg in cpgs:
            name = cpg.get("name", "unknown")
            lbl = [self.array_host, name]

            state_m.add_metric(lbl, float(cpg.get("state", 0)))

            # SAUsage / SDUsage / UsrUsage blocks each carry: usedMiB, rawUsedMiB, totalMiB, rawTotalMiB
            sa_usage = cpg.get("SAUsage", {})
            sd_usage = cpg.get("SDUsage", {})
            usr_usage = cpg.get("UsrUsage", {})

            used_sa_m.add_metric(lbl, self._mib_to_bytes(float(sa_usage.get("usedMiB", 0))))
            used_sd_m.add_metric(lbl, self._mib_to_bytes(float(sd_usage.get("usedMiB", 0))))
            used_usr_m.add_metric(lbl, self._mib_to_bytes(float(usr_usage.get("usedMiB", 0))))

            total_mib = float(usr_usage.get("totalMiB", 0))
            used_mib = float(usr_usage.get("usedMiB", 0))
            total_m.add_metric(lbl, self._mib_to_bytes(total_mib))
            free_m.add_metric(lbl, self._mib_to_bytes(max(0.0, total_mib - used_mib)))

            fpvv_m.add_metric(lbl, float(cpg.get("numFPVVs", 0)))
            tpvv_m.add_metric(lbl, float(cpg.get("numTPVVs", 0)))
            tdvv_m.add_metric(lbl, float(cpg.get("numTDVVs", 0)))

        yield state_m
        yield used_sa_m
        yield used_sd_m
        yield used_usr_m
        yield total_m
        yield free_m
        yield fpvv_m
        yield tpvv_m
        yield tdvv_m

    # ---- Volumes ------------------------------------------------------

    def _collect_volumes(self):
        """
        Mirrors the Zabbix HPE Primera volume triggers.

        The WSAPI exposes three separate fields per volume:
        $.state          — primary health: 1=Normal, 2=Degraded, 3=Failed, 99=Unknown
        $.degradedStates — array of detailed degraded state codes (informational)
        $.failedStates   — array of detailed failed state codes (informational)

        Zabbix only alerts on $.state; degradedStates/failedStates are collected
        for context. We follow the same pattern.
        """
        try:
            volumes = self.client.get_volumes()
        except Exception as exc:
            log.warning("volumes: %s", exc)
            return

        state_m = GaugeMetricFamily(
            "hpe_primera_volume_state",
            "Volume primary state: 1=Normal, 2=Degraded, 3=Failed, 99=Unknown.",
            labels=["array", "volume", "cpg"],
        )
        degraded_states_count_m = GaugeMetricFamily(
            "hpe_primera_volume_degraded_states_count",
            "Number of detailed degraded state codes active on the volume ($.degradedStates).",
            labels=["array", "volume", "cpg"],
        )
        failed_states_count_m = GaugeMetricFamily(
            "hpe_primera_volume_failed_states_count",
            "Number of detailed failed state codes active on the volume ($.failedStates).",
            labels=["array", "volume", "cpg"],
        )
        size_m = GaugeMetricFamily(
            "hpe_primera_volume_size_bytes",
            "Provisioned volume size in bytes.",
            labels=["array", "volume", "cpg"],
        )

        for vol in volumes:
            name = vol.get("name", "unknown")
            cpg_name = vol.get("userCPG", vol.get("copyOfName", ""))
            lbl = [self.array_host, name, cpg_name]

            state_m.add_metric(lbl, float(vol.get("state", 1)))
            degraded_states_count_m.add_metric(lbl, float(len(vol.get("degradedStates", []))))
            failed_states_count_m.add_metric(lbl, float(len(vol.get("failedStates", []))))
            size_m.add_metric(lbl, self._mib_to_bytes(float(vol.get("sizeMiB", 0))))

        yield state_m
        yield degraded_states_count_m
        yield failed_states_count_m
        yield size_m

    # ---- Physical Disks -----------------------------------------------

    def _collect_disks(self):
        """
        Mirror the Zabbix disk triggers:
          - Disk state (normal/degraded/failed/new/absent)
          - Path degraded flags: loop_a0, loop_a1, loop_b0, loop_b1
        """
        try:
            disks = self.client.get_disks()
        except Exception as exc:
            log.warning("disks: %s", exc)
            return

        state_m = GaugeMetricFamily(
            "hpe_primera_disk_state",
            "Physical disk state: 1=Normal, 2=Degraded, 3=Failed, 4=New, 5=Absent, 6=Removed.",
            labels=["array", "disk_id", "position"],
        )
        loop_a0_m = GaugeMetricFamily(
            "hpe_primera_disk_path_a0_degraded",
            "1 if disk path A0 is degraded.",
            labels=["array", "disk_id", "position"],
        )
        loop_a1_m = GaugeMetricFamily(
            "hpe_primera_disk_path_a1_degraded",
            "1 if disk path A1 is degraded.",
            labels=["array", "disk_id", "position"],
        )
        loop_b0_m = GaugeMetricFamily(
            "hpe_primera_disk_path_b0_degraded",
            "1 if disk path B0 is degraded.",
            labels=["array", "disk_id", "position"],
        )
        loop_b1_m = GaugeMetricFamily(
            "hpe_primera_disk_path_b1_degraded",
            "1 if disk path B1 is degraded.",
            labels=["array", "disk_id", "position"],
        )
        total_m = GaugeMetricFamily(
            "hpe_primera_disk_total_bytes",
            "Physical disk total capacity in bytes.",
            labels=["array", "disk_id", "position"],
        )

        for disk in disks:
            disk_id = str(disk.get("id", "?"))
            pos_data = disk.get("diskPos", {})
            position = "{node}:{slot}:{mag}:{diskPos}".format(
                node=pos_data.get("node", "?"),
                slot=pos_data.get("slot", "?"),
                mag=pos_data.get("mag", "?"),
                diskPos=pos_data.get("diskPos", "?"),
            )
            lbl = [self.array_host, disk_id, position]

            state = int(disk.get("state", 1))
            state_m.add_metric(lbl, float(state))
            total_m.add_metric(
                lbl, self._mib_to_bytes(float(disk.get("totalMiB", 0)))
            )

            # Path degraded flags — derived from the pathState bitmask.
            # Bit mapping: A0=bit0, A1=bit1, B0=bit2, B1=bit3
            # A path is "degraded" if its bit is 0 (not active) and the disk
            # is otherwise present.
            path_state = int(disk.get("pathState", 0b1111))
            if state in (1, 2):  # only meaningful for normal/degraded disks
                loop_a0_m.add_metric(lbl, 1.0 if not (path_state & 0x1) else 0.0)
                loop_a1_m.add_metric(lbl, 1.0 if not (path_state & 0x2) else 0.0)
                loop_b0_m.add_metric(lbl, 1.0 if not (path_state & 0x4) else 0.0)
                loop_b1_m.add_metric(lbl, 1.0 if not (path_state & 0x8) else 0.0)
            else:
                loop_a0_m.add_metric(lbl, 0.0)
                loop_a1_m.add_metric(lbl, 0.0)
                loop_b0_m.add_metric(lbl, 0.0)
                loop_b1_m.add_metric(lbl, 0.0)

        yield state_m
        yield loop_a0_m
        yield loop_a1_m
        yield loop_b0_m
        yield loop_b1_m
        yield total_m

    # ---- Nodes --------------------------------------------------------

    def _collect_nodes(self):
        try:
            nodes = self.client.get_nodes()
        except Exception as exc:
            log.warning("nodes: %s", exc)
            return

        state_m = GaugeMetricFamily(
            "hpe_primera_node_state",
            "Node state: 1=OK, 2=Degraded, 3=Failed, 4=Unknown.",
            labels=["array", "node_id", "name"],
        )
        led_m = GaugeMetricFamily(
            "hpe_primera_node_led_state",
            "Node LED state (0=off, 1=green, 2=amber, 3=red).",
            labels=["array", "node_id", "name"],
        )
        mem_total_m = GaugeMetricFamily(
            "hpe_primera_node_memory_total_bytes",
            "Total memory in the node in bytes.",
            labels=["array", "node_id", "name"],
        )
        mem_free_m = GaugeMetricFamily(
            "hpe_primera_node_memory_free_bytes",
            "Free memory in the node in bytes.",
            labels=["array", "node_id", "name"],
        )

        for node in nodes:
            node_id = str(node.get("id", "?"))
            name = str(node.get("name", f"node{node_id}"))
            lbl = [self.array_host, node_id, name]

            state_m.add_metric(lbl, float(node.get("state", 0)))
            led_m.add_metric(lbl, float(node.get("ledStates", [0])[0]
                                         if node.get("ledStates") else 0))
            mem_total_m.add_metric(
                lbl, float(node.get("memoryMiB", 0)) * 1024 * 1024
            )
            # WSAPI does not expose free node memory directly; expose 0 as placeholder
            mem_free_m.add_metric(lbl, 0.0)

        yield state_m
        yield led_m
        yield mem_total_m
        yield mem_free_m

    # ---- Ports --------------------------------------------------------

    def _collect_ports(self):
        """
        Mirror the Zabbix port state and failover state triggers.
        Port link states (from WSAPI PortLinkState enum):
          1=CONFIG_WAIT, 2=ALPA_WAIT, 3=LOGIN_WAIT, 4=READY, 5=LOSS_SYNC,
          6=ERROR_STATE, 7=XXX, 8=NONPARTICIPATE, 9=COREDUMP, 10=OFFLINE,
          11=FWDEAD, 12=IDLE_FOR_RESET, 13=DHCP_IN_PROGRESS, 14=PENDING_RESET,
          15=NEW, 16=DISABLED, 17=DOWN, 18=FAILED, 19=PURGING
        """
        try:
            ports = self.client.get_ports()
        except Exception as exc:
            log.warning("ports: %s", exc)
            return

        link_state_m = GaugeMetricFamily(
            "hpe_primera_port_link_state",
            "Port link state (4=READY is healthy; see WSAPI docs for other values).",
            labels=["array", "node", "slot", "card_port", "type"],
        )
        failover_state_m = GaugeMetricFamily(
            "hpe_primera_port_failover_state",
            "Port failover state (0=NONE/ok, non-zero indicates failover active).",
            labels=["array", "node", "slot", "card_port", "type"],
        )
        port_healthy_m = GaugeMetricFamily(
            "hpe_primera_port_healthy",
            "1 if the port link state is READY (4), 0 otherwise.",
            labels=["array", "node", "slot", "card_port", "type"],
        )

        for port in ports:
            pos = port.get("portPos", {})
            node = str(pos.get("node", "?"))
            slot = str(pos.get("slot", "?"))
            card_port = str(pos.get("cardPort", "?"))
            port_type = str(port.get("type", "?"))
            lbl = [self.array_host, node, slot, card_port, port_type]

            link_state = int(port.get("linkState", 0))
            failover = int(port.get("failoverState", 0))

            link_state_m.add_metric(lbl, float(link_state))
            failover_state_m.add_metric(lbl, float(failover))
            port_healthy_m.add_metric(lbl, 1.0 if link_state == 4 else 0.0)

        yield link_state_m
        yield failover_state_m
        yield port_healthy_m


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def load_config_from_env() -> Dict:
    array_count = int(os.getenv("HPE_PRIMERA_ARRAY_COUNT", "1"))
    arrays = []
    for i in range(array_count):
        prefix = f"HPE_PRIMERA_{i}_"
        arrays.append({
            "host":       os.environ[f"{prefix}HOST"],  # required, fail fast if missing
            "port":       int(os.getenv(f"{prefix}PORT",       "8080")),
            "scheme":     os.getenv(f"{prefix}SCHEME",         "https"),
            "username":   os.environ[f"{prefix}USERNAME"],
            "password":   os.environ[f"{prefix}PASSWORD"],
            "verify_ssl": os.getenv(f"{prefix}VERIFY_SSL",     "false").lower() == "true",
            "timeout":    int(os.getenv(f"{prefix}TIMEOUT",    "30")),
        })
    return {
        "exporter_port": int(os.getenv("HPE_PRIMERA_EXPORTER_PORT", "9118")),
        "arrays": arrays,
    }


def main():
    parser = argparse.ArgumentParser(description="HPE Primera Prometheus Exporter")
    parser.add_argument("--port", type=int, default=None,
                        help="Override HTTP port to expose metrics on.")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)

    cfg = load_config_from_env()
    listen_port = args.port or cfg["exporter_port"]

    registry = CollectorRegistry()
    for array_cfg in cfg["arrays"]:
        collector = PrimeraCollector(array_cfg)
        registry.register(collector)
        log.info("Registered collector for array: %s", array_cfg["host"])

    start_http_server(listen_port, registry=registry)
    log.info("Exporter listening on :%d — metrics at /metrics", listen_port)

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Shutting down.")


if __name__ == "__main__":
    main()