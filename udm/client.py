from dataclasses import dataclass
from typing import List, Optional
from pyparsing import Opt
import requests


@dataclass(frozen=True)
class UdmClient:
    username: str
    password: str
    ip_address: str
    verify: bool
    cert_path: Optional[str]

    session = requests.Session()

    @property
    def base_url(self):
        return f"https://{self.ip_address}:443"

    def login(self, x_csrf_token: Optional[str]) -> None:
        print("Logging into UDM...")
        if self.verify:
            self.session.verify = self.cert_path
        if x_csrf_token is not None:
            self.session.headers['X-CSRF-TOKEN'] = x_csrf_token
        self.session.post(
            url=f"{self.base_url}/api/auth/login",
            data=dict(username=self.username, password=self.password, strict=True),
            verify=self.verify,
        )
        print("Login complete!")

    def __get_data(self, resource: str) -> dict:
        response = self.session.get(
            url=f"{self.base_url}/{resource}",
            verify=self.verify,
        )
        if response.status_code != 200:
            raise RuntimeError(f"<{response.status_code}> {response.text}")
        response_json = response.json()
        if response_json["meta"]["rc"] != "ok":
            raise RuntimeError(f"<{response.status_code}> {response.text}")
        return response_json["data"]

    def get_sysinfo(self) -> List[dict]:
        print("Retrieving sysinfo from UDM...")
        return self.__get_data(f"proxy/network/api/s/default/stat/sysinfo")

    def get_device_data(self) -> List[dict]:
        print("Retrieving device data from UDM...")
        return self.__get_data(f"proxy/network/api/s/default/stat/device")

    def get_udm(self) -> dict:
        udm: Optional[dict] = next(
            iter([x for x in self.get_device_data() if x["type"] == "udm"]), None
        )
        if udm is None:
            raise RuntimeError(f"Expected to find 1 UDM (found {len(udm)})")
        return udm

    def get_udm_ip(self, port_index: int, port_mac: str) -> str:
        udm: dict = self.get_udm()

        print(f"Validating UDM IP address...")
        udm_ip: str = udm.get("ip")
        if not udm_ip:
            raise RuntimeError(f"Invalid UDM IP address: '{udm_ip}'")

        def _check_port() -> None:
            print(f"Checking port {port_index} ({port_mac})...")
            port_table: List[dict] = udm.get("port_table")
            if not port_table:
                raise RuntimeError("Failed to find port table")
            port: Optional[dict] = next(
                iter(
                    [
                        x
                        for x in port_table
                        if x["port_idx"] == port_index and x["mac"] == port_mac
                    ]
                ),
                None,
            )
            if not port:
                raise RuntimeError(f"Failed to find port {port_index}")
            if port.get("is_uplink", False) != True:
                raise RuntimeError(f"Port {port_index} is not uplink")
            port_ip: str = port.get("ip")
            if udm_ip != port_ip:
                raise RuntimeError(
                    f"UDM IP address '{udm_ip}' does not match port {port_index}: '{port_ip}'"
                )

        def _check_geo_info() -> None:
            print("Checking geo info...")
            geo_info = udm.get("geo_info")
            if not geo_info:
                raise RuntimeError("Failed to find geo info")
            geo_info_wan_ip = geo_info.get("WAN", {}).get("address")
            if not geo_info_wan_ip:
                raise RuntimeError("Failed to find WAN IP address in geo info")
            if udm_ip != geo_info_wan_ip:
                raise RuntimeError(
                    f"UDM IP address '{udm_ip}' does not match geo info: '{geo_info_wan_ip}'"
                )

        def _check_uplink() -> None:
            print("Checking uplink...")
            uplink = udm["uplink"]
            uplink_ip = uplink["ip"]
            if udm_ip != uplink_ip:
                raise RuntimeError(
                    f"UDM IP address '{udm_ip}' does not match uplink: {uplink_ip}"
                )

        _check_port()
        _check_geo_info()
        _check_uplink()
        print("UDM IP address validated!")
        return udm_ip

    def get_portforwarding_rules(self):
        print("Retrieving port forwarding rules")
        return self.__get_data(f"proxy/network/api/s/default/rest/portforward")

    def delete_portfowarding_rule(self, port: str):
        print(f"Deleting port forwarding rule for port {port}")
        rules = self.get_portforwarding_rules()
        rule_id = next((x["_id"] for x in rules if x["dst_port"] == port), None)
        if rule_id is not None:
            response = self.session.delete(
                f"{self.base_url}/proxy/network/api/s/default/rest/portforward/{rule_id}",
                json={},
                verify=self.verify,
                headers={
                    **self.session.headers,
                    'Content-Type': 'application/json'
                }
            )
            print(f"Deleted port forwarding rule; server response: {response.text}")
        else:
            print("Port forwarding rule not found")

    def create_portforwarding_rule(
        self,
        name: str,
        destination_port: str,
        forward_ip: str,
        foward_port: str,
        tcp: bool,
        udp: bool,
        enabled: bool = True,
        interface: str = "wan",
        source: str = "any",
        log: bool = False,
        replace: bool = False,
    ):
        protocol = ""
        if tcp:
            protocol += "tcp"
        if tcp and udp:
            protocol += "_"
        if udp:
            protocol += "udp"
        data = dict(
            dst_port=str(destination_port),
            enabled=enabled,
            fwd=forward_ip,
            fwd_port=str(foward_port),
            log=log,
            name=name,
            pfwd_interface=interface,
            proto=protocol,
            src=source,
        )
        print(f"Creating portforwarding rule: {data}")
        if replace is True:
            self.delete_portfowarding_rule(port=destination_port)
        response = self.session.post(
            f"{self.base_url}/proxy/network/api/s/default/rest/portforward",
            json=data,
            verify=self.verify,
        )
        print(f"Created portforwarding rule; server response: {response.text}")
