# udm
Python client for UDM.

## Installation

```
pip install git+https://github.com/mjsonofharry/udm.git@v0.0.1
```

## Usage

```python

from udm.client import UdmClient

udm_client = UdmClient(
    username="",
    password="",
    ip_address="192.168.1.1",
    verify=True,
    cert_path="/path/to/udm/cert"
)
udm.login()
udm.create_portforwarding_rule(
    name="ioquake",
    port=27960,
    tcp=False,
    udp=True,
    enabled=True
)
```
