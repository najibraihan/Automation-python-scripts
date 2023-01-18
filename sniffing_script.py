"""Script responsible for sniffing on the network traffic in given iOS device."""
import argparse
import logging
import pathlib


from pymobiledevice3 import exceptions
from pymobiledevice3 import lockdown
from pymobiledevice3.services import pcapd


logger = logging.getLogger("__name__")
script_path = pathlib.Path(__file__).resolve().parent

SLEEP_BETWEEN_ACTIONS = 10


class NetworkSniffingError(Exception):
    """Network sniffing error."""


def start_sniffing_and_capturing_traffic(device_id: str) -> None:

    lock_down = lockdown.LockdownClient(serial=device_id)
    with open(script_path / "out.pcap", "wb") as fo:
        pcapd.PcapdService.write_to_pcap(
            fo, pcapd.PcapdService(lockdown=lock_down).watch()
        )


def main() -> None:
    """Run local instance of network sniffer

    To sniff on network traffic on real device and save it in pcap file, run:

    ```shell
    PYTHONPATH=. python3 agent/sniffing_script.py --device-id D0AA002187JB1801254
    ```

    Returns:
        None
    """

    parser = argparse.ArgumentParser(
        description="Run network sniffer on target device for determined time."
    )
    parser.add_argument(
        "--device-id", type=str, required=True, help="The ID of the device."
    )

    args = parser.parse_args()

    device_id: str = args.device_id

    try:
        start_sniffing_and_capturing_traffic(device_id=device_id)
    except exceptions.PyMobileDevice3Exception as e:
        logger.error("Error %s", e)


if __name__ == "__main__":
    main()
