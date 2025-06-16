from graphviz import Digraph
import logging
from typing import Set, Tuple, List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("data/logs/netsentry.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_network_tree(
    networks: Set[Tuple[str, str]],
    devices: List[Dict[str, Any]],
    streams: List[Dict[str, Any]],
    output_file: str = "output/netsentry_tree.png"
) -> None:
    """Generate a graphical tree of networks, devices, and streams."""
    try:
        dot = Digraph(comment="Network Discovery Tree", format="png")
        dot.node("A", "Scanned Networks", shape="box", style="filled", fillcolor="lightblue")
        
        for i, (ssid, bssid) in enumerate(networks, 1):
            net_id = f"N{i}"
            dot.node(net_id, f"Network: {ssid}\nBSSID: {bssid}", shape="ellipse")
            dot.edge("A", net_id)
            
            for j, device in enumerate(devices, 1):
                if device["ip"].startswith("192.168.1"):
                    dev_id = f"D{i}{j}"
                    ports = "\n".join([f"{p['port']} ({p['service']})" for p in device["ports"]])
                    dot.node(
                        dev_id,
                        f"IP: {device['ip']}\nMAC: {device['mac']}\nVendor: {device['vendor']}\nPorts: {ports}",
                        shape="rectangle"
                    )
                    dot.edge(net_id, dev_id)
            
            for k, stream in enumerate(streams, 1):
                if stream["src_ip"].startswith("192.168.1"):
                    stream_id = f"S{i}{k}"
                    dot.node(
                        stream_id,
                        f"Stream: {stream['protocol']}\nSrc: {stream['src_ip']}\nDst: {stream['dst_ip']}",
                        shape="diamond"
                    )
                    dot.edge(net_id, stream_id)
        
        logger.info(f"Generating network tree at {output_file}")
        dot.render(output_file, view=True)
    
    except Exception as e:
        logger.error(f"Failed to generate network tree: {str(e)}")