from typing import Optional, List

def port_to_iface(port: int) -> str:
    if port == 64: return "veth250"
    elif port == 320 or port == 250: return "veth251"
    
    return f"veth{2*port}"


def all_model_port_ifaces(max_port: int = 16, extra_ports: Optional[List[int]] = None) -> List[str]:
    ports = set(range(0, max_port + 1)) # Unique ports
    if extra_ports is not None:
        for p in extra_ports: ports.add(p)


    ifaces = [port_to_iface(p) for p in ports]
    return list(set(ifaces)) # Return only unique ifaces