import socket

def probe_port(host, port):
    """
    Check if a port is open on a host.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

def scan_local_services():
    """
    Scan localhost for active cyber-range services using native sockets.
    """

    services = {
        "DVWA": probe_port("localhost", 8080),
        "MySQL": probe_port("localhost", 3307),
        "Nginx": probe_port("localhost", 5000)
    }

    return services


if __name__ == "__main__":
    print(scan_local_services())
