import requests
import socket


def probe_http_service(port):

    try:

        response = requests.get(
            f"http://localhost:{port}",
            timeout=3
        )

        return {
            "success": True,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown")
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }


def probe_tcp_service(port):

    try:

        sock = socket.socket()
        sock.settimeout(3)

        sock.connect(("localhost", port))

        return {
            "success": True,
            "port": port
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":

    print("\nDVWA Probe")
    print(probe_http_service(8080))

    print("\nMySQL Probe")
    print(probe_tcp_service(3307))

    print("\nNginx Probe")
    print(probe_http_service(5000))
