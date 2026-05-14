import subprocess


def scan_local_services():
    """
    Scan localhost for active cyber-range services.
    """

    result = subprocess.check_output(
        ["nmap", "-p", "5000,8080,3306", "localhost"]
    ).decode()

    services = {
        "DVWA": False,
        "MySQL": False,
        "Nginx": False
    }

    if "8080/tcp open" in result:
        services["DVWA"] = True

    if "3306/tcp open" in result:
        services["MySQL"] = True

    if "5000/tcp open" in result:
        services["Nginx"] = True

    return services


if __name__ == "__main__":
    print(scan_local_services())
