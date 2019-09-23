from csv import reader
import sys
sys.path.append('app/util')
import hash
import concurrent.futures
#import bytes

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

def brute_force_attack(target_hash, target_salt):
    common_pswds = load_common_passwords()
    
    for i, pswd in enumerate(common_pswds):
        res = hash.hash_pbkdf2(pswd[0], target_salt)
        if target_hash == res:
            print('matched with common password: ', pswd[0])
            return pswd[0]
    return None

def main():    
    salted_creds = load_breach(SALTED_BREACH_PATH)
    print(salted_creds[52])
    brute_force_attack(salted_creds[52][1], salted_creds[52][2])

if __name__ == "__main__":
    main()
