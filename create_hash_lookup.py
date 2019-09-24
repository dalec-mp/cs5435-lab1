from csv import reader, writer
import sys
sys.path.append("app/util")
import hash

COMMON_PASSWORDS_PATH = "./common_passwords.txt"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'password')
        return list(r)

def hash_pswd_list(pswds):
    lookup_list = []
    for pswd in pswds:
        hashed_pswd = hash.hash_sha256(pswd[0])
        pair = [hashed_pswd, pswd[0]]
        lookup_list.append(pair)
    return lookup_list

def main():
    common_pswds = load_breach(COMMON_PASSWORDS_PATH)
    lookup_list = hash_pswd_list(common_pswds)

    with open('./lookup.csv', 'w') as f:
        wtr = writer(f, delimiter=',')
        wtr.writerow(['hash','password'])

        for pair in lookup_list:
            wtr.writerow(pair)

if __name__ == "__main__":
    main()
