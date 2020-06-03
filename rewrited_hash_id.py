#!/usr/bin/env python3
# encoding: utf-8
# Hash Identifier
# By Zion3R
# Forked and edited by fu11p0w3r
# www.Blackploit.com
# Root@Blackploit.com

from sys import argv, exit

version = 1.2

logo='''   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v'''+str(version)+''' #
   #                                                             By Zion3R #
   #                                                     Thanks: fu11p0w3r #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################'''

# hash.islower()  minusculas
# hash.isdigit()  numerico
# hash.isalpha()  letras
# hash.isalnum()  alfanumerico

hashlist = {
    '4_chars':['CRC-16','CRC-16-CCITT','FCS-16'],
    '8_chars':['CRC-32','ADLER-32','CRC-32B','XOR-32','GHash-32-3','GHash-32-5'],
    '13_chars':['DES(Unix)'],
    '16_chars':['MD5(Half)','MD5(Middle)','MySQL'],
    '32_chars':['Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))',
              'Haval128','Haval128HMAC','MD2','MD2(HMAC)','MD4','MD4(HMAC)','MD5','MD5(HMAC)',
              'MD5(HMAC(Wordpress))','NTLM','RAdminv2x','RipeMD-128','RipeMD-128(HMAC)','SNEFRU-128',
              'SNEFRU-128(HMAC)','Tiger-128','Tiger-128(HMAC)','md5($pass.$salt)','md5($salt.\'-\'.md5($pass))',
              'md5($salt.$pass)','md5($salt.$pass.$salt)','md5($salt.$pass.$username)','md5($salt.md5($pass))',
              'md5($salt.md5($pass).$salt)','md5($salt.md5($pass.$salt))','md5($salt.md5($salt.$pass))',
              'md5($salt.md5(md5($pass).$salt))','md5($username.0.$pass)','md5($username.LF.$pass)',
              'md5($username.md5($pass).$salt)','md5(md5($pass))','md5(md5($pass).$salt)','md5(md5($pass).md5($salt))',
              'md5(md5($salt).$pass)','md5(md5($salt).md5($pass))','md5(md5($username.$pass).$salt)',
              'md5(md5(md5($pass)))','md5(md5(md5(md5($pass))))','md5(md5(md5(md5(md5($pass)))))','md5(sha1($pass))',
              'md5(sha1(md5($pass)))','md5(sha1(md5(sha1($pass))))','md5(strtoupper(md5($pass)))'],
    '40_chars':['Haval-160','Haval-160(HMAC)','MySQL5','RipeMD-160','RipeMD-160(HMAC)','SHA-1','SHA-1(HMAC)',
              'SHA-1(MaNGOS)','SHA-1(MaNGOS2)','Tiger-160','Tiger-160(HMAC)','sha1($pass.$salt)','sha1($salt.$pass)',
              'sha1($salt.md5($pass))','sha1($salt.md5($pass).$salt)','sha1($salt.sha1($pass))','sha1($salt.sha1($salt.sha1($pass)))',
              'sha1($username.$pass)','sha1($username.$pass.$salt)','sha1(md5($pass))','sha1(md5($pass).$salt)','sha1(md5(sha1($pass)))',
              'sha1(sha1($pass))','sha1(sha1($pass).$salt)','sha1(sha1($pass).substr($pass,0,3))','sha1(sha1($salt.$pass))',
              'sha1(sha1(sha1($pass)))','sha1(strtolower($username).$pass)'],
    '48_chars':['Haval-192','Haval-192(HMAC)','Tiger-192','Tiger-192(HMAC)'],
    '56_chars':['Haval-224','Haval-224(HMAC)','SHA-224','SHA-224(HMAC)'],
    '64_chars':['SHA-256','SHA-256(HMAC)','Haval-256','Haval-256(HMAC)','GOST R 34.11-94','RipeMD-256','RipeMD-256(HMAC)',
                'SNEFRU-256','SNEFRU-256(HMAC)','SHA-256(md5($pass))','SHA-256(sha1($pass))'],
    '80_chars':['RipeMD-320','RipeMD-320(HMAC)'],
    '96_chars':['SHA-384','SHA-384(HMAC)'],
    '128_chars':['SHA-512','SHA-512(HMAC)','Whirlpool','Whirlpool(HMAC)'],
    'prefixes':{
        '0x':['Lineage II C4'],
        '$H$':['MD5(phpBB3)'],
        '$1$':['MD5(Unix)'],
        '$P$':['MD5(Wordpress)'],
        '$apr':['MD5(APR)'],
        '*':['MySQL-160bit'],
        'sha1$':['SHA-1(Django)'],
        'sha256':['SHA-256(Django)'],
        '$6$':['SHA-256s'],
        'sha384':['SHA-384(Django)'],
    },
    'specials':{
        ':': ['md5($pass.$salt) - Joomla', 'SAM'],
    }
}

def detect_hash(hash):
    global hashlist
    h_size = len(hash)
    for prefix in hashlist['prefixes']:
        if prefix in hash[0:6]:
            return hashlist['prefixes'][prefix]
    if hash[32:33] == ':':
        return hashlist['specials'][':']
    elif h_size >=4 and h_size <=128 and hash.isalnum() == True:
        return hashlist[f'{h_size}_chars']
    else:
        return 'Not Detected'

if __name__ == '__main__':
    print(logo)
    try:
        hash = str(argv[1])
    except:
        print('[!] Error, pls try again with correct value!')
        exit(0)
    else:
        print("-" * 50)
        result = detect_hash(hash)
        if result != 'Not Detected':
            if len(result) >= 2:
                result.sort()
                print("\nPossible Hashs:")
                for _ in range(2):
                    print(f"[+] {result[_]}")
                print("\nLeast Possible Hashs:")
                for _ in range(2, len(result)):
                    print(f"[+] {result[_]}")
            else:
                result.sort()
                print("\nPossible Hashs:")
                for _ in result:
                    print(f"[+] {_}")
                    print("\n\n\tBye!")
                    exit(0)
        else:
            print(result)
