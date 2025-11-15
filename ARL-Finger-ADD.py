#!/usr/bin/python3
# -*- coding:utf-8 -*-
"""
-------------------------------------------------
Author:       loecho
Datetime:     2021-07-23 12:47
ProjectName:  getFinger.py
Blog:         https://loecho.me
Email:        loecho@foxmail.com
-------------------------------------------------
"""
import sys
import json
import requests

requests.packages.urllib3.disable_warnings()


'''
-----ARL支持字段：-------
body = " "
title = ""
header = ""
icon_hash = ""
'''


def main(url, token):
    try:
        with open("./finger.json", 'r', encoding="utf-8") as f:
            load_dict = json.load(f)
    except FileNotFoundError:
        print("[-] 错误：未找到 finger.json 文件，请确保它在当前目录下")
        return
    except json.JSONDecodeError as e:
        print(f"[-] 错误：finger.json 文件格式错误: {e}")
        return

    body = "body=\"{}\""
    title = "title=\"{}\""
    icon_hash = "icon_hash=\"{}\""

    for i in load_dict.get('fingerprint', []):
        try:
            finger_json = i  # 简化处理，无需重复序列化/反序列化
            name = finger_json['cms']
            keyword_list = finger_json.get('keyword', [])
            
            if not keyword_list:
                print(f"[-] 警告：指纹 '{name}' 没有关键词，跳过")
                continue

            if finger_json['method'] == "keyword":
                if finger_json['location'] == "body":
                    rule_format = body
                elif finger_json['location'] == "title":
                    rule_format = title
                elif finger_json['location'] == "icon_hash":
                    rule_format = icon_hash
                else:
                    print(f"[-] 未知位置类型: {finger_json['location']}，跳过指纹 '{name}'")
                    continue

                # 只使用第一个关键词（根据原脚本逻辑）
                rule = rule_format.format(keyword_list[0])
                add_Finger(name, rule, url, token)
        except Exception as e:
            print(f"[-] 处理指纹时出错: {e}")


def add_Finger(name, rule, url, token):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
        "Connection": "close",
        "Token": token,
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json; charset=UTF-8"
    }
    api_url = f"{url}/api/fingerprint/"
    data = {"name": name, "human_rule": rule}

    try:
        response = requests.post(api_url, json=data, headers=headers, verify=False)
        if response.status_code == 200:
            print(f''' Add: [\033[32;1m+\033[0m]  {json.dumps(data)}\n Rsp: [\033[32;1m+\033[0m] {response.text}''')
        else:
            print(f"[-] 添加失败: HTTP {response.status_code}, {response.text}")
    except Exception as e:
        print(f"[-] 请求出错: {e}")


def test(name, rule):
    print(f"name: {name}, rule: {rule}")


if __name__ == '__main__':
    try:
        if 1 < len(sys.argv) < 5:
            login_url = sys.argv[1]
            login_name = sys.argv[2]
            login_password = sys.argv[3]

            # 确保 URL 以 / 结尾
            if not login_url.endswith('/'):
                login_url += '/'

            # 登录获取 Token
            login_data = {"username": login_name, "password": login_password}
            login_res = requests.post(
                url=f"{login_url}api/user/login",
                json=login_data,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
                    "Content-Type": "application/json; charset=UTF-8"
                },
                verify=False
            )

            # 判断是否登录成功
            if login_res.status_code == 200 and 'token' in login_res.json().get('data', {}):
                token = login_res.json()['data']['token']
                print("[+] 登录成功!!")
                main(login_url, token)
            else:
                print(f"[-] 登录失败! 状态码: {login_res.status_code}, 响应: {login_res.text}")
        else:
            print('''
    usage:
        
        python3 ARl-Finger-ADD.py https://192.168.1.1:5003/ admin password
                                                        
                                                         by  loecho
            ''')
    except Exception as e:
        print(f"[-] 执行脚本时出错: {e}")