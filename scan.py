#-*- coding:utf-8 -*-
from optparse import OptionParser
from Libs.func import *
import threading
from queue import Queue


event = threading.Event()
event.set()
q_urls = Queue(-1)

col = Color()
init = FuzzFunction()

# 多线程类
class multi_thread(threading.Thread):
    def __init__(self, q_urls, num):
        threading.Thread.__init__(self)
        self.q_urls = q_urls
        self.t = num

    def run(self):
        while event.is_set():
            if self.q_urls.empty():
                break
            else:
                url = self.q_urls.get()
                scan(url=url, cookie=None, sql_type='get')

# 多线程方法
def scan_thread(q_urls, t):
    threads = []
    thread_num = t
    for num in range(1, thread_num + 1):
        t = multi_thread(q_urls, num)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# 打开urls.txt文件，获取所有url
def get_urls(urlsFile):
    with open(urlsFile, 'rt') as f:
        for each in f.readlines():
            q_urls.put(each[:-1])
    return q_urls


# 对单个url扫描Get型的注入payload
def scan(url, cookie, sql_type, postPath):
    init.setSysPath(sql_type)                        # 将Get|Post型Payload所在的目录添加到系统变量里
    FuzzScripts = init.FuzzScriptList(sql_type)        # 获取Get型Payload下的所有fuzz脚本
    if url:
        print('[*] Scan url : {}'.format(url))
    elif postPath:
        print('[*] Scan post : {}'.format(postPath))

    for each in FuzzScripts:
        output = '[*] Load Fuzz {}'.format(each)
        col.OutputCyanine(output)
        init.FuzzPayload(url=url, cookie=cookie, fuzzScriptName=each[:-3], postPath=postPath)                   # 执行fuzzPayload

def cmdParser(url, cookie=None, urlsFile=None, threads=1, postPath=None):
    # options.url, options.cookies, options.urlsFile, options.threads, options.postCont, options.output
    ExpFolders = init.FuzzFloderList()
    # -u
    if url:
        scan(url=url, cookie=cookie, sql_type='get', postPath=None)
    # -d
    elif urlsFile:
        get_urls(urlsFile)
        scan_thread(q_urls, threads)
    # -p
    elif postPath:
        scan(url=None, cookie=None, sql_type='post', postPath=postPath)


def banner():
    banner = r'''
       _____  ____  _         ______                 ____             _____ _        
      / ____|/ __ \| |       |  ____|               |  _ \           / ____| |       
     | (___ | |  | | |       | |__ _   _ ________   | |_) |_   _    | (___ | | _____ 
      \___ \| |  | | |       |  __| | | |_  /_  /   |  _ <| | | |    \___ \| |/ / _ \
      ____) | |__| | |____   | |  | |_| |/ / / /    | |_) | |_| |    ____) |   <  __/
     |_____/ \___\_\______|  |_|   \__,_/___/___|   |____/ \__, |   |_____/|_|\_\___|
                                                            __/ |                    
                                                           |___/                     
    '''
    col.OutputBlue(banner)

if __name__ == '__main__':
    banner()
    usage = 'usage : &prog \npython3 scan.py -u http://target.com/id=1\n' \
            'python3 scan.py -u http://target.com/id=1 -c phpsession=1;security=low\n' \
            'python3 scan.py -d 1.txt\n' \
            'python3 scan.py -d 1.txt -t 10\n' \
            'python3 scan.py -p 2.txt\n' \
            'python3 scan.py -u/-d/-p -o ret.txt\n' \


    parse = OptionParser(usage=usage)
    parse.add_option('-u', '--url', dest='url', type='string', help='attack url')
    parse.add_option('-c', '--cookie', dest='cookie', type='string', help='the attack url needs cookie')
    parse.add_option('-d', '--urls', dest='urlsFile', type='string', help='input urls file path')
    parse.add_option('-t', '--threads', dest='threads', type='int', help='the num of scan threads', default=1)
    parse.add_option('-p', '--postPath', dest='postPath', type='string', help='the post content file')

    options, args = parse.parse_args()
    cmdParser(options.url, options.cookie, options.urlsFile, options.threads, options.postPath)
    print('scan end!')