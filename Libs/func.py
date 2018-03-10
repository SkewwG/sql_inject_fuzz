import os
import sys
from Libs.color import *
from urllib.parse import urlparse
import os

col = Color()
root_path = os.getcwd()

# 定义Fuzz文件夹各个功能的类
class FuzzFunction():
    def __init__(self):
        self.path = os.getcwd() + '/Fuzz/'     # 跳到根目录

    # 列出Fuzz文件夹内的所有注入类型文件夹名字
    def FuzzFloderList(self):
        FolderList = filter(lambda x : (True,False)[x[-3:] == '.py'], os.listdir(self.path))
        return FolderList

    # 列出某个注入类型下的所有fuzz脚本
    def FuzzScriptList(self, FuzzFloder):
        ScriptList = filter(lambda x : (True,False)[x[-3:] == 'pyc' or x[-5:] == '__.py' or x[:2] == '__'], os.listdir(self.path + FuzzFloder))
        return ScriptList

    # 保存结果
    def save(self, domain, colPayload):
        path = root_path + '/ret/{}.txt'.format(domain)
        with open(path, 'at', encoding='utf-8') as f:
            f.writelines(colPayload + '\n')

    # 执行payload
    def FuzzPayload(self, url, cookie, fuzzScriptName, postPath):
        domain = urlparse(url).netloc if url else postPath.split('.txt')[0][-1]
        md = __import__(fuzzScriptName)
        #print(md)
        try:
            if hasattr(md, 'Fuzz'):
                fuzz = getattr(md, 'Fuzz')(url=url, cookie=cookie, postPath=postPath)
                RedPayloads, YellowPayloads, BluePayloads, GreenPayloads, wafPayloads = fuzz.attack()
                # col.OutputGreen('[+Success] : {}'.format(ret)) if ret else col.OutputRed('[-Fail]')
                print('Output Result : ↓')
                if RedPayloads:
                    for RedPayload in RedPayloads:
                        col.OutputRed('[+Success+] : {}'.format(RedPayload))
                        self.save(domain, RedPayload)

                        # with open('{}/ret/ret.txt'.format(os.getcwd()), 'at') as f:
                        #     ret = '%-30s %s\n' % (url, expName)
                        #     f.writelines(ret)
                if YellowPayloads:
                    for YellowPayload in YellowPayloads:
                        col.OutputYellow('[+SQL syntax+] : {}'.format(YellowPayload))
                        self.save(domain, YellowPayload)
                if BluePayloads:
                    for BluePayload in BluePayloads:
                        col.OutputBlue('[$Maybe$] : {}'.format(BluePayload))
                        self.save(domain, BluePayload)
                if wafPayloads:
                    for wafPayload in wafPayloads:
                        col.OutputRed('[-检测到WAF-] : {}'.format(wafPayload))
                        self.save(domain, wafPayload)
                if GreenPayloads:
                    pass
                    # for GreenPayload in GreenPayloads:
                    #     col.OutputGreen('[-Fail-] : {}'.format(GreenPayload))
        except Exception as e:
            print(e)

    # 给系统环境变量添加FuzzFloder的路径
    def setSysPath(self, FuzzFloder):
        sys.path.append(self.path + FuzzFloder)


# expFunction = ExpFunction()
# expFunction.setSysPath('phpcms')
# expFunction.ExeExp('phpcms_down','http://demo.phpcms960.com')

