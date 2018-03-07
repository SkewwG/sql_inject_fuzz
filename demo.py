# # 测试脚本
# import requests
#
# url = "http://demo.dvwa.com/vulnerabilities/sqli/?id=1' and 1=1&Submit=Submit#"
# # data1 = "uname=admin' and 1=1 --+&passwd=123&submit=Submit"
# # data2 = "uname=admin' and 1=2 #&passwd=admin&submit=Submit"
# # headers = {'Content-Type': 'application/x-www-form-urlencoded'}
# headers = {"cookie" : None}
# #cookies = {"Cookie": 'PHPSESSID=43k4h77471cisstqfu747o56b7; security=low'}
# res = requests.get(url=url, headers=headers)
# ret = res.text
# code = res.status_code
#
# length = len(ret)
# print(ret)
# print(code)
# print(length)


with open(r'C:\Users\Asus\Desktop\py\py3\project\sql_inject_fuzz\1.txt', 'rt') as f:
    # print(f.readlines())
    for each in f.readlines():
        if '\n' == each:
            print('ok')