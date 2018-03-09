语法：↓

python3 scan.py -u "http://target.com/id=1&u=2"     对指定url的所有参数尝试payload注入

python3 scan.py -u "http://target.com/id=11&u=2" -c "phpsession=1;security=low"   对指定url的所有参数尝试payload注入，且带入cookies

python3 scan.py -d urls.txt 对一个txt文件内的所有url尝试payload注入

python3 scan.py -d urls.txt -t 10    对一个txt文件内的所有url尝试payload注入，并设置线程数为10条

python3 scan.py -p 2.txt            对post提交的数据包尝试payload注入

error_blind文件夹是报错注入和延时注入，与该脚本无关，单独使用

Fuzz是get和post的payload文件夹

Libs是配置文件夹

urls是保存批量url的目录文件夹

默认保存在ret/domain.txt   

domain是网站的域名，如果是post文件，则取的是路径的最后一位