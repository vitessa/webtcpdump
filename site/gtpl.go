package site

var tmplIndex = `<!DOCTYPE html>
<html lang="zh-CN">
    <head>
        <meta charset="utf-8">
        <title>webtcpdump</title>
        <script type="application/javascript">
            function dumpToAdaptor()
            {
                location.replace("adaptor");
            }
        </script>
    </head>
    <body onload="dumpToAdaptor()">
</html>`

var tmplAdaptor = `<!DOCTYPE html>
<html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>webtcpdump</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body style="font-family:Consolas">
        <ul class="breadcrumb">
            <li><a href="/">Home</a></li>
            <li class="active">Adaptor</li>
        </ul>
        <div class="container">
            <div class="row">
                 <div class="table-responsive">
                    <table class="table table-hover table-condensed">
                        <caption>
                            All Adaptors
                        </caption>
                        <tr>
                            <th>    #       </th>
                            <th>    Name    </th>
                            <th>    IPv4    </th>
                            <th>    IPv6    </th>
                            <th>    MTU     </th>
                        </tr>
                        {{range .Adaptors}}
                        <tr>
                            <td>    {{.Idx}}                        </td>
                            <td>    {{.Name}}                       </td>
                            <td>    <a href="/listen">{{.IPv4}}</a> </td>
                            <td>    <a href="/listen">{{.IPv6}}</a> </td>
                            <td>    {{.MTU}}                        </td>
                        </tr>
                        {{end}}
                    </table>
                </div>
            </div>
        <div>
    </body>
</html>`

var tmplListen = `<!DOCTYPE html>
<html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>webtcpdump</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body style="font-family:Consolas">
        <ul class="breadcrumb">
            <li><a href="/">Home</a></li>
            <li><a href="/adaptor">Adaptor</a></li>
            <li class="active">Listen</li>
        </ul>
        <table cellpadding="4" cellspacing="4">
            <tr align="center">
                <td> <button type="button" onclick="location.assign('/')"> 主页 </button> </td>
                <td> <button type="button" onclick="history.back()"> 返回 </button> </td>
                <td> <button type="button" onclick="location.reload()"> 刷新 </button> </td>
            <tr>
        </table>

        <div class="container">
            <div class="row">
                 <div class="table-responsive">
                    <table class="table table-hover table-condensed">
                        <caption>
                            Listening Port
                        </caption>
                        <tr>
                            <th>    #           </th>
                            <th>    Addr        </th>
                            <th>    Port        </th>
                            <th>    State       </th>
                            <th>    PID         </th>
                            <th>    Program     </th>
                        </tr>
                        {{range .Stats}}
                        <tr>
                            <td>    {{.Idx}}        </td>
                            <td>    {{.SrcAddr}}    </td>
                            <td>    <a href="/establish?port={{.SrcPort}}">{{.SrcPort}}</a>  </td>
                            <td>    {{.State}}      </td>
                            <td>    {{.Pid}}        </td>
                            <td>    {{.Program}}    </td>
                        </tr>
                        {{end}}
                    </table>
                </div>
            </div>
        </div>
    </body>
</html>`

var tmplEstablish = `<!DOCTYPE html>
<html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>webtcpdump</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body style="font-family:Consolas">
        <ul class="breadcrumb">
            <li><a href="/">Home</a></li>
            <li><a href="/adaptor">Adaptor</a></li>
            <li><a href="/listen">Listen</a></li>
            <li class="active">Establish</li>
        </ul>
        <table cellpadding="4" cellspacing="4">
            <tr align="center">
                <td> <button type="button" onclick="location.assign('/')"> 主页 </button> </td>
                <td> <button type="button" onclick="history.back()"> 返回 </button> </td>
                <td> <button type="button" onclick="location.reload()"> 刷新 </button> </td>
            <tr>
        </table>
        <div class="container">
            <div class="row">
                 <div class="table-responsive">
                    <table class="table table-hover table-condensed">
                        <caption>
                            Sockets
                        </caption>
                        <tr>
                            <th>    #           </th>
                            <th>    Src IP      </th>
                            <th>    Src Port    </th>
                            <th>    Dst IP      </th>
                            <th>    Dst Port    </th>
                            <th>    State       </th>
                        </tr>
                        {{range .Stats}}
                        <tr>
                            <td>    {{.Idx}}        </td>
                            <td>    {{.SrcAddr}}    </td>
                            <td>    {{.SrcPort}}    </td>
                            <td>    {{.DstAddr}}    </td>
                            <td>    <a href="/tcpsniff?SrcAddr={{.SrcAddr}}&SrcPort={{.SrcPort}}&DstAddr={{.DstAddr}}&DstPort={{.DstPort}}">{{.DstPort}}</a>    </td>
                            <td>    {{.State}}      </td>
                        </tr>
                        {{end}}
                    </table>
                </div>
            </div>
        </div>
    </body>
</html>`

var tmplTcpSniff = `<!DOCTYPE html>
<html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>webtcpsniff</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
        <script type="application/javascript">
            function init()
            {
                if(!window.WebSocket)
                {
                    console.log('This browser does not supports WebSocket');
                    return;
                }
                initWebSocket(); 
            }
            window.addEventListener("load", init, false);

            function initWebSocket()
            {
                url = "ws://" + document.location.host + document.location.pathname + document.location.search
                const websocket = new WebSocket(url);

                websocket.addEventListener('open', function (event)
                {
                    writeToScreen("CONNECTED");
                });
                websocket.addEventListener('close', function (event)
                {
                    writeToScreen("CLOSED");
                });
                websocket.addEventListener('error', function (event)
                {
                    writeToScreen("WebSocket Error");
                });
                websocket.addEventListener('message', function (event)
                {
                    writeToScreen(event.data);
                });
            }

            function writeToScreen(message)
            {
                document.getElementById("monitor").insertAdjacentText("beforeend", message + "\n");
                // 滚动到底部
                window.scroll(0, document.body.scrollHeight);
            }

            function clickButtonTest()
            {
                writeToScreen("点击测试按钮");
            }
        </script>
    </head>
    <body style="font-family:Consolas">
        <ul class="breadcrumb">
            <li><a href="/">Home</a></li>
            <li><a href="/adaptor">Adaptor</a></li>
            <li><a href="/listen">Listen</a></li>
            <li><a href="/establish?&port={{.SrcPort}}">Establish</a></li>
            <li class="active">TcpSniff</li>
        </ul>
        <button type="button" onclick="clickButtonTest();"> 测试 </button>
        <div class="container-fluid vh-200">
            <div class="row">
                <div class="col col-xs-12 col-sm-12 col-md-12 col-lg-12">
                    <p><pre id="monitor"></pre></p>
                </div>
            </div>
        </div>
    </body>
</html>`
