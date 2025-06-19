# MyHTML

- Directory: html
- File: MyHTML

## Templates

### view-transition

```html
<div id="page-content" style="view-transition-name: page;">
    $html$
</div>
```

### reload html

```go
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reload</title>
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="icon" href="/public/favicon.ico" type="image/x-icon" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        /* Colors */
        :root {
            --bg-color: #ecf0f1;
            --text-color: #2c3e50;
        }

        body, html {
            height: 100%;
            margin: 0;
            padding: 0;
            overflow: hidden;
            font-family: Arial, sans-serif;
        }

        #contentFrame {
            position: absolute;
            top: 60px;
            left: 0;
            width: 100%;
            height: calc(100% - 60px);
            border: none;
            box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.1);
            border-radius: 10px; /* new border radius */
        }

        #navbar {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 60px;
            background-color: #2c3e50;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0 20px;
            box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.1);
        }

        #fileSelect {
            position: absolute;
            left: 10px; /* Adjust as needed */
            top: 17px; /* Adjust as needed */
            max-width: 170px;
            color: #2c3e50;
            border: none;
            background-color: #ecf0f1;
            padding: 5px 10px;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        #fileSelect:focus {
            outline: none; /* remove focus outline */
        }

        /* Style the dropdown options */
        #fileSelect option {
            padding: 5px 10px;
            background-color: #ecf0f1;
            color: #2c3e50;
        }

        #iconContainer {
            display: flex;
            gap: 15px;
        }

        .icon {
            width: 25px;
            height: 30px;
            background-color: #ecf0f1;
            border-radius: 15%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #2c3e50;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        .icon:hover {
            background-color: #bdc3c7;
        }
    </style>
</head>
<body>
<div id="navbar">
    <select id="fileSelect" onchange="loadFile()">
        <option value="">Select a file</option>
    </select>
    <div id="iconContainer">
        <div class="icon"
             onclick="setIframeWidth('mobile')">
            <i class="fas fa-mobile-alt"></i>
        </div>
        <div class="icon"
             onclick="setIframeWidth('tablet')">
            <i class="fas fa-tablet-alt"></i>
        </div>
        <div class="icon"
             onclick="setIframeWidth('fullscreen')">
            <i class="fas fa-desktop"></i>
        </div>
    </div>
</div>
<iframe id="contentFrame" src="http://localhost:8080"></iframe>

<script>
    const socket = new WebSocket("ws://localhost:8080/ws");
    socket.onmessage = function(event) {
        if (event.data === "reload") {
            document.getElementById('contentFrame').contentWindow.location.reload();
        }
    };
    socket.onclose = function() {
        console.log("WebSocket closed, attempting to reconnect...");
        setTimeout(() => window.location.reload(), 3000);
    };

    function setIframeWidth(device) {
        var iframe = document.getElementById('contentFrame');
        switch (device) {
            case 'mobile':
                iframe.style.width = '375px';
                iframe.style.left = '0';
                iframe.style.right = '0';
                iframe.style.margin = 'auto';
                break;
            case 'tablet':
                iframe.style.width = '768px';
                iframe.style.left = '0';
                iframe.style.right = '0';
                iframe.style.margin = 'auto';
                break;
            default:
                iframe.style.width = '100%';
                iframe.style.left = '0';
                iframe.style.right = '0';
                iframe.style.margin = '0';
        }
        localStorage.setItem('device', device);
    }
</script>
</body>
</html>
```