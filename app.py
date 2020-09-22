# -*- coding: utf-8 -*-  
import os
import json
import logging
import requests
import time
import datetime
import hmac
import hashlib
import base64
import urllib.parse
from urllib.parse import urlparse

from flask import Flask
from flask import request

app = Flask(__name__)

logging.basicConfig(
    level=logging.DEBUG if os.getenv('LOG_LEVEL') == 'debug' else logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s')


@app.route('/API/runner', methods=['POST', 'GET'])
def send():
    if request.method == 'POST':
        post_data = request.get_data()
        app.logger.debug(post_data)
        send_alert(json.loads(post_data))
        return 'success'
    else:
        return 'weclome to use prometheus alertmanager dingtalk webhook server!'


def send_alert(data):
    token = os.getenv('ROBOT_TOKEN')
    secret = os.getenv('ROBOT_SECRET')
    if not token:
        app.logger.error('you must set ROBOT_TOKEN env')
        return
    if not secret:
        app.logger.error('you must set ROBOT_SECRET env')
        return
    timestamp = int(round(time.time() * 1000))
    url = 'https://oapi.dingtalk.com/robot/send?access_token=%s&timestamp=%d&sign=%s' % (token, timestamp, make_sign(timestamp, secret))

    for data in data['alerts']:
        title = data["labels"]["severity"]
        instance = '- 告警实例: %s\n' % data["labels"]["instance"] if data["labels"].get("instance") else ""
        alertname = '- 告警事件: %s\n' % data["labels"]["alertname"]
        summary = '- 告警详情: %s\n' % data["annotations"]["summary"]
        description = '- 所属项目: %s\n' % data["annotations"]["description"]
        startsAt = '- 开始时间: %s\n' %  str(datetime.datetime.strptime(data["startsAt"].split('.')[0], "%Y-%m-%dT%H:%M:%S") + datetime.timedelta(hours=8))

        if data["status"] == "resolved":
            stat = '# <font color=#006600>recovery</font>\n'
            endsAt = '- 恢复时间: %s\n' % str(datetime.datetime.strptime(data["endsAt"].split('.')[0], "%Y-%m-%dT%H:%M:%S") + datetime.timedelta(hours=8))
            recive_data = stat + alertname + instance + description + summary + startsAt + endsAt
        elif data["labels"]["severity"] == 'warning':
            stat = '# <font color=#FF9933>%s</font>\n' % data["labels"]["severity"]
            recive_data = stat + alertname + instance + description + summary + startsAt
        else:
            stat = '# <font color=#CC0000>%s</font>\n' % data["labels"]["severity"]
            recive_data = stat + alertname + instance + description + summary + startsAt
        
        send_data = {
            "msgtype": "markdown",
            "markdown": {
            "title":title,
            "text":recive_data
            },
            "at":{
            "atMobiles":[
            ],
            "isAtAll":True
            }
        }
        req = requests.post(url, json=send_data)
        result = req.json()
        if result['errcode'] != 0:
            app.logger.error(result)

def make_sign(timestamp, secret):
    """新版钉钉更新了安全策略，这里我们采用签名的方式进行安全认证
    https://ding-doc.dingtalk.com/doc#/serverapi2/qf2nxq
    """
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    return sign


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
