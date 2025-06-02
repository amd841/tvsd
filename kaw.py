import requests
# import oauthlib.oauth1
import oauth2 
# from requests_oauthlib import OAuth2Session
# from requests_oauthlib import OAuth1Session
# from requests_oauthlib import OAuth1
import base64
import hmac
import hashlib
import json
from flask import Flask
class Consumer:
  def __init__(self, key, secret):
    self.key = key
    self.secret = secret

class Token:
  def __init__(self, key, secret):
    self.key = key
    self.secret = secret



app = Flask(__name__)

@app.route("/")
def hello_world():
    # return "<p>Hello, World!</p>"
    x = requests.get('https://sepehrtv.ir/frame/t/alkosar')
    data = x.text
    # print(data)
    data  = data[data.index("_app"):data.index("_app") +16+8]
    # print(data)
    x = requests.get('https://sepehrtv.ir/_next/static/chunks/pages/'+data)
    data = x.text
    data = data[data.index("{consumer:{key:"):]
    key = data[16:32+16]
    secret = data[data.index("secret:")+8:data.index("secret:")+8+32]
    token = data[data.index('getItem("secret")')+20:]
    tokenkey = token[token.index('"')+ 1 :token.index('"')+ 65]
    tokensecret = token[token.index('getItem("token")')+20:]
    tokensecret = tokensecret[tokensecret.index('"')+ 1 :tokensecret.index('"')+ 65]
    # print('tokenkey',tokenkey)
    # print('tokensecret',tokensecret)
    # print('tokenkey',tokenkey)
    # exit()
    # token
    # print('key',key)
    # print('secret',secret)
    # print('token',tokenkey)

    url = "https://sepehrapi.sepehrtv.ir/v3/channels/?key=alkosar&include_media_resources=true&include_details=true"
    parameters = {
        "oauth_consumer_key": key,
        "oauth_nonce": oauth2.generate_nonce(),
        "oauth_timestamp": oauth2.generate_timestamp(),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_version": "1.0",
        # Other parameters...
    }

    # # Create a Client object
    # client = oauthlib.oauth1.Client(key, client_secret=secret)

    # # Generate the OAuth signature
    # uri, headers, body = client.sign(url, http_method='GET', parameters=parameters)
    # The signature will be in the Authorization header
    # oauth_signature = headers['Authorization'].split('oauth_signature="')[1].split('"')[0]
    # print("OAuth Signature:", oauth_signature)

    # x = requests.get(url,data=parameters)
    # data = x.text
    # print(data)
    # oauth = OAuth1Session(key, client_secret=secret)
    # fetch_response = oauth.fetch_request_token(url)

    ###
    # sts_clear = request.method + "\n"             # HTTP verb
    # sts_clear += "\n"                             # Content MD5
    # sts_clear += "\n"                             # Content type
    # sts_clear += self.tstamp + "\n"               # Date
    # sts_clear += request.path_url                 # Canonicalized resource

    ##
    # sts_base64 = base64.b64encode(url.encode("utf-8"))
    # sts_digest = hmac.new(secret.encode("utf-8"), sts_base64, hashlib.sha1)
    # signature = base64.b64encode(sts_digest.digest())
    # print('signature',signature)
    # signature = base64.b64encode(hmac.new(key, secret, hashlib.sha1).digest())
    # print('signature',signature)

    # oauth = OAuth1(key, client_secret=secret,signature_method='HMAC-SHA1')
    # r = requests.get(url=url, auth=oauth)
    # print(r)
    # print(r.content)

    # consumer = {'secret':secret,'key':key}
    tokenC = Token(tokenkey,tokensecret)
    consumer = Consumer(key, secret)

    params = {
                "oauth_version": "1.0",
                "oauth_nonce": oauth2.generate_nonce(),
                "oauth_timestamp": str(oauth2.generate_timestamp()),
                "oauth_token": tokenC.key,
                "oauth_consumer_key": consumer.key,
                "oauth_signature_method":"HMAC-SHA1"
            }
    req = oauth2.Request(method="GET", url=url, parameters=params)
    signature_method = oauth2.SignatureMethod_HMAC_SHA1()
    # print(consumer.secret)
    req.sign_request(signature_method, consumer, tokenC)
    headers = req.to_header()
    payload = {}

    # print('headers',headers)
    # print('url',url)
    # print(payload)
    params = {
                "key": "alkosar",
                "include_media_resources": 'true',
                "include_details": 'true',
            }

    response = requests.request("GET", url, headers=headers)
    # response = requests.get(url,headers=headers,params=params)
        
    lista = json.loads(response.text)
    channel = lista['list'][0]['streams'][0]['src']
    fileData = requests.get(channel)
    # print(fileData.text)
    print(channel)
    print(fileData.text.replace('\n','<br>').replace('576p.m3u8',channel[:channel.index('alkawtharsd.m')] + '576p.m3u8'))
    # return fileData.text


hello_world()
