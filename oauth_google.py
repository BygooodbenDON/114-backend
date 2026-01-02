import os
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from fastapi import HTTPException, status

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

def verify_google_id_token(token: str):
    """驗證從前端或 Postman 傳來的 Google ID Token"""
    try:
        # 這裡會去向 Google 的伺服器驗證 token 是否合法、過期
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        # 返回 Google 使用者資訊 (email, name, sub...)
        return idinfo
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="無效的 Google Token"
        )
def exchange_code_for_tokenas(code: str, redirect_uri: str)-> dict:
    """使用授權碼向 Google 換取 ID Token 和 Access Token"""
    payload = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    response = requests.post(GOOGLE_TOKEN_URL, data=payload)

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"無法換取 Token: {response.json().get('error_description', '未知錯誤')}"
        )
    return response.json()  # 包含 access_token, id_token 等資訊