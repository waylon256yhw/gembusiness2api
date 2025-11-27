import json, time, hmac, hashlib, base64, os, asyncio, uuid, ssl, re
from datetime import datetime
from typing import List, Optional, Union, Dict, Any
import logging

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# ---------- 日志配置 ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gemini")

# ---------- 配置 ----------
SECURE_C_SES = os.getenv("SECURE_C_SES")
HOST_C_OSES  = os.getenv("HOST_C_OSES")
CSESIDX      = os.getenv("CSESIDX")
CONFIG_ID    = os.getenv("CONFIG_ID")
PROXY        = os.getenv("PROXY") or None
TIMEOUT_SECONDS = 600 

# ---------- 模型映射配置 ----------
MODEL_MAPPING = {
    "gemini-auto": None,
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-3-pro-preview": "gemini-3-pro-preview"
}

# ---------- 全局 Session 缓存 ----------
SESSION_CACHE: Dict[str, dict] = {}

# ---------- HTTP 客户端 ----------
http_client = httpx.AsyncClient(
    proxies=PROXY,
    verify=False,
    http2=False,
    timeout=httpx.Timeout(TIMEOUT_SECONDS, connect=60.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
)

# ---------- 工具函数 ----------
def get_common_headers(jwt: str) -> dict:
    return {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "authorization": f"Bearer {jwt}",
        "content-type": "application/json",
        "origin": "https://business.gemini.google",
        "referer": "https://business.gemini.google/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "x-server-timeout": "1800",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
    }

def urlsafe_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def kq_encode(s: str) -> str:
    b = bytearray()
    for ch in s:
        v = ord(ch)
        if v > 255:
            b.append(v & 255)
            b.append(v >> 8)
        else:
            b.append(v)
    return urlsafe_b64encode(bytes(b))

def create_jwt(key_bytes: bytes, key_id: str, csesidx: str) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT", "kid": key_id}
    payload = {
        "iss": "https://business.gemini.google",
        "aud": "https://biz-discoveryengine.googleapis.com",
        "sub": f"csesidx/{csesidx}",
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }
    header_b64  = kq_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = kq_encode(json.dumps(payload, separators=(",", ":")))
    message     = f"{header_b64}.{payload_b64}"
    sig         = hmac.new(key_bytes, message.encode(), hashlib.sha256).digest()
    return f"{message}.{urlsafe_b64encode(sig)}"

# ---------- JWT 管理 ----------
class JWTManager:
    def __init__(self) -> None:
        self.jwt: str = ""
        self.expires: float = 0
        self._lock = asyncio.Lock()

    async def get(self) -> str:
        async with self._lock:
            if time.time() > self.expires:
                await self._refresh()
            return self.jwt

    async def _refresh(self) -> None:
        cookie = f"__Secure-C_SES={SECURE_C_SES}"
        if HOST_C_OSES:
            cookie += f"; __Host-C_OSES={HOST_C_OSES}"
        
        logger.debug("🔑 正在刷新 JWT...")
        r = await http_client.get(
            "https://business.gemini.google/auth/getoxsrf",
            params={"csesidx": CSESIDX},
            headers={
                "cookie": cookie,
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
                "referer": "https://business.gemini.google/"
            },
        )
        if r.status_code != 200:
            logger.error(f"❌ getoxsrf 失败: {r.status_code} {r.text}")
            raise HTTPException(r.status_code, "getoxsrf failed")
        
        txt = r.text[4:] if r.text.startswith(")]}'") else r.text
        data = json.loads(txt)

        key_bytes = base64.urlsafe_b64decode(data["xsrfToken"] + "==")
        self.jwt     = create_jwt(key_bytes, data["keyId"], CSESIDX)
        self.expires = time.time() + 270
        logger.info(f"✅ JWT 刷新成功")

jwt_mgr = JWTManager()

# ---------- Session & File 管理 ----------
async def create_google_session() -> str:
    jwt = await jwt_mgr.get()
    headers = get_common_headers(jwt)
    body = {
        "configId": CONFIG_ID,
        "additionalParams": {"token": "-"},
        "createSessionRequest": {
            "session": {"name": "", "displayName": ""}
        }
    }
    
    logger.debug("🌐 申请新 Session...")
    r = await http_client.post(
        "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetCreateSession",
        headers=headers,
        json=body,
    )
    if r.status_code != 200:
        logger.error(f"❌ createSession 失败: {r.status_code} {r.text}")
        raise HTTPException(r.status_code, "createSession failed")
    sess_name = r.json()["session"]["name"]
    return sess_name

async def upload_context_file(session_name: str, mime_type: str, base64_content: str) -> str:
    """上传文件到指定 Session，返回 fileId"""
    jwt = await jwt_mgr.get()
    headers = get_common_headers(jwt)
    
    # 生成随机文件名
    ext = mime_type.split('/')[-1] if '/' in mime_type else "bin"
    file_name = f"upload_{int(time.time())}_{uuid.uuid4().hex[:6]}.{ext}"

    body = {
        "configId": CONFIG_ID,
        "additionalParams": {"token": "-"},
        "addContextFileRequest": {
            "name": session_name,
            "fileName": file_name,
            "mimeType": mime_type,
            "fileContents": base64_content
        }
    }

    logger.info(f"📤 上传图片 [{mime_type}] 到 Session...")
    r = await http_client.post(
        "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetAddContextFile",
        headers=headers,
        json=body,
    )

    if r.status_code != 200:
        logger.error(f"❌ 上传文件失败: {r.status_code} {r.text}")
        raise HTTPException(r.status_code, f"Upload failed: {r.text}")
    
    data = r.json()
    file_id = data.get("addContextFileResponse", {}).get("fileId")
    logger.info(f"✅ 图片上传成功, ID: {file_id}")
    return file_id

# ---------- 消息处理逻辑 ----------
def get_conversation_key(messages: List[dict]) -> str:
    if not messages: return "empty"
    # 仅使用第一条消息的内容生成指纹，忽略图片数据防止指纹过大
    first_msg = messages[0].copy()
    if isinstance(first_msg.get("content"), list):
        # 如果第一条是多模态，只取文本部分做 Hash
        text_part = "".join([x["text"] for x in first_msg["content"] if x["type"] == "text"])
        first_msg["content"] = text_part
    
    key_str = json.dumps(first_msg, sort_keys=True)
    return hashlib.md5(key_str.encode()).hexdigest()

def parse_last_message(messages: List['Message']):
    """解析最后一条消息，分离文本和图片"""
    if not messages:
        return "", []
    
    last_msg = messages[-1]
    content = last_msg.content
    
    text_content = ""
    images = [] # List of {"mime": str, "data": str_base64}

    if isinstance(content, str):
        text_content = content
    elif isinstance(content, list):
        for part in content:
            if part.get("type") == "text":
                text_content += part.get("text", "")
            elif part.get("type") == "image_url":
                url = part.get("image_url", {}).get("url", "")
                # 解析 Data URI: data:image/png;base64,xxxxxx
                match = re.match(r"data:(image/[^;]+);base64,(.+)", url)
                if match:
                    images.append({"mime": match.group(1), "data": match.group(2)})
                else:
                    logger.warning(f"⚠️ 暂不支持非 Base64 图片链接: {url[:30]}...")

    return text_content, images

def build_full_context_text(messages: List['Message']) -> str:
    """仅拼接历史文本，图片只处理当次请求的"""
    prompt = ""
    for msg in messages:
        role = "User" if msg.role in ["user", "system"] else "Assistant"
        content_str = ""
        if isinstance(msg.content, str):
            content_str = msg.content
        elif isinstance(msg.content, list):
            for part in msg.content:
                if part.get("type") == "text":
                    content_str += part.get("text", "")
                elif part.get("type") == "image_url":
                    content_str += "[图片]"
        
        prompt += f"{role}: {content_str}\n\n"
    return prompt

# ---------- OpenAI 兼容接口 ----------
app = FastAPI(title="Gemini-Business OpenAI Gateway")

class Message(BaseModel):
    role: str
    content: Union[str, List[Dict[str, Any]]]

class ChatRequest(BaseModel):
    model: str = "gemini-auto"
    messages: List[Message]
    stream: bool = False
    temperature: Optional[float] = 0.7
    top_p: Optional[float] = 1.0

def create_chunk(id: str, created: int, model: str, delta: dict, finish_reason: Union[str, None]) -> str:
    chunk = {
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": delta,
            "finish_reason": finish_reason
        }]
    }
    return json.dumps(chunk)

@app.get("/v1/models")
async def list_models():
    data = []
    now = int(time.time())
    for m in MODEL_MAPPING.keys():
        data.append({
            "id": m,
            "object": "model",
            "created": now,
            "owned_by": "google",
            "permission": []
        })
    return {"object": "list", "data": data}

@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

@app.post("/v1/chat/completions")
async def chat(req: ChatRequest):
    # 1. 模型校验
    if req.model not in MODEL_MAPPING:
        raise HTTPException(status_code=404, detail=f"Model '{req.model}' not found.")

    # 2. 解析请求内容
    last_text, current_images = parse_last_message(req.messages)
    
    # 3. 锚定 Session
    conv_key = get_conversation_key([m.dict() for m in req.messages])
    cached = SESSION_CACHE.get(conv_key)
    
    if cached:
        google_session = cached["session_id"]
        text_to_send = last_text
        logger.info(f"♻️ 延续旧对话 [{req.model}]: {google_session[-12:]}")
        SESSION_CACHE[conv_key]["updated_at"] = time.time()
        is_retry_mode = False
    else:
        logger.info(f"🆕 开启新对话 [{req.model}]")
        google_session = await create_google_session()
        # 新对话使用全量文本上下文 (图片只传当前的)
        text_to_send = build_full_context_text(req.messages)
        SESSION_CACHE[conv_key] = {"session_id": google_session, "updated_at": time.time()}
        is_retry_mode = True

    chat_id = f"chatcmpl-{uuid.uuid4()}"
    created_time = int(time.time())

    # 封装生成器 (含图片上传和重试逻辑)
    async def response_wrapper():
        retry_count = 0
        max_retries = 2
        
        current_text = text_to_send
        current_retry_mode = is_retry_mode
        
        # 图片 ID 列表 (每次 Session 变化都需要重新上传，因为 fileId 绑定在 Session 上)
        current_file_ids = []

        while retry_count <= max_retries:
            try:
                current_session = SESSION_CACHE[conv_key]["session_id"]
                
                # A. 如果有图片且还没上传到当前 Session，先上传
                # 注意：每次重试如果是新 Session，都需要重新上传图片
                if current_images and not current_file_ids:
                    for img in current_images:
                        fid = await upload_context_file(current_session, img["mime"], img["data"])
                        current_file_ids.append(fid)

                # B. 准备文本 (重试模式下发全文)
                if current_retry_mode:
                    current_text = build_full_context_text(req.messages)

                # C. 发起对话
                async for chunk in stream_chat_generator(
                    current_session, 
                    current_text, 
                    current_file_ids, 
                    req.model, 
                    chat_id, 
                    created_time, 
                    req.stream
                ):
                    yield chunk
                break 

            except (httpx.ConnectError, httpx.ReadTimeout, ssl.SSLError, HTTPException) as e:
                retry_count += 1
                logger.warning(f"⚠️ 请求异常 (重试 {retry_count}/{max_retries}): {e}")

                if retry_count <= max_retries:
                    logger.info("🔄 尝试重建 Session...")
                    try:
                        new_sess = await create_google_session()
                        SESSION_CACHE[conv_key] = {"session_id": new_sess, "updated_at": time.time()}
                        current_retry_mode = True 
                        current_file_ids = [] # 清空 ID，强制下次循环重新上传到新 Session
                    except Exception as create_err:
                        logger.error(f"❌ 重建失败: {create_err}")
                        if req.stream: yield f"data: {json.dumps({'error': {'message': 'Session Recovery Failed'}})}\n\n"
                        return
                else:
                    if req.stream: yield f"data: {json.dumps({'error': {'message': f'Final Error: {e}'}})}\n\n"
                    return

    if req.stream:
        return StreamingResponse(response_wrapper(), media_type="text/event-stream")
    
    full_content = ""
    async for chunk_str in response_wrapper():
        if chunk_str.startswith("data: [DONE]"): break
        if chunk_str.startswith("data: "):
            try:
                data = json.loads(chunk_str[6:])
                delta = data["choices"][0]["delta"]
                if "content" in delta: full_content += delta["content"]
            except: pass

    return {
        "id": chat_id,
        "object": "chat.completion",
        "created": created_time,
        "model": req.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": full_content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    }

async def stream_chat_generator(session: str, text_content: str, file_ids: List[str], model_name: str, chat_id: str, created_time: int, is_stream: bool = True):
    jwt = await jwt_mgr.get()
    headers = get_common_headers(jwt)
    
    body = {
        "configId": CONFIG_ID,
        "additionalParams": {"token": "-"},
        "streamAssistRequest": {
            "session": session,
            "query": {"parts": [{"text": text_content}]},
            "filter": "",
            "fileIds": file_ids, # 注入文件 ID
            "answerGenerationMode": "NORMAL",
            "toolsSpec": {
                "webGroundingSpec": {},
                "toolRegistry": "default_tool_registry",
                "imageGenerationSpec": {},
                "videoGenerationSpec": {}
            },
            "languageCode": "zh-CN",
            "userMetadata": {"timeZone": "Asia/Shanghai"},
            "assistSkippingMode": "REQUEST_ASSIST"
        }
    }

    target_model_id = MODEL_MAPPING.get(model_name)
    if target_model_id:
        body["streamAssistRequest"]["assistGenerationConfig"] = {
            "modelId": target_model_id
        }

    if is_stream:
        chunk = create_chunk(chat_id, created_time, model_name, {"role": "assistant"}, None)
        yield f"data: {chunk}\n\n"

    r = await http_client.post(
        "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetStreamAssist",
        headers=headers,
        json=body,
    )
    
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=f"Upstream Error {r.text}")

    try:
        data_list = r.json()
    except Exception as e:
        logger.error(f"❌ JSON 解析失败: {e}")
        raise HTTPException(status_code=502, detail="Invalid JSON response")

    for data in data_list:
        for reply in data.get("streamAssistResponse", {}).get("answer", {}).get("replies", []):
            text = reply.get("groundedContent", {}).get("content", {}).get("text", "")
            if text and not reply.get("thought"):
                chunk = create_chunk(chat_id, created_time, model_name, {"content": text}, None)
                if is_stream:
                    yield f"data: {chunk}\n\n"
    
    if is_stream:
        final_chunk = create_chunk(chat_id, created_time, model_name, {}, "stop")
        yield f"data: {final_chunk}\n\n"
        yield "data: [DONE]\n\n"

if __name__ == "__main__":
    if not all([SECURE_C_SES, CSESIDX, CONFIG_ID]):
        print("Error: Missing required environment variables.")
        exit(1)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)