import logging
import requests
import asyncio
import time
import httpx
import json
import urllib3
from io import BytesIO
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
from cachetools import TTLCache
from PIL import Image, ImageDraw, ImageFont
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from datetime import datetime, UTC
from Crypto.Cipher import AES
from collections.abc import Iterable
import base64
from flask_caching import Cache
from typing import Tuple, Optional
import my_pb2
import output_pb2
import requests
import binascii
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timezone
import random
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from protobuf_decoder.protobuf_decoder import Parser
from requests.exceptions import RequestException
from typing import Dict, Any, List, Union
import unicodedata
import re
import jwt 
import os
from PIL import Image
import io
import concurrent.futures
import tempfile
# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB49"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}
TIMEOUT = httpx.Timeout(30.0, connect=60.0)
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
MAX_WORKERS = 5  # Number of concurrent image downloads
TIMEOUT = 8  # Seconds for each request
IMAGE_SIZE = (220, 220)
PADDING = 20
COLUMNS = 7
KEY_VALIDATION_URL = "https://scvirtual.alphi.media/botsistem/sendlike/expire_key.json"
def fetch_attversion():
    url = "https://pt.textbin.net/raw/alrhw5dehl"  # Link com JSON simples

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        def buscar_attversion(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k == "attversion":
                        return v
                    resultado = buscar_attversion(v)
                    if resultado is not None:
                        return resultado
            elif isinstance(d, list):
                for item in d:
                    resultado = buscar_attversion(item)
                    if resultado is not None:
                        return resultado
            return None
        
        attversion = buscar_attversion(data)
        if attversion is not None:
            print(f"attversion: {attversion}")
            return attversion
        else:
            print("Parâmetro 'attversion' não encontrado.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
    except ValueError:
        print("Erro ao decodificar o JSON.")
def process_account_data(json_data: Dict[str, Any], my_id: int = None) -> Dict[str, Any]:
    """
    Processa dados de contas garantindo nicknames legíveis no JSON de saída.
    Filtra apenas contas do Brasil (country == "BR").

    Retorna:
    {
        "credits": "@scvirtual",
        "status": "success/error",
        "message": "",
        "data": [contas],
        "timestamp": "YYYY-MM-DD HH:MM:SS"
    }
    """
    response = {
        "credits": "@scvirtual",
        "status": "success",
        "message": "",
        "data": [],
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    try:
        def get_nested(data: Dict, path: List[str], default=None):
            """Acesso seguro a dados aninhados"""
            for key in path:
                if isinstance(data, dict):
                    data = data.get(key, default)
                else:
                    return default
            return data

        def extract_nick(nick_data: Any) -> str:
            """Extrai nickname mantendo caracteres especiais"""
            if isinstance(nick_data, str):
                return nick_data
            elif isinstance(nick_data, dict):
                return nick_data.get('data', '')
            return ''

        # Processamento principal
        main_data = get_nested(json_data, ['1'], {})
        
        accounts = []
        if isinstance(main_data, list):
            for item in main_data:
                if account_data := get_nested(item, ['data'], {}):
                    accounts.append(account_data)
        elif isinstance(main_data, dict):
            if account_data := get_nested(main_data, ['data'], {}):
                accounts.append(account_data)

        # Processa contas
        seen_ids = set()
        for account in accounts:
            try:
                account_id = get_nested(account, ['1', 'data'])
                if not account_id or account_id in seen_ids:
                    continue
                
                country = get_nested(account, ['5', 'data'], "")
                

                seen_ids.add(account_id)
                
                response['data'].append({
                    "nameid": account_id,
                    "namenick": extract_nick(get_nested(account, ['3', 'data'])),
                    "accountlike": get_nested(account, ['21', 'data'], 0),
                    "accountlevel": get_nested(account, ['6', 'data'], 0),
                    "country": country
                })
            except:
                continue

        # Ordenação
        if my_id and response['data']:
            response['data'].sort(key=lambda x: (
                x['nameid'] != my_id,
                -x['accountlike'],
                x['nameid'] or 0
            ))

    except Exception as e:
        response.update({
            "status": "error",
            "message": f"Erro no processamento: {str(e)}",
            "data": []
        })

    # Garante que os caracteres Unicode não serão escapados
    return json.loads(json.dumps(response, ensure_ascii=False))

def Encrypt_Text(nick):
    encoded_bytes = nick.encode('utf-8')
    length = len(encoded_bytes)
    
    # Formatar o comprimento em 2 dígitos hex
    length_hex = f"{length:02x}"
    
    # Converter cada byte para hexadecimal
    hex_data = encoded_bytes.hex()
    
    # Formatar no padrão desejado: 0a + comprimento + dados
    return f"0a{length_hex}{hex_data}"



# === Pre-downloaded assets ===

NIVEL_ICONES = {
    "admin": "https://dl.dir.freefiremobile.com/common/OB49/CSH/FF_UI_Badge_KOL03.png",
    "vip": "https://dl.dir.freefiremobile.com/common/OB49/CSH/FF_UI_Badge_KOL02.png",
    "user": "https://dl.dir.freefiremobile.com/common/OB49/CSH/FF_UI_Badge_KOL01.png"
}

FONT_URL = "https://raw.githubusercontent.com/Thong-ihealth/arial-unicode/main/Arial-Unicode-Bold.ttf"

# Dicionário para armazenar os dados dos ícones baixados
ICONS_DATA = {}

for nivel, icon_url in NIVEL_ICONES.items():
    try:
        resp = requests.get(icon_url)
        resp.raise_for_status()
        ICONS_DATA[nivel] = resp.content
        logging.info("Ícone '%s' baixado com sucesso: %s", nivel, icon_url)
    except Exception as e:
        logging.error("Erro ao baixar ícone '%s' (%s): %s", nivel, icon_url, e)
        ICONS_DATA[nivel] = None
    try:
        resp = requests.get(FONT_URL)
        resp.raise_for_status()
        FONT_DATA = resp.content
        logging.info("Fonte personalizada baixada com sucesso.")
    except Exception as e:
        logging.error(f"Erro ao baixar a fonte, usando padrão: {e}")
        FONT_DATA = None

# Exemplo: acessar os dados do ícone de celebrity
BADGE_DATA = ICONS_DATA.get("celebrity")
BADGE_DATA1 = ICONS_DATA.get("admin")
BADGE_DATA2 = ICONS_DATA.get("vip")

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.DEBUG)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
def is_uid_in_list(uid):
    url = "http://scvirtual.alphi.media/botsistem/sendlike/verified.json"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Erro ao carregar JSON: {e}")
        return False, None

    uid_str = str(uid)

    if uid_str in data:
        info = data[uid_str]
        if isinstance(info, dict):
            nivel = info.get("nivel", None)
            return True, nivel
        else:
            # UID está presente, mas não tem informação de nível
            return True, None
    else:
        return False, None



def get_custom_font(size):
    if FONT_DATA:
        try:
            return ImageFont.truetype(BytesIO(FONT_DATA), int(size))
        except Exception as e:
            logging.error("Error loading truetype from FONT_DATA: %s", e)
    return ImageFont.load_default()

def fetch_image(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return Image.open(BytesIO(resp.content)).convert("RGBA")
    except Exception as e:
        logging.error("Image fetch error from %s: %s", url, e)
        return None

def get_banner_url(banner_id):
    return f"https://raw.githubusercontent.com/minimalsend/RESOURCES_FF/refs/heads/main/BANNERS/{banner_id}.png"

def get_avatar_url(avatar_id):
    return f"https://raw.githubusercontent.com/minimalsend/RESOURCES_FF/refs/heads/main/AVATARS/{avatar_id}.png"

# Text positions & sizes
ACCOUNT_NAME_POSITION   = {"x": 62,  "y": 0,  "font_size": 12.5}
ACCOUNT_LEVEL_POSITION  = {"x": 180, "y": 45, "font_size": 12.5}
GUILD_NAME_POSITION     = {"x": 62,  "y": 40, "font_size": 12.5}
AVATAR_POSITION         = {"x": 0,   "y": 0,  "width": 60, "height": 60}
PIN_POSITION            = {"x": 0,   "y": 40, "width": 20, "height": 20}
BADGE_POSITION          = {"x": 35,  "y": -1,  "width": 28, "height": 28}

SCALE = 8
FALLBACK_BANNER_ID = "900000014"
FALLBACK_AVATAR_ID = "900000013"

# === Crypto & Protobuf Helpers ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        
        if result.wire_type == "varint":
            field_data['data'] = result.data
        elif result.wire_type == "string":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data['data'] = parse_results(result.data.results)
        
        # Sempre adiciona como lista para campos repetidos
        if result.field in result_dict:
            if not isinstance(result_dict[result.field], list):
                # Se não for lista ainda, transforma o valor existente em lista
                result_dict[result.field] = [result_dict[result.field]]
            # Adiciona o novo valor à lista
            result_dict[result.field].append(field_data)
        else:
            # Para o primeiro valor, armazena diretamente (será convertido para lista se repetir)
            result_dict[result.field] = field_data
    
    return result_dict
def parse_rst(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        
        if result.wire_type == "varint":
            field_data['data'] = result.data
        elif result.wire_type == "string":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data['data'] = parse_rst(result.data.results)
        
        # Se o campo já existe, transforma em uma lista ou adiciona à lista existente
        if result.field in result_dict:
            if isinstance(result_dict[result.field], list):
                result_dict[result.field].append(field_data)
            else:
                # Se já existe um valor único, converte em uma lista
                result_dict[result.field] = [result_dict[result.field], field_data]
        else:
            result_dict[result.field] = field_data
    
    return result_dict
def parse_rst2(parsed_results):
    result_dict = {}

    # Acessa o atributo .results se parsed_results não for iterável diretamente
    results = getattr(parsed_results, 'results', parsed_results)

    for result in results:
        field_data = {
            'wire_type': result.wire_type
        }

        if result.wire_type in ("varint", "string"):
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            if hasattr(result.data, 'results'):
                field_data['data'] = parse_rst2(result.data)
            else:
                field_data['data'] = str(result.data)

        if result.field in result_dict:
            if isinstance(result_dict[result.field], list):
                result_dict[result.field].append(field_data)
            else:
                result_dict[result.field] = [result_dict[result.field], field_data]
        else:
            result_dict[result.field] = field_data

    return result_dict
def parse_rst4(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        
        if result.wire_type == "varint":
            field_data['data'] = result.data
        elif result.wire_type == "string":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data['data'] = parse_results(result.data.results)
        
        # Se o campo já existe, transforma em uma lista ou adiciona à lista existente
        if result.field in result_dict:
            if isinstance(result_dict[result.field], list):
                result_dict[result.field].append(field_data)
            else:
                # Se já existe um valor único, converte em uma lista
                result_dict[result.field] = [result_dict[result.field], field_data]
        else:
            result_dict[result.field] = field_data
    
    return result_dict
def load_tokens2():
    try:
        # Link direto para o JSON BR
        url = "https://scvirtual.alphi.media/botsistem/sendlike/tokenbr.json"
        
        response = requests.get(url)
        response.raise_for_status()  # Verifica se a requisição foi bem-sucedida
        
        tokens_data = response.json()  # Converte para lista de dicionários
        
        # Extrai apenas os valores dos tokens para uma lista
        tokens_list = [item["token"] for item in tokens_data if "token" in item]
        
        # Seleciona um token aleatório se houver tokens disponíveis
        if tokens_list:
            return random.choice(tokens_list)
        return None

    except Exception as e:
        print(f"Error loading tokens: {e}")  # Mensagem de erro sem server_name
        return None
def parse_rst3(parsed_results):
    result_dict = {}

    # Acessa o atributo .results se parsed_results não for iterável diretamente
    results = getattr(parsed_results, 'results', parsed_results)

    for result in results:
        field_data = {
            'wire_type': result.wire_type
        }

        if result.wire_type in ("varint", "string"):
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            if hasattr(result.data, 'results'):
                field_data['data'] = parse_rst3(result.data)
            else:
                field_data['data'] = str(result.data)

        if result.field in result_dict:
            if isinstance(result_dict[result.field], list):
                result_dict[result.field].append(field_data)
            else:
                result_dict[result.field] = [result_dict[result.field], field_data]
        else:
            result_dict[result.field] = field_data

    return result_dict
def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)
def get_available_room2(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_rst(parsed_results)
    return json.dumps(parsed_results_dict)
def get_available_room3(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_rst2(parsed_results)
    return json.dumps(parsed_results_dict)
def get_available_room4(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_rst3(parsed_results)
    return json.dumps(parsed_results_dict)
def get_available_room5(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_rst4(parsed_results)
    return json.dumps(parsed_results_dict)
def getgallery(input_json):
    output = {
        "credits": "@scvirtual",
        "items": []
    }

    def extract_target_ids(data):
        if isinstance(data, dict):
            # Verifica se é um objeto com campo "6" contendo os IDs que queremos
            if "6" in data and isinstance(data["6"], dict):
                if "data" in data["6"] and isinstance(data["6"]["data"], dict):
                    if "6" in data["6"]["data"] and isinstance(data["6"]["data"]["6"], dict):
                        if "data" in data["6"]["data"]["6"]:
                            item_id = data["6"]["data"]["6"]["data"]
                            output["items"].append({"itemId": item_id})
            
            # Continua procurando em outros campos
            for value in data.values():
                extract_target_ids(value)
                
        elif isinstance(data, list):
            for item in data:
                extract_target_ids(item)

    extract_target_ids(input_json)
    return output
def geteventinfo(input_json):
    output = {
        "Credit": "@scvirtual",
        "Region": "BR",
        "events": []
    }

    # Dicionário temporário para agrupar eventos pelo título
    events_by_title = {}

    # Processa eventos da Seção "1" (eventos normais)
    if "1" in input_json and "data" in input_json["1"]:
        if "1" in input_json["1"]["data"]:
            for item in input_json["1"]["data"]["1"]:
                if "data" not in item:
                    continue

                data = item["data"]

                # Verifica se a região é BR
                if "12" not in data or data["12"].get("data") != "BR":
                    continue

                # Extrai os dados básicos do evento
                title = data.get("3", {}).get("data", "")
                description = data.get("9", {}).get("data", "")
                image = data.get("5", {}).get("data", "")
                link = data.get("20", {}).get("data", data.get("8", {}).get("data", ""))

                # Pula se não tiver título
                if not title:
                    continue

                # Converte os timestamps para datas
                start_timestamp = data.get("10", {}).get("data") if "10" in data and data["10"]["wire_type"] == "varint" else None
                end_timestamp = data.get("11", {}).get("data") if "11" in data and data["11"]["wire_type"] == "varint" else None

                # Se o título já existe no dicionário, mescla as datas
                if title in events_by_title:
                    existing_event = events_by_title[title]

                    if start_timestamp and (existing_event["start_timestamp"] is None or start_timestamp < existing_event["start_timestamp"]):
                        existing_event["start_timestamp"] = start_timestamp

                    if end_timestamp and (existing_event["end_timestamp"] is None or end_timestamp > existing_event["end_timestamp"]):
                        existing_event["end_timestamp"] = end_timestamp

                    if not existing_event["description"] and description:
                        existing_event["description"] = description
                    if not existing_event["link"] and link:
                        existing_event["link"] = link
                    if not existing_event["image"] and image:
                        existing_event["image"] = image
                else:
                    events_by_title[title] = {
                        "title": title,
                        "start_timestamp": start_timestamp,
                        "end_timestamp": end_timestamp,
                        "description": description,
                        "link": link,
                        "image": image
                    }

    # Processa eventos da Seção "2" (promoções)
    if "2" in input_json and "data" in input_json["2"]:
        if "1" in input_json["2"]["data"]:
            for item in input_json["2"]["data"]["1"]:
                if "data" not in item:
                    continue

                data = item["data"]

                # Verifica se a região é BR
                if "1" not in data or data["1"].get("data") != "BR":
                    continue

                # Extrai os dados da promoção (tratando como um evento normal)
                title = data.get("4", {}).get("data", "")
                image = data.get("14", {}).get("data", "")
                start_timestamp = data.get("6", {}).get("data") if "6" in data and data["6"]["wire_type"] == "varint" else None
                end_timestamp = data.get("7", {}).get("data") if "7" in data and data["7"]["wire_type"] == "varint" else None

                # Se for uma promoção de diamantes, ajusta o título para ficar mais amigável
                if "[REVENUE]" in title:
                    title = title.replace("[REVENUE]", "").strip()
                elif "[PRODUCT]" in title:
                    title = title.replace("[PRODUCT]", "").strip()

                if not title:
                    continue

                # Se o título já existe, mescla (caso contrário, adiciona como novo evento)
                if title in events_by_title:
                    existing_event = events_by_title[title]

                    if start_timestamp and (existing_event["start_timestamp"] is None or start_timestamp < existing_event["start_timestamp"]):
                        existing_event["start_timestamp"] = start_timestamp

                    if end_timestamp and (existing_event["end_timestamp"] is None or end_timestamp > existing_event["end_timestamp"]):
                        existing_event["end_timestamp"] = end_timestamp

                    if not existing_event["image"] and image:
                        existing_event["image"] = image
                else:
                    events_by_title[title] = {
                        "title": title,
                        "start_timestamp": start_timestamp,
                        "end_timestamp": end_timestamp,
                        "description": "",  # Promoções geralmente não têm descrição
                        "link": "",  # Promoções geralmente não têm link externo
                        "image": image
                    }

    # Agora processa todos os eventos (Seção 1 + Seção 2) para criar a saída final
    now = datetime.now().timestamp()

    for title, event_data in events_by_title.items():
        # Formata as datas
        start = datetime.utcfromtimestamp(event_data["start_timestamp"]).strftime('%Y-%m-%d %H:%M:%S') if event_data["start_timestamp"] else ""
        end = datetime.utcfromtimestamp(event_data["end_timestamp"]).strftime('%Y-%m-%d %H:%M:%S') if event_data["end_timestamp"] else ""

        # Determina o status
        status = "Por vir"
        if event_data["start_timestamp"] and event_data["end_timestamp"]:
            if now >= event_data["start_timestamp"] and now <= event_data["end_timestamp"]:
                status = "Ativo"
            elif now > event_data["end_timestamp"]:
                status = "Encerrado"

        output["events"].append({
            "Tittle": title,
            "start": start,
            "end": end,
            "description": event_data["description"],
            "source": event_data["image"],
            "link": event_data["link"],
            "status": status
        })

    # Ordena os eventos por data de início
    output["events"].sort(
        key=lambda x: datetime.strptime(x["start"], '%Y-%m-%d %H:%M:%S') if x["start"] else datetime.min,
        reverse=True
    )

    return output
def updwish(input_json):
    output = {
        "credits": "@scvirtual",
        "items": []
    }

    # Acessa a lista de itens dentro da chave "1"
    items_list = input_json.get("1", [])
    if not isinstance(items_list, list):
        items_list = [items_list]

    for item in items_list:
        if "data" in item and isinstance(item["data"], dict):
            data = item["data"]
            if "1" in data and "2" in data:
                item_id = data["1"]["data"]
                release_time = data["2"]["data"]
                output["items"].append({
                    "itemId": item_id,
                    "releaseTime": release_time
                })

    return output
def getwish(input_json):
    output = {
        "credits": "@scvirtual",
        "items": []
    }

    # Acessa a lista de itens dentro da chave "1"
    items_list = input_json.get("1", [])
    if not isinstance(items_list, list):
        items_list = [items_list]

    for item in items_list:
        if "data" in item and isinstance(item["data"], dict):
            data = item["data"]
            if "1" in data and "2" in data:
                item_id = data["1"]["data"]
                release_time = data["2"]["data"]
                output["items"].append({
                    "itemId": item_id,
                    "releaseTime": release_time
                })

    return output
def is_valid_key(user_key):
    """Verifica se a key é válida ou expirada no JSON remoto"""
    try:
        # Força atualização do cache
        headers = {'Cache-Control': 'no-cache', 'Pragma': 'no-cache'}
        response = requests.get(KEY_VALIDATION_URL, headers=headers)

        keys_data = response.json()

        for key_info in keys_data.get("keys", []):
            
            if key_info["key"].strip() == user_key.strip():
                expiration_time = int(key_info["expires"])
                current_time = int(datetime.now(UTC).timestamp())
              
                return current_time < expiration_time

        return False

    except Exception as e:
        return False

def parse_protobuf_data(binary_data):
    """Parse os dados binários diretamente para o protobuf"""
    response = app_pb2.EventResponse()
    response.ParseFromString(binary_data)
    return response
def parse_response(content: str) -> dict:
    """Parse protobuf response into dictionary."""
    return dict(
        line.split(":", 1)
        for line in content.split("\n")
        if ":" in line
    )
def consultar_token_e_openid(access_token: str) -> dict:
    # 1. Consultar token na API da Garena
    url_garena = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
    headers_garena = {
        "access-token": access_token,
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://reward.ff.garena.com",
        "Referer": "https://reward.ff.garena.com/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
    }

    try:
        response = requests.get(url_garena, headers=headers_garena)
        response.raise_for_status()
        garena_data = response.json()
    except Exception as e:
        return {"erro": f"❌ Erro ao consultar token da Garena: {str(e)}"}

    uid = garena_data.get("uid")
    if not uid:
        return {"erro": "❌ UID não encontrado na resposta da Garena."}

    # 2. Consultar open_id usando o UID
    url_openid = "https://recargajogo.com.br/api/auth/player_id_login"
    payload = {
        "app_id": 100067,
        "login_id": str(uid)
    }

    headers_openid = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; SM-A137F Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.39 Mobile Safari/537.36",
        "sec-ch-ua-platform": "Android",
        "sec-ch-ua": '"Android WebView";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?1",
        "Origin": "https://recargajogo.com.br",
        "X-Requested-With": "com.xbrowser.play",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://recargajogo.com.br/?app=100067&channel=221070&item=67390",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9,bn-BD;q=0.8,bn;q=0.7",
        "Cookie": (
            "source=mb; region=BD; mspid2=80e513899ce7c59b2e61d208dd630a0b; "
            "_ga=GA1.1.1038399898.1733795308; "
            "datadome=sGHR4ZTAyW6zcAJXIvRZNOQTEWAFneXpFzU5XB9nZka7OA9o93bjtYTyy1e0IKx0FPY__JXhRgVoaEG5iV5G5PU2fnelMEuxCgqbuzWXCRELnAkmFPGgQFtSlBLEGeoh; "
            "session_key=4y34scvpgk2h8l0b5v1ppvxnzev6ov96; "
            "_ga_6F84K2JN88=GS1.1.1733795308.1.1.1733795370.0.0.0"
        )
    }

    try:
        resp_openid = requests.post(url_openid, json=payload, headers=headers_openid)
        resp_openid.raise_for_status()
        openid_data = resp_openid.json()
    except Exception as e:
        return {"erro": f"❌ Erro ao consultar open_id: {str(e)}"}

    if "erro" in openid_data:
        return {"erro": f"❌ Erro da API do open_id: {openid_data['erro']}"}

    open_id = openid_data.get("open_id", "")

    return {
        "uid": uid,
        "open_id": open_id,
        "name": garena_data.get("name"),
        "region": garena_data.get("region"),
        "token": garena_data.get("token")
    }
def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext)
    return cipher.encrypt(padded_message)
def majorlogin_jwt(access_tokens):
    access_token = access_tokens

    if not access_token:
        return {"erro": "❌ access_token não fornecido."}, 400

    fech_token = consultar_token_e_openid(access_token)

    if 'erro' in fech_token:
        return fech_token, 400

    open_id = fech_token.get('open_id')
    versionob = fetch_attversion()
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": f'{versionob}'
    }

    for platform_type in range(1, 12):  # 1 até 7
        game_data = my_pb2.GameData()
        game_data.timestamp = "2024-12-05 18:15:32"
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.108.3"
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = platform_type
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)

        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')
        edata = bytes.fromhex(hex_encrypted_data)

        try:
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=5)

            try:
                json_resp = response.json()
                if json_resp.get("message") == "BR_PLATFORM_INVALID_PLATFORM\n":
                    print(f"Platform {platform_type} inválida, tentando próxima...")
                    continue  # tenta próxima
            except ValueError:
                json_resp = {}

            if response.status_code == 200:
                try:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(response.content)
                    data_dict = {field.name: getattr(example_msg, field.name)
                                 for field in example_msg.DESCRIPTOR.fields
                                 if field.name not in ["binary", "binary_data", "Garena420"]}
                except Exception:
                    try:
                        data_dict = response.json()
                    except ValueError:
                        return jsonify({"message": response.text}), 200

                if data_dict and "token" in data_dict:
                    token_value = data_dict["token"]
                    try:
                        decoded_token = jwt.decode(token_value, options={"verify_signature": False})
                    except Exception as e:
                        decoded_token = {"error": str(e)}
                    return jsonify({
                        "token": token_value,
                        "@scvirtual": decoded_token,
                        "platform_type": platform_type
                    }), 200
                else:
                    return jsonify({"message": "No token found in response"}), 200

        except requests.RequestException as e:
            continue  # tenta próxima

    return jsonify({"message": "❌ Todos os platform_type de 1 a 7 resultaram em BR_PLATFORM_INVALID_PLATFORM"}), 400

def GetAccountInformation(uid: str, unk: str, region: str, endpoint: str) -> dict:
    """Get player account information."""
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")

    try:
        # Monta o payload protobuf
        proto_message = main_pb2.GetPlayerPersonalShow()
        json_format.ParseDict({'a': uid, 'b': unk}, proto_message)
        payload = proto_message.SerializeToString()

        # Encripta com AES CBC
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

        # Pega o token JWT e limpa possíveis aspas
        jwtlogin = load_tokens()
        versionob = fetch_attversion()

        print(f"[DEBUG] JWT usado: {jwtlogin}")

        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': f'{versionob}',
            'Content-Type': 'application/octet-stream',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwtlogin}',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"

        with httpx.Client(timeout=TIMEOUT) as client:
            try:
                response = client.post(url, data=data_enc, headers=headers)
                response.raise_for_status()

                # Decodificar a resposta protobuf
                decoded_message = AccountPersonalShow_pb2.AccountPersonalShowInfo()
                decoded_message.ParseFromString(response.content)

                # Converter para JSON legível
                json_data = json.loads(json_format.MessageToJson(decoded_message))

                return json_data

            except httpx.HTTPStatusError as http_err:
                print(f"[HTTP ERROR] Status: {http_err.response.status_code} - {http_err.response.text}")
                raise ValueError(f"HTTP Error {http_err.response.status_code}: {http_err.response.text}")

            except httpx.RequestError as req_err:
                print(f"[REQUEST ERROR] Request to {req_err.request.url} failed: {str(req_err)}")
                raise ValueError(f"Request error: {str(req_err)}")

            except Exception as e:
                print(f"[CLIENT ERROR] Unexpected error in HTTP client: {str(e)}")
                raise ValueError(f"Client error: {str(e)}")

    except Exception as e:
        print(f"[GENERAL ERROR] {str(e)}")
        raise ValueError(f"Failed to get account info: {str(e)}")
# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator
def transform_protobuf_to_output(event_response):
    """Transforma a mensagem protobuf para o formato de saída"""
    output = app_pb2.FinalOutput()
    output.credit = "@scvirtual"
    output.region = "BR"
    
    now = datetime.now().timestamp()
    
    if event_response.HasField('event_group'):
        for item in event_response.event_group.items:
            if not item.data.region or item.data.region != "BR":
                continue
                
            if not item.data.title:
                continue
                
            # Cria evento transformado
            transformed_event = output.events.add()
            transformed_event.title = item.data.title
            transformed_event.source = item.data.source if item.data.source else ""
            
            # Processa tempos
            if item.data.start_time:
                transformed_event.start = datetime.utcfromtimestamp(item.data.start_time).strftime('%Y-%m-%d %H:%M:%S')
            
            if item.data.end_time:
                transformed_event.end = datetime.utcfromtimestamp(item.data.end_time).strftime('%Y-%m-%d %H:%M:%S')
            
            # Determina status
            if item.data.start_time and item.data.end_time:
                if now >= item.data.start_time and now <= item.data.end_time:
                    transformed_event.status = "Ativo"
                elif now > item.data.end_time:
                    transformed_event.status = "Encerrado"
                else:
                    transformed_event.status = "Por vir"
            else:
                transformed_event.status = "Por vir"
    
    # Ordena eventos
    output.events.sort(key=lambda x: x.start if x.start else "", reverse=True)
    return output
def load_tokens():
    try:
        # Link direto para o JSON BR
        url = "https://scvirtual.alphi.media/botsistem/sendlike/tokenvip.json"
        
        response = requests.get(url)
        response.raise_for_status()  # Verifica se a requisição foi bem-sucedida
        
        tokens_data = response.json()  # Converte para lista de dicionários
        
        # Extrai apenas os valores dos tokens para uma lista
        tokens_list = [item["token"] for item in tokens_data if "token" in item]
        
        # Seleciona um token aleatório se houver tokens disponíveis
        if tokens_list:
            return random.choice(tokens_list)
        return None

    except Exception as e:
        print(f"Error loading tokens: {e}")  # Mensagem de erro sem server_name
        return None
        
#DONT EDIT
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text))
    return cipher_text.hex()
@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

@app.route('/player-info')
def get_account_info():
    """Endpoint to get player information."""
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid or not region:
        return jsonify({"error": "UID and REGION are required"}), 400

    try:
        return_data = GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        return jsonify(return_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/get-events', methods=['GET'])
def get_player_info():
    try:
        user_key = request.args.get('key')

        # 🔑 Validação da chave
        if not is_valid_key(user_key):
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": "Chave inválida ou expirada",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 403

        # 🔑 Obter token JWT
        jwt_token = load_tokens()
        if not jwt_token:
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": "Falha ao gerar token JWT",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        # 📦 Versão e payload
        versionob = fetch_attversion()
        data_hex = "9223af2eab91b7a150d528f657731074"
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as e:
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": f"Erro ao codificar dados: {str(e)}",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        # 🔧 Headers
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': versionob,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwt_token}',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive'
        }

        # 🚀 Request
        try:
            endpoint = "https://client.us.freefiremobile.com/LoginGetSplash"
            response = requests.post(endpoint, headers=headers, data=data, timeout=10)
        except requests.exceptions.RequestException as e:
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": f"Erro na requisição: {str(e)}",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        # ⚠️ Verificação do status HTTP
        if response.status_code != 200:
            return jsonify({
                "credits": "TEAM-AKIRU",
                "message": f"API retornou status {response.status_code}",
                "status": "error",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), response.status_code

        # 🎯 Tenta protobuf primeiro
        try:
            event_response = app_pb2.EventResponse()
            event_response.ParseFromString(response.content)
            final_output = transform_protobuf_to_output(event_response)
            output_dict = MessageToDict(final_output)
            return jsonify(output_dict)

        except Exception as protobuf_error:
            # 🔄 Se protobuf falhar, tenta via hex
            try:
                hex_response = binascii.hexlify(response.content).decode('utf-8')
                json_result = get_available_room(hex_response)
                parsed_data = json.loads(json_result)
                transformed_data = geteventinfo(parsed_data)
                return jsonify(transformed_data)
            except Exception as hex_error:
                return jsonify({
                    "credits": "TEAM-AKIRU",
                    "message": "Erro ao processar resposta",
                    "status": "error",
                    "raw_response": binascii.hexlify(response.content).decode('utf-8'),
                    "protobuf_error": str(protobuf_error),
                    "hex_error": str(hex_error),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }), 500

    except Exception as e:
        # ⚠️ Aqui havia bug: "response" pode não existir no escopo do erro
        return jsonify({
            "credits": "TEAM-AKIRU",
            "message": f"Erro inesperado: {str(e)}",
            "status": "error",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500
@app.route('/get-acc', methods=['GET'])
def get_name():
    try:
        versionob = fetch_attversion()
        player_id = request.args.get('acc')
        user_key = request.args.get('key')

        if not is_valid_key(user_key):
            return jsonify({"error": "Chave inválida ou expirada."}), 403

        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "credits": "@scvirtual",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        jwt_token = load_tokens()  # Make sure this function is defined
        if not jwt_token:
            return jsonify({
                "status": "error",
                "message": "Failed to generate JWT token",
                "credits": "@scvirtual",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        data = bytes.fromhex(encrypt_api(Encrypt_Text(player_id)))  # Make sure encrypt_api and Encrypt_ID functions are defined
        url = "https://client.us.freefiremobile.com/FuzzySearchAccountByName"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': f'{versionob}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwt_token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)

        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room2(hex_response)  # Make sure this function is defined
            parsed_data = json.loads(json_result)
            transformed_data = process_account_data(parsed_data)
            print(json.dumps(transformed_data, indent=2, ensure_ascii=False))
            return jsonify(transformed_data)
        else:
            return jsonify({
                "status": "error",
                "message": f"API request failed with status code {response.status_code}",
                "credits": "@scvirtual",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), response.status_code

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "credits": "@scvirtual",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500
@app.route('/get-wishlist', methods=['GET'])
def getwishinfo():
    try:
        player_id = request.args.get('id')
        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "credits": "@scvirtual",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        jwt_token = load_tokens()
        if not jwt_token:
            return jsonify({
                "status": "error",
                "message": "Failed to generate JWT token",
                "credits": "@scvirtual",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500
        versionob = fetch_attversion()
        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))
        url = "https://client.us.freefiremobile.com/GetWishListItems"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion':  f'{versionob}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwt_token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)

        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room3(hex_response)
            parsed_data = json.loads(json_result)
            transformed_data = getwish(parsed_data)
            return jsonify(transformed_data)
        else:
            return jsonify({
                "status": "error",
                "message": f"API request failed with status code {response.status_code}",
                "credits": "@scvirtual",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), response.status_code

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "credits": "@scvirtual",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500
@app.route('/set-wishlist', methods=['GET'])
def updwishlistinfo():
    try:
        versionob = fetch_attversion()
        iditems = request.args.get('id')
        value = request.args.get('value')  # add ou del
        jwt_param = request.args.get('jwt')  # JWT opcional via query param
        access_token = request.args.get('access_token')

        if not iditems or value not in ['add', 'del']:
            return jsonify({
                "status": "error",
                "message": "Player ID e valor 'add' ou 'del' são obrigatórios",
                "credits": "@scvirtual",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        # Obtendo JWT
        if jwt_param:
            jwt_token = jwt_param
        elif access_token:
            response_obj, status_code = majorlogin_jwt(access_token)
            json_data = response_obj.get_json() if response_obj else {}
            bearer_token_response = json_data
            jwt_token = bearer_token_response.get("token") if bearer_token_response else None
            print("JWT gerado via access_token:", jwt_token)
        else:
            jwt_token = load_tokens2()
            print("JWT carregado aleatório:", jwt_token)

        if not jwt_token:
            return jsonify({
                "status": "error",
                "message": "Falha ao obter JWT token",
                "credits": "@scvirtual",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        # Decodifica o JWT sem verificar assinatura
        try:
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            account_id = decoded.get("account_id", "desconhecido")
        except Exception:
            account_id = "erro_ao_decodificar"

        id_list = [iditem.strip() for iditem in iditems.split(',') if iditem.strip()]
        results = []

        # Payloads com replace específico
        payloads = {
            "add": [
                {"template": "0a05fcf9c9d20212001a1146756c6c53637265656e50726576696577", "replace": "fcf9c9d202"},
                {"template": "0a04a8f9e86012001a0750726f66696c65", "replace": "a8f9e860"}
            ],
            "del": [
                {"template": "0a001205fcf9c9d202221146756c6c53637265656e50726576696577", "replace": "fcf9c9d202"},
                {"template": "0a001204a8f9e8602208576973684c697374", "replace": "a8f9e860"}
            ]
        }

        url = "https://client.us.freefiremobile.com/ChangeWishListItem"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': f'{versionob}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwt_token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        for iditem in id_list:
            success = False
            for pl in payloads[value]:
                try:
                    iddd = Encrypt_ID(iditem)
                    final_payload = pl["template"]
                    if pl["replace"]:
                        final_payload = final_payload.replace(pl["replace"], iddd)
                    data = bytes.fromhex(encrypt_api(final_payload))

                    response = requests.post(url, headers=headers, data=data, verify=False)

                    if response.status_code == 200:
                        hex_response = binascii.hexlify(response.content).decode('utf-8')
                        json_result = get_available_room4(hex_response)
                        parsed_data = json.loads(json_result)
                        transformed_data = updwish(parsed_data)

                        results.append({
                            "id": iditem,
                            "status": "success",
                            "message": f"Wishlist item {'adicionado' if value == 'add' else 'removido'} com sucesso.",
                            "data": transformed_data
                        })
                        success = True
                        break  # se deu certo, não tenta o próximo payload
                except Exception:
                    continue  # tenta o próximo payload

            if not success:
                results.append({
                    "id": iditem,
                    "status": "error",
                    "message": "API request failed after trying all payloads"
                })

        all_success = all(result['status'] == 'success' for result in results)

        return jsonify({
            "status": "success" if all_success else "partial",
            "account_id": account_id,
            "results": results,
            "credits": "@scvirtual",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200 if all_success else 207

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "credits": "@scvirtual",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

@app.route('/getimgid', methods=['GET'])
def genimg():
    try:
        # Get parameters
        ids_param = request.args.get('ids')
        region = request.args.get('region', 'br')
        
        if not ids_param:
            return Response("IDs parameter is required", status=400, mimetype='text/plain')

        # Split IDs by comma and clean up
        item_ids = [id.strip() for id in ids_param.split(',') if id.strip()]
        if not item_ids:
            return Response("No valid IDs provided", status=400, mimetype='text/plain')

        # Process images concurrently
        with tempfile.TemporaryDirectory() as img_dir:
            images = downliad(item_ids, img_dir)
            if not images:
                return Response("No valid images found", status=404, mimetype='text/plain')

            # Create composite image
            composite_image = craetioon(images)
            
            # Return the image
            img_io = io.BytesIO()
            composite_image.save(img_io, 'PNG')
            img_io.seek(0)
            
            return Response(img_io.getvalue(), mimetype='image/png')

    except Exception as e:
        print(f"Error in generate_image: {str(e)}")
        return Response("Internal Server Error", status=500, mimetype='text/plain')


def downliad(item_ids, img_dir):
    images = []
    
    def download_single_image(item_id):
        try:
            # Primeira tentativa - getimage-omega
            image_url = f"https://get-image-vert.vercel.app/get_image?id={item_id}"
            response = requests.get(image_url, stream=True, timeout=TIMEOUT)
            
            if response.status_code == 200 and 'image' in response.headers.get('Content-Type', ''):
                image_path = os.path.join(img_dir, f"{item_id}.png")
                with open(image_path, 'wb') as f:
                    for chunk in response.iter_content(1024):
                        f.write(chunk)
                return {"path": image_path, "name": f"{item_id}.png"}
            
            # Segunda tentativa - advimage (se a primeira falhou)
            image_url = f"https://advapi-dun.vercel.app/get_image?id={item_id}"
            response = requests.get(image_url, stream=True, timeout=TIMEOUT)
            
            if response.status_code == 200 and 'image' in response.headers.get('Content-Type', ''):
                image_path = os.path.join(img_dir, f"{item_id}.png")
                with open(image_path, 'wb') as f:
                    for chunk in response.iter_content(1024):
                        f.write(chunk)
                return {"path": image_path, "name": f"{item_id}.png"}
                
        except requests.exceptions.RequestException as e:
            print(f"Error downloading image {item_id}: {str(e)}")
        except Exception as e:
            print(f"Unexpected error with image {item_id}: {str(e)}")
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(download_single_image, item_id) for item_id in item_ids]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                images.append(result)
    
    return images

def craetioon(images):
    # Caso especial: apenas uma imagem (tratamento como no PHP)
    if len(images) == 1:
        # Tamanho maior para imagem única (900x900 como no PHP)
        SINGLE_WIDTH, SINGLE_HEIGHT = 900, 900
        
        try:
            image = images[0]
            output_image = Image.new('RGB', (SINGLE_WIDTH, SINGLE_HEIGHT), (10, 10, 30))
            
            # Carregar fundo baseado na raridade (equivalente ao PHP)
            bg_path = get_background_path(image["name"])
            if os.path.exists(bg_path):
                with Image.open(bg_path) as bg_image:
                    bg_image = bg_image.resize((SINGLE_WIDTH, SINGLE_HEIGHT))
                    output_image.paste(bg_image, (0, 0))
            
            # Carregar e posicionar a imagem principal (50% do espaço como no PHP)
            with Image.open(image["path"]).convert("RGBA") as icon_image:
                target_width = SINGLE_WIDTH * 0.5
                target_height = SINGLE_HEIGHT * 0.5
                
                ratio = min(target_width/icon_image.width, target_height/icon_image.height)
                new_size = (int(icon_image.width * ratio), int(icon_image.height * ratio))
                icon_image = icon_image.resize(new_size, Image.Resampling.LANCZOS)
                
                pos = (
                    (SINGLE_WIDTH - new_size[0]) // 2,
                    (SINGLE_HEIGHT - new_size[1]) // 2
                )
                output_image.paste(icon_image, pos, icon_image)
            
            return output_image
            
        except Exception as e:
            print(f"Error processing single image {image['name']}: {str(e)}")
            # Se falhar, continua para o processamento normal abaixo

    # Processamento normal para múltiplas imagens (mantendo seu código original)
    width, height = IMAGE_SIZE
    rows = (len(images) + COLUMNS - 1) // COLUMNS
    image_width = COLUMNS * (width + PADDING) - PADDING
    image_height = rows * (height + PADDING) - PADDING

    output_image = Image.new('RGB', (image_width, image_height), (10, 10, 30))
    
    for index, image in enumerate(images):
        try:
            row, col = divmod(index, COLUMNS)
            x = col * (width + PADDING)
            y = row * (height + PADDING)
            
            # Open and process icon
            with Image.open(image["path"]).convert("RGBA") as icon_image:
                # Get background based on first digit
                bg_path = get_background_path(image["name"])
                if os.path.exists(bg_path):
                    with Image.open(bg_path) as bg_image:
                        bg_image = bg_image.resize((width, height))
                        output_image.paste(bg_image, (x, y))
                
                # Resize and center icon
                ratio = min(width/icon_image.width, height/icon_image.height)
                new_size = (int(icon_image.width * ratio), int(icon_image.height * ratio))
                icon_image = icon_image.resize(new_size, Image.Resampling.LANCZOS)
                pos = (
                    x + (width - new_size[0]) // 2,
                    y + (height - new_size[1]) // 2
                )
                output_image.paste(icon_image, pos, icon_image)
                
        except Exception as e:
            print(f"Error processing image {image['name']}: {str(e)}")
            continue
    
    return output_image

def get_background_path(image_name):
    # Extrai os dígitos do nome da imagem
    digits_match = re.search(r'\d+', image_name)
    item_id = int(digits_match.group(0)) if digits_match else 0

    php_url = "https://scvirtual.alphi.media/botsistem/sendlike/classrare.php"  # Altere se necessário
    default_bg = os.path.join("rows", "row4.png")

    try:
        response = requests.post(php_url, data={'id': item_id}, timeout=5)
        if response.status_code != 200:
            return default_bg

        data = response.json()

        # Verifica se houve erro
        if 'error' in data:
            return default_bg

        # Usa o número da raridade diretamente (ex: "1", "4", etc.)
        rare_id = data.get('rareid', '4')
        image_filename = f"row{rare_id}.png"
        return os.path.join("rows", image_filename)

    except Exception as e:
        print(f"Erro ao consultar o PHP: {e}")
        return default_bg
@app.route('/get-galery', methods=['GET'])
def getgalleryinfo():
    try:
        player_id = request.args.get('id')
        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "credits": "TEAM-AKIRU",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        jwt_token = load_tokens()  # Make sure this function is defined
        if not jwt_token:
            return jsonify({
                "status": "error",
                "message": "Failed to generate JWT token",
                "credits": "TEAM-AKIRU",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500
        versionob = fetch_attversion()
        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))  # Make sure encrypt_api and Encrypt_ID functions are defined
        url = "https://client.us.freefiremobile.com/GetPlayerGalleryShowInfo"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': f'{versionob}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwt_token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)

        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room5(hex_response)  # Make sure this function is defined
            parsed_data = json.loads(json_result)
            transformed_data = getgallery(parsed_data)  # Aplica a transformação
            return transformed_data
        else:
            return jsonify({
                "status": "error",
                "message": f"API request failed with status code {response.status_code}",
                "credits": "TEAM-AKIRU",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), response.status_code

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "credits": "TEAM-AKIRU",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
