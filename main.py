import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say
from aiohttp import web
import asyncio
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# VariabLes dyli 
#------------------------------------------#
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
fast_spam_running = False
fast_spam_task = None
custom_spam_running = False
custom_spam_task = None
spam_request_running = False
spam_request_task = None
evo_fast_spam_running = False
evo_fast_spam_task = None
evo_custom_spam_running = False
evo_custom_spam_task = None
lag_running = False
lag_task = None
# Globals exposed to webhook handler (set at login)
GLOBAL_KEY = None
GLOBAL_IV = None
GLOBAL_REGION = None
GLOBAL_AUTH_TOKEN = None
webhook_server_started = False
#------------------------------------------#

# Emote mapping for evo commands
EMOTE_MAP = {
    1: 909000063,
    2: 909000081,
    3: 909000075,
    4: 909000085,
    5: 909000134,
    6: 909000098,
    7: 909035007,
    8: 909051012,
    9: 909000141,
    10: 909034008,
    11: 909051015,
    12: 909041002,
    13: 909039004,
    14: 909042008,
    15: 909051014,
    16: 909039012,
    17: 909040010,
    18: 909035010,
    19: 909041005,
    20: 909051003,
    21: 909034001
}

# Helper functions for ghost join
def dec_to_hex(decimal):
    """Convert decimal to hex string"""
    hex_str = hex(decimal)[2:]
    return hex_str.upper() if len(hex_str) % 2 == 0 else '0' + hex_str.upper()

async def encrypt_packet(packet_hex, key, iv):
    """Encrypt packet using AES CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    packet_bytes = bytes.fromhex(packet_hex)
    padded_packet = pad(packet_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded_packet)
    return encrypted.hex()

async def nmnmmmmn(packet_hex, key, iv):
    """Wrapper for encrypt_packet"""
    return await encrypt_packet(packet_hex, key, iv)

async def ghost_join_packet(player_id, secret_code, key, iv):
    """Create ghost join packet"""
    try:
        # Create a simple packet structure for joining
        # This is a basic implementation - adjust based on your needs
        packet_data = f"01{dec_to_hex(len(secret_code))}{secret_code.encode().hex()}"
        
        # Encrypt the packet
        encrypted_packet = await encrypt_packet(packet_data, key, iv)
        
        # Create header
        header_length = len(encrypted_packet) // 2
        header_length_hex = dec_to_hex(header_length)
        
        # Build final packet based on header length
        if len(header_length_hex) == 2:
            final_packet = "0515000000" + header_length_hex + encrypted_packet
        elif len(header_length_hex) == 3:
            final_packet = "051500000" + header_length_hex + encrypted_packet
        elif len(header_length_hex) == 4:
            final_packet = "05150000" + header_length_hex + encrypted_packet
        elif len(header_length_hex) == 5:
            final_packet = "0515000" + header_length_hex + encrypted_packet
        else:
            final_packet = "0515000000" + header_length_hex + encrypted_packet
            
        return bytes.fromhex(final_packet)
        
    except Exception as e:
        print(f"Error creating ghost join packet: {e}")
        return None

async def lag_team_loop(team_code, key, iv, region):
    """Rapid join/leave loop to create lag"""
    global lag_running
    count = 0
    
    while lag_running:
        try:
            # Join the team
            join_packet = await GenJoinSquadsPacket(team_code, key, iv)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
            
            # Very short delay before leaving
            await asyncio.sleep(0.01)  # 10 milliseconds
            
            # Leave the team
            leave_packet = await ExiT(None, key, iv)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)
            
            count += 1
            print(f"Lag cycle #{count} completed for team: {team_code}")
            
            # Short delay before next cycle
            await asyncio.sleep(0.01)  # 10 milliseconds between cycles
            
        except Exception as e:
            print(f"Error in lag loop: {e}")
            # Continue the loop even if there's an error
            await asyncio.sleep(0.1)
 
####################################

#Clan-info-by-clan-id
def Get_clan_info(clan_id):
    try:
        url = f"https://get-clan-info.vercel.app/get_clan_info?clan_id={clan_id}"
        res = requests.get(url)
        if res.status_code == 200:
            data = res.json()
            msg = f""" 
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
▶▶▶▶GUILD DETAILS◀◀◀◀
Achievements: {data['achievements']}\n\n
Balance : {fix_num(data['balance'])}\n\n
Clan Name : {data['clan_name']}\n\n
Expire Time : {fix_num(data['guild_details']['expire_time'])}\n\n
Members Online : {fix_num(data['guild_details']['members_online'])}\n\n
Regional : {data['guild_details']['regional']}\n\n
Reward Time : {fix_num(data['guild_details']['reward_time'])}\n\n
Total Members : {fix_num(data['guild_details']['total_members'])}\n\n
ID : {fix_num(data['id'])}\n\n
Last Active : {fix_num(data['last_active'])}\n\n
Level : {fix_num(data['level'])}\n\n
Rank : {fix_num(data['rank'])}\n\n
Region : {data['region']}\n\n
Score : {fix_num(data['score'])}\n\n
Timestamp1 : {fix_num(data['timestamp1'])}\n\n
Timestamp2 : {fix_num(data['timestamp2'])}\n\n
Welcome Message: {data['welcome_message']}\n\n
XP: {fix_num(data['xp'])}\n\n
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY AYUSH
            """
            return msg
        else:
            msg = """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Failed to get info, please try again later!!

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY AYUSH
            """
            return msg
    except:
        pass
#GET INFO BY PLAYER ID
def get_player_info(player_id):
    url = f"https://like2.vercel.app/player-info?uid={player_id}&server={server2}&key={key2}"
    response = requests.get(url)
    print(response)    
    if response.status_code == 200:
        try:
            r = response.json()
            return {
                "Account Booyah Pass": f"{r.get('booyah_pass_level', 'N/A')}",
                "Account Create": f"{r.get('createAt', 'N/A')}",
                "Account Level": f"{r.get('level', 'N/A')}",
                "Account Likes": f" {r.get('likes', 'N/A')}",
                "Name": f"{r.get('nickname', 'N/A')}",
                "UID": f" {r.get('accountId', 'N/A')}",
                "Account Region": f"{r.get('region', 'N/A')}",
                }
        except ValueError as e:
            pass
            return {
                "error": "Invalid JSON response"
            }
    else:
        pass
        return {
            "error": f"Failed to fetch data: {response.status_code}"
        }
#CHAT WITH AI
def talk_with_ai(question):
    url = f"https://gemini-api-api-v2.vercel.app/prince/api/v1/ask?key=prince&ask={question}"
    res = requests.get(url)
    if res.status_code == 200:
        data = res.json()
        msg = data["message"]["content"]
        return msg
    else:
        return "An error occurred while connecting to the server."
#SPAM REQUESTS
def spam_requests(player_id):
    # This URL now correctly points to the Flask app you provided
    url = f"https://like2.vercel.app/send_requests?uid={player_id}&server={server2}&key={key2}"
    try:
        res = requests.get(url, timeout=20) # Added a timeout
        if res.status_code == 200:
            data = res.json()
            # Return a more descriptive message based on the API's JSON response
            return f"API Status: Success [{data.get('success_count', 0)}] Failed [{data.get('failed_count', 0)}]"
        else:
            # Return the error status from the API
            return f"API Error: Status {res.status_code}"
    except requests.exceptions.RequestException as e:
        # Handle cases where the API isn't running or is unreachable
        print(f"Could not connect to spam API: {e}")
        return "Failed to connect to spam API."
####################################

# ** NEW INFO FUNCTION using the new API **
def newinfo(uid):
    # Base URL without parameters
    url = "https://like2.vercel.app/player-info"
    # Parameters dictionary - this is the robust way to do it
    params = {
        'uid': uid,
        'server': server2,  # Hardcoded to bd as requested
        'key': key2
    }
    try:
        # Pass the parameters to requests.get()
        response = requests.get(url, params=params, timeout=10)
        
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            # Check if the expected data structure is in the response
            if "basicInfo" in data:
                return {"status": "ok", "data": data}
            else:
                # The API returned 200, but the data is not what we expect (e.g., error message in JSON)
                return {"status": "error", "message": data.get("error", "Invalid ID or data not found.")}
        else:
            # The API returned an error status code (e.g., 404, 500)
            try:
                # Try to get a specific error message from the API's response
                error_msg = response.json().get('error', f"API returned status {response.status_code}")
                return {"status": "error", "message": error_msg}
            except ValueError:
                # If the error response is not JSON
                return {"status": "error", "message": f"API returned status {response.status_code}"}

    except requests.exceptions.RequestException as e:
        # Handle network errors (e.g., timeout, no connection)
        return {"status": "error", "message": f"Network error: {str(e)}"}
    except ValueError: 
        # Handle cases where the response is not valid JSON
        return {"status": "error", "message": "Invalid JSON response from API."}

	
#ADDING-100-LIKES-IN-24H
def send_likes(uid):
    try:
        likes_api_response = requests.get(
             f"https://yourlikeapi/like?uid={uid}&server_name={server2}&x-vercel-set-bypass-cookie=true&x-vercel-protection-bypass={BYPASS_TOKEN}",
             timeout=15
             )
      
      
        if likes_api_response.status_code != 200:
            return f"""
[C][B][FF0000]━━━━━
[FFFFFF]Like API Error!
Status Code: {likes_api_response.status_code}
Please check if the uid is correct.
━━━━━
"""

        api_json_response = likes_api_response.json()

        player_name = api_json_response.get('PlayerNickname', 'Unknown')
        likes_before = api_json_response.get('LikesbeforeCommand', 0)
        likes_after = api_json_response.get('LikesafterCommand', 0)
        likes_added = api_json_response.get('LikesGivenByAPI', 0)
        status = api_json_response.get('status', 0)

        if status == 1 and likes_added > 0:
            # ✅ Success
            return f"""
[C][B][11EAFD]‎━━━━━━━━━━━━
[FFFFFF]Likes Status:

[00FF00]Likes Sent Successfully!

[FFFFFF]Player Name : [00FF00]{player_name}  
[FFFFFF]Likes Added : [00FF00]{likes_added}  
[FFFFFF]Likes Before : [00FF00]{likes_before}  
[FFFFFF]Likes After : [00FF00]{likes_after}  
[C][B][11EAFD]‎━━━━━━━━━━━━
[C][B][FFB300]Subscribe: [FFFFFF]SPIDEERIO YT [00FF00]!!
"""
        elif status == 2 or likes_before == likes_after:
            # 🚫 Already claimed / Maxed
            return f"""
[C][B][FF0000]━━━━━━━━━━━━

[FFFFFF]No Likes Sent!

[FF0000]You have already taken likes with this UID.
Try again after 24 hours.

[FFFFFF]Player Name : [FF0000]{player_name}  
[FFFFFF]Likes Before : [FF0000]{likes_before}  
[FFFFFF]Likes After : [FF0000]{likes_after}  
[C][B][FF0000]━━━━━━━━━━━━
"""
        else:
            # ❓ Unexpected case
            return f"""
[C][B][FF0000]━━━━━━━━━━━━
[FFFFFF]Unexpected Response!
Something went wrong.

Please try again or contact support.
━━━━━━━━━━━━
"""

    except requests.exceptions.RequestException:
        return """
[C][B][FF0000]━━━━━
[FFFFFF]Like API Connection Failed!
Is the API server (app.py) running?
━━━━━
"""
    except Exception as e:
        return f"""
[C][B][FF0000]━━━━━
[FFFFFF]An unexpected error occurred:
[FF0000]{str(e)}
━━━━━
"""
####################################
#CHECK ACCOUNT IS BANNED

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"}

# ---- Random Colores ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return (None, None)
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = Team_msg_pb2.ReceivedChat()
    proto.ParseFromString(packet) # This can raise google.protobuf.message.DecodeError
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: whisper_writer.write(PacKeT) ; await whisper_writer.drain()
    elif TypE == 'OnLine': online_writer.write(PacKeT) ; await online_writer.drain()
    else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)' 

async def safe_send_message(chat_type, message, target_uid, chat_id, key, iv, max_retries=3):
    """Safely send message with retry mechanism"""
    for attempt in range(max_retries):
        try:
            P = await SEndMsG(chat_type, message, target_uid, chat_id, key, iv)
            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
            print(f"Message sent successfully on attempt {attempt + 1}")
            return True
        except Exception as e:
            print(f"Failed to send message (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5)  # Wait before retry
    return False

async def fast_emote_spam(uids, emote_id, key, iv, region):
    """Fast emote spam function that sends emotes rapidly"""
    global fast_spam_running
    count = 0
    max_count = 25  # Spam 25 times
    
    while fast_spam_running and count < max_count:
        for uid in uids:
            try:
                uid_int = int(uid)
                H = await Emote_k(uid_int, int(emote_id), key, iv, region)
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
            except Exception as e:
                print(f"Error in fast_emote_spam for uid {uid}: {e}")
        
        count += 1
        await asyncio.sleep(0.1)  # 0.1 seconds interval between spam cycles

# NEW FUNCTION: Custom emote spam with specified times
async def custom_emote_spam(uid, emote_id, times, key, iv, region):
    """Custom emote spam function that sends emotes specified number of times"""
    global custom_spam_running
    count = 0
    
    while custom_spam_running and count < times:
        try:
            uid_int = int(uid)
            H = await Emote_k(uid_int, int(emote_id), key, iv, region)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
            count += 1
            await asyncio.sleep(0.1)  # 0.1 seconds interval between emotes
        except Exception as e:
            print(f"Error in custom_emote_spam for uid {uid}: {e}")
            break

# NEW FUNCTION: Faster spam request loop - Sends exactly 30 requests quickly
async def spam_request_loop(target_uid, key, iv, region):
    """Spam request function that creates group and sends join requests in loop - FASTER VERSION"""
    global spam_request_running
    count = 0
    max_requests = 30  # Send exactly 30 requests
    
    while spam_request_running and count < max_requests:
        try:
            # Create squad
            PAc = await OpEnSq(key, iv, region)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
            await asyncio.sleep(0.2)  # Reduced delay
            
            # Send invite
            V = await SEnd_InV(5, int(target_uid), key, iv, region)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
            
            # Leave squad immediately without waiting
            E = await ExiT(None, key, iv)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)
            
            count += 1
            print(f"Sent request #{count} to {target_uid}")
            
            # Shorter delay between requests
            await asyncio.sleep(0.5)  # Reduced from 1 second to 0.5 seconds
            
        except Exception as e:
            print(f"Error in spam_request_loop for uid {target_uid}: {e}")
            # Continue with next request instead of breaking
            await asyncio.sleep(0.5)


# ---- Webhook / HTTP helper to join squad and accept friend requests ----
async def join_squad_and_accept_friends(team_code):
    """Join a squad using team code and accept all incoming friend requests.
    Returns a tuple (success: bool, message: str).
    """
    try:
        # Step 1: Join the squad using the team code
        print(f"[WEBHOOK] Attempting to join squad with code: {team_code}")
        join_packet = await GenJoinSquadsPacket(team_code, GLOBAL_KEY, GLOBAL_IV)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
        
        return True, f"Bot joined squad with code: {team_code}. Now accepting friend requests..."
        
    except Exception as e:
        return False, f"Error joining squad: {str(e)}"


async def find_command_in_json(obj):
    """Recursively search a JSON-like object for the first string that starts with '/' (a command)."""
    if isinstance(obj, str):
        if obj.strip().startswith('/'):
            return obj.strip()
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            res = await find_command_in_json(v)
            if res: return res
    if isinstance(obj, list):
        for v in obj:
            res = await find_command_in_json(v)
            if res: return res
    return None


async def handle_squad_text_command(inPuTMsG, uid, chat_id, key, iv, region):
    """Handle a subset of commands sent in squad/online chat so the bot can be used without being friended."""
    global lag_running, lag_task
    try:
        # Normalize to lowercase so commands are case-insensitive
        text = inPuTMsG.strip().lower()
        # /inv <uid> - invite a player
        if text.startswith('/inv '):
            parts = text.split()
            if len(parts) >= 2:
                target = parts[1]
                try:
                    PAc = await OpEnSq(key, iv, region)
                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
                    C = await cHSq(5, int(target), key, iv, region)
                    await asyncio.sleep(0.3)
                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C)
                    V = await SEnd_InV(5, int(target), key, iv, region)
                    await asyncio.sleep(0.3)
                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
                    E = await ExiT(None, key, iv)
                    await asyncio.sleep(3.5)
                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)
                    resp = f"✅ Invited {target} to group."
                except Exception as e:
                    resp = f"Error inviting {target}: {e}"
                await safe_send_message(0, resp, uid, chat_id, key, iv)
                return True

        # /join <code> - join a team by code
        if text.startswith('/join '):
            parts = text.split()
            if len(parts) >= 2:
                code = parts[1]
                try:
                    join_packet = await GenJoinSquadsPacket(code, GLOBAL_KEY, GLOBAL_IV)
                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
                    resp = f"✅ Joined team {code}"
                except Exception as e:
                    resp = f"Error joining team {code}: {e}"
                await safe_send_message(0, resp, uid, chat_id, key, iv)
                return True

        # /exit - leave current squad
        if text.strip() == '/exit':
            try:
                leave = await ExiT(uid, key, iv)
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave)
                resp = "✅ Left the squad"
            except Exception as e:
                resp = f"Error leaving squad: {e}"
            await safe_send_message(0, resp, uid, chat_id, key, iv)
            return True

        # /ghost <code> - ghost join
        if text.startswith('/ghost '):
            parts = text.split()
            if len(parts) >= 2:
                code = parts[1]
                try:
                    packet = await ghost_join_packet(uid, code, key, iv)
                    if packet:
                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', packet)
                        resp = f"✅ Ghost join attempted for code {code}"
                    else:
                        resp = "Ghost join failed to create packet"
                except Exception as e:
                    resp = f"Error ghost joining: {e}"
                await safe_send_message(0, resp, uid, chat_id, key, iv)
                return True

        # /lag <code> and /stop lag
        if text.startswith('/lag '):
            parts = text.split()
            if len(parts) >= 2:
                code = parts[1]
                if not lag_running:
                    lag_running = True
                    lag_task = asyncio.create_task(lag_team_loop(code, key, iv, region))
                    resp = f"✅ Started lag loop on {code}"
                else:
                    resp = "Lag already running"
                await safe_send_message(0, resp, uid, chat_id, key, iv)
                return True

        if text.strip() == '/stop lag':
            if lag_task and not lag_task.done():
                lag_running = False
                lag_task.cancel()
                resp = "✅ Stopped lag loop"
            else:
                resp = "No lag loop running"
            await safe_send_message(0, resp, uid, chat_id, key, iv)
            return True

        # Emote command: /e <uid> <emote_id>
        if text.strip().startswith('/e '):
            parts = text.split()
            if len(parts) >= 3:
                try:
                    target_uid = int(parts[1])
                    emote_id = int(parts[2])
                    H = await Emote_k(target_uid, emote_id, key, iv, region)
                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                    resp = f"✅ Emote {emote_id} sent to {target_uid}"
                except Exception as e:
                    resp = f"Error sending emote: {e}"
                await safe_send_message(0, resp, uid, chat_id, key, iv)
                return True

    except Exception as e:
        print(f"[SQUAD-CMD] Exception handling command: {e}")
    return False

async def send_friend_accept_packet(requester_uid, key, iv, region):
    """Send a friend accept packet through the game protocol.
    Returns a tuple (success: bool, message: str).
    """
    global whisper_writer, online_writer
    try:
        # Create a structured packet for accepting a friend request
        accept_packet = await GenAcceptFriendPacket(requester_uid, key, iv, region)

        # Send through the game connection if available, preferring the 'OnLine' writer for actions
        if online_writer:
            online_writer.write(accept_packet)
            await online_writer.drain()
            return True, f"Friend request acceptance packet sent to {requester_uid} (via online_writer)"
        elif whisper_writer:
            whisper_writer.write(accept_packet)
            await whisper_writer.drain()
            return True, f"Friend request acceptance packet sent to {requester_uid} (via whisper_writer)"
        else:
            print(f"[DEBUG][ACCEPT] No writer available to send packet")
            return False, "No active connection to send friend acceptance"

    except Exception as e:
        print(f"[DEBUG][ACCEPT] Exception: {e}")
        return False, f"Error sending friend acceptance packet: {str(e)}"


async def send_friend_request_packet(requestee_uid, key, iv, region):
    """Send a friend request packet through the game protocol.
    Returns a tuple (success: bool, message: str).
    """
    global whisper_writer, online_writer
    try:
        # Create a structured packet for sending a friend request
        request_packet = await GenSendFriendRequestPacket(requestee_uid, key, iv, region)

        if online_writer:
            online_writer.write(request_packet)
            await online_writer.drain()
            return True, f"Friend request packet sent to {requestee_uid} via online_writer"
        elif whisper_writer:
            whisper_writer.write(request_packet)
            await whisper_writer.drain()
            return True, f"Friend request packet sent to {requestee_uid} via whisper_writer"
        else:
            print(f"[DEBUG][SEND] No writer available to send packet")
            return False, "No active connection to send friend request"

    except Exception as e:
        print(f"[DEBUG][SEND] Exception: {e}")
        return False, f"Error sending friend request packet: {str(e)}"


async def webhook_invite_handler(request):
    """HTTP POST /invite with JSON {"team_code": "ABC123"} or {"target_uid": "123456789"}
    Bot joins the squad using team code, or accepts friend requests by UID.
    """
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"status": "error", "message": "Invalid JSON"}, status=400)

    # Check for team_code (squad join mode)
    team_code = data.get("team_code") or data.get("code")
    if team_code:
        asyncio.create_task(_webhook_run_join(team_code))
        return web.json_response({"status": "ok", "message": f"Bot joining squad with code: {team_code}"})
    
    # NEW: Check for clan_id (clan join/apply mode)
    clan_id = data.get("clan_id")
    if clan_id:
        asyncio.create_task(_webhook_run_join_clan(clan_id))
        return web.json_response({"status": "ok", "message": f"Bot processing request to join clan with ID: {clan_id}"})

    # NEW: Check for accepting a clan invite
    accept_clan_id = data.get("accept_clan_id")
    if accept_clan_id:
        asyncio.create_task(_webhook_run_accept_clan_invite(accept_clan_id))
        return web.json_response({"status": "ok", "message": f"Bot processing request to accept invite from clan ID: {accept_clan_id}"})
    
    # Check for target_uid (friend request accept mode)
    target_uid = data.get("target_uid") or data.get("uid")
    if target_uid:
        # Attempt immediate accept and return the result to caller
        if not GLOBAL_KEY or not GLOBAL_IV or not GLOBAL_REGION: # Added region check
            return web.json_response({"status": "error", "message": "Bot encryption keys not ready"}, status=503)
        success, msg = await send_friend_accept_packet(target_uid, GLOBAL_KEY, GLOBAL_IV, GLOBAL_REGION) # Pass region
        status = "ok" if success else "error"
        code = 200 if success else 500
        return web.json_response({"status": status, "message": msg}, status=code)

    # Check for send_uid (send friend request mode)
    send_uid = data.get("send_uid") or data.get("send_request_uid")
    if send_uid:
        # Attempt immediate send and return the result to caller
        if not GLOBAL_KEY or not GLOBAL_IV or not GLOBAL_REGION: # Added region check
            return web.json_response({"status": "error", "message": "Bot encryption keys not ready for sending request"}, status=503)
        success, msg = await send_friend_request_packet(send_uid, GLOBAL_KEY, GLOBAL_IV, GLOBAL_REGION) # Pass region
        status = "ok" if success else "error"
        code = 200 if success else 500
        return web.json_response({"status": status, "message": msg}, status=code)
    
    # Neither provided
    return web.json_response({
        "status": "error", 
        "message": "Missing parameter. Use: {\"team_code\": \"...\"}, {\"clan_id\": \"...\"}, {\"accept_clan_id\": \"...\"}, {\"target_uid\": \"...\"} or {\"send_uid\": \"...\"}"
    }, status=400)


async def _webhook_run_join(team_code):
    # Join squad using team code
    if not GLOBAL_KEY or not GLOBAL_IV or not GLOBAL_AUTH_TOKEN:
        print(f"[WEBHOOK] Bot network data not ready")
        return
    
    success, msg = await join_squad_and_accept_friends(team_code)
    print(f"[WEBHOOK] Join result: {success} - {msg}")


async def _webhook_run_join_clan(clan_id):
    """Joins a clan using clan ID."""
    if not GLOBAL_KEY or not GLOBAL_IV or not GLOBAL_REGION:
        print(f"[WEBHOOK] Bot network data not ready for joining clan.")
        return

    try:
        print(f"[WEBHOOK] Attempting to join clan with ID: {clan_id}")
        # This function is added to xC4.py
        join_packet = await GenJoinClanPacket(clan_id, GLOBAL_KEY, GLOBAL_IV, GLOBAL_REGION)

        # The packet should be sent on the 'OnLine' writer, similar to joining a squad.
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)

        print(f"[WEBHOOK] Clan join packet sent for clan ID: {clan_id}")
    except Exception as e:
        print(f"[WEBHOOK] Error joining clan: {str(e)}")

async def _webhook_run_accept_clan_invite(clan_id):
    """Accepts a clan invitation using clan ID."""
    if not GLOBAL_KEY or not GLOBAL_IV or not GLOBAL_REGION:
        print(f"[WEBHOOK] Bot network data not ready for accepting clan invite.")
        return

    try:
        print(f"[WEBHOOK] Attempting to accept clan invite from clan ID: {clan_id}")
        # This function is added to xC4.py
        accept_packet = await GenAcceptClanInvitePacket(clan_id, GLOBAL_KEY, GLOBAL_IV, GLOBAL_REGION)

        # The packet should be sent on the 'OnLine' writer.
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', accept_packet)

        print(f"[WEBHOOK] Clan invite acceptance packet sent for clan ID: {clan_id}")
    except Exception as e:
        print(f"[WEBHOOK] Error accepting clan invite: {str(e)}")

async def _webhook_accept_friend(target_uid):
    # Accept friend request from target_uid using game protocol
    if not GLOBAL_KEY or not GLOBAL_IV:
        print(f"[WEBHOOK] Bot encryption keys not ready")
        return
    
    success, msg = await send_friend_accept_packet(target_uid, GLOBAL_KEY, GLOBAL_IV)
    print(f"[WEBHOOK] Accept friend result: {success} - {msg}")


async def _webhook_send_request(target_uid):
    # Send friend request to target_uid using game protocol
    if not GLOBAL_KEY or not GLOBAL_IV:
        print(f"[WEBHOOK] Bot encryption keys not ready for sending request")
        return
    success, msg = await send_friend_request_packet(target_uid, GLOBAL_KEY, GLOBAL_IV)
    print(f"[WEBHOOK] Send friend request result: {success} - {msg}")


async def start_webhook_server(port: int = 8080):
    app = web.Application()
    app.router.add_post('/invite', webhook_invite_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    print(f"Webhook server listening on http://0.0.0.0:{port}/invite")


# NEW FUNCTION: Evolution emote spam with mapping
async def evo_emote_spam(uids, number, key, iv, region):
    """Send evolution emotes based on number mapping"""
    try:
        emote_id = EMOTE_MAP.get(int(number))
        if not emote_id:
            return False, f"Invalid number! Use 1-21 only."
        
        success_count = 0
        for uid in uids:
            try:
                uid_int = int(uid)
                H = await Emote_k(uid_int, emote_id, key, iv, region)
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                success_count += 1
                await asyncio.sleep(0.1)
            except Exception as e:
                print(f"Error sending evo emote to {uid}: {e}")
        
        return True, f"Sent evolution emote {number} (ID: {emote_id}) to {success_count} player(s)"
    
    except Exception as e:
        return False, f"Error in evo_emote_spam: {str(e)}"

# NEW FUNCTION: Fast evolution emote spam
async def evo_fast_emote_spam(uids, number, key, iv, region):
    """Fast evolution emote spam function"""
    global evo_fast_spam_running
    count = 0
    max_count = 25  # Spam 25 times
    
    emote_id = EMOTE_MAP.get(int(number))
    if not emote_id:
        return False, f"Invalid number! Use 1-21 only."
    
    while evo_fast_spam_running and count < max_count:
        for uid in uids:
            try:
                uid_int = int(uid)
                H = await Emote_k(uid_int, emote_id, key, iv, region)
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
            except Exception as e:
                print(f"Error in evo_fast_emote_spam for uid {uid}: {e}")
        
        count += 1
        await asyncio.sleep(0.1)  # CHANGED: 0.5 seconds to 0.1 seconds
    
    return True, f"Completed fast evolution emote spam {count} times"

# NEW FUNCTION: Custom evolution emote spam with specified times
async def evo_custom_emote_spam(uids, number, times, key, iv, region):
    """Custom evolution emote spam with specified repeat times"""
    global evo_custom_spam_running
    count = 0
    
    emote_id = EMOTE_MAP.get(int(number))
    if not emote_id:
        return False, f"Invalid number! Use 1-21 only."
    
    while evo_custom_spam_running and count < times:
        for uid in uids:
            try:
                uid_int = int(uid)
                H = await Emote_k(uid_int, emote_id, key, iv, region)
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
            except Exception as e:
                print(f"Error in evo_custom_emote_spam for uid {uid}: {e}")
        
        count += 1
        await asyncio.sleep(0.1)  # CHANGED: 0.5 seconds to 0.1 seconds
    
    return True, f"Completed custom evolution emote spam {count} times"

async def TcPOnLine(ip, port, key, iv, AutHToKen, LoGinDaTaUncRypTinG, region, TarGeT, reconnect_delay=0.5):
    global online_writer, spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid, XX, uid, Spy, data2, Chat_Leave, fast_spam_running, fast_spam_task, custom_spam_running, custom_spam_task, spam_request_running, spam_request_task, evo_fast_spam_running, evo_fast_spam_task, evo_custom_spam_running, evo_custom_spam_task, lag_running, lag_task
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break

                # --- START: TEAM CHAT COMMAND HANDLING (from chat server) ---
                if data2.hex().startswith('120000'):
                    await process_chat_message(data2, key, iv, LoGinDaTaUncRypTinG, region, TarGeT)

                # --- START: UNIFIED ONLINE PACKET HANDLING (from online server) ---
                if data2.hex().startswith('05'): # Handle all '05' type packets (squad, clan, etc.)
                    try:
                        decrypted_hex = await DEc_PacKeT(data2.hex()[10:], key, iv)
                        packet_json_str = await DeCode_PackEt(decrypted_hex)
                        
                        if packet_json_str:
                            packet = json.loads(packet_json_str)
                            
                            # --- Clan Join/Accept Confirmation Logic ---
                            clan_id = packet.get("5", {}).get("data", {}).get("51", {}).get("data")
                            # Guessing field 33 is the clan auth token, similar to squad codes in 14 and 31
                            clan_auth_data = packet.get("5", {}).get("data", {}).get("33", {}).get("data")

                            if clan_id and clan_auth_data:
                                print(f"[CLAN-HANDLER] Detected clan membership confirmation for clan ID: {clan_id}")
                                print(f"[CLAN-HANDLER] Found potential clan auth data: {clan_auth_data}")
                                
                                # Authenticate with the clan chat to become "active"
                                auth_packet = await AuthClan(clan_id, clan_auth_data, key, iv)
                                if whisper_writer:
                                    whisper_writer.write(auth_packet)
                                    await whisper_writer.drain()
                                    print(f"[CLAN-HANDLER] Sent clan chat authentication packet.")
                                else:
                                    print("[CLAN-HANDLER] Error: whisper_writer not available to send clan auth.")
                            
                            # --- Squad Join Confirmation Logic ---
                            squad_owner_uid = packet.get('5', {}).get('data', {}).get('1', {}).get('data')
                            chat_code = packet.get("5", {}).get("data", {}).get("14", {}).get("data")

                            if squad_owner_uid and chat_code:
                                print("[SQUAD-HANDLER] Detected squad join confirmation.")
                                OwNer_UiD, CHaT_CoDe, SQuAD_CoDe = await GeTSQDaTa(packet)
                                JoinCHaT = await AutH_Chat(3, OwNer_UiD, CHaT_CoDe, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', JoinCHaT)
                                message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! '
                                P = await SEndMsG(0, message, OwNer_UiD, OwNer_UiD, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                                # Try to detect a text command inside the decoded packet JSON and handle it
                                try:
                                    cmd = await find_command_in_json(packet)
                                    if cmd:
                                        print(f"[SQUAD-CMD] Detected command in squad chat: {cmd} from {OwNer_UiD}")
                                        handled = await handle_squad_text_command(cmd, OwNer_UiD, CHaT_CoDe, key, iv, GLOBAL_REGION)
                                        if handled:
                                            print(f"[SQUAD-CMD] Command handled: {cmd}")
                                except Exception as e:
                                    print(f"[SQUAD-CMD] Error detecting/handling squad command: {e}")

                    except Exception as e:
                        # This is expected for packets that don't match the structure, so we can ignore it.
                        pass

            online_writer.close() ; await online_writer.wait_closed() ; online_writer = None

        except Exception as e: print(f"- ErroR With {ip}:{port} - {e}") ; online_writer = None
        await asyncio.sleep(reconnect_delay)
                            
async def process_chat_message(data, key, iv, LoGinDaTaUncRypTinG, region, TarGeT):
    """Helper function to process any incoming chat message."""
    global whisper_writer, online_writer, fast_spam_running, fast_spam_task, custom_spam_running, custom_spam_task, spam_request_running, spam_request_task, evo_fast_spam_running, evo_fast_spam_task, evo_custom_spam_running, evo_custom_spam_task, lag_running, lag_task

async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region, TarGeT, reconnect_delay=0.5):
    print(region, 'TCP CHAT')

    global spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , online_writer , chat_id , XX , uid , Spy,data2, Chat_Leave, fast_spam_running, fast_spam_task, custom_spam_running, custom_spam_task, spam_request_running, spam_request_task, evo_fast_spam_running, evo_fast_spam_task, evo_custom_spam_running, evo_custom_spam_task, lag_running, lag_task
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print('\n - TarGeT BoT in CLan ! ')
                print(f' - Clan Uid > {clan_id}')
                print(f' - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if whisper_writer: whisper_writer.write(pK) ; await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: break
                
                # Check for friend request notifications (typically different packet type)
                # --- START: UNIFIED CHAT COMMAND HANDLING ---
                if data.hex().startswith("120000"):
                    await process_chat_message(data, key, iv, LoGinDaTaUncRypTinG, region, TarGeT)
                # --- END: UNIFIED CHAT COMMAND HANDLING ---
                # Friend requests come with specific packet headers
                if data.hex().startswith("0a") or data.hex().startswith("1a"):
                    try:
                        # Try to detect friend request pattern and accept automatically
                        hex_data = data.hex()
                        print(f"[AUTO-ACCEPT] Detected potential friend request packet: {hex_data[:50]}")
                        
                        # Attempt to extract UID and auto-accept
                        # Friend request packets typically have structure: 0a [varint length] [UID data] ...
                        if hex_data.startswith("0a"):
                            # Try to parse and accept: attempt to decode protobuf payload and find a UID
                            try:
                                uid_found = None
                                # try a couple of offsets for the payload parsing
                                for off in (10, 6, 4):
                                    try:
                                        parsed = await DeCode_PackEt(hex_data[off:])
                                    except Exception:
                                        parsed = None
                                    if parsed:
                                        try:
                                            obj = json.loads(parsed)
                                        except Exception:
                                            obj = None
                                        if obj:
                                            # recursive search for integer-looking UID
                                            def find_uid(x):
                                                if isinstance(x, dict):
                                                    for v in x.values():
                                                        res = find_uid(v)
                                                        if res: return res
                                                elif isinstance(x, list):
                                                    for v in x:
                                                        res = find_uid(v)
                                                        if res: return res
                                                elif isinstance(x, int):
                                                    if 1000000000 <= x <= 6000000000:
                                                        return x
                                                return None
                                            uid_found = find_uid(obj)
                                            if uid_found:
                                                break
                                
                                # Pass region to the accept function
                                if uid_found:
                                    asyncio.create_task(send_friend_accept_packet(uid_found, key, iv, region))
                                    print(f"[AUTO-ACCEPT] Sent acceptance packet to UID: {uid_found}")
                                else:
                                    print(f"[AUTO-ACCEPT] Could not find UID in packet payload")
                            except Exception as parse_e:
                                print(f"[AUTO-ACCEPT] Could not parse friend UID from packet: {parse_e}")
                    except Exception as e:
                        print(f"[AUTO-ACCEPT] Error parsing packet: {e}")
                
                # The original command processing logic is now inside process_chat_message
                            
            if whisper_writer: whisper_writer.close() ; await whisper_writer.wait_closed() ; whisper_writer = None
                    
                    	
                    	
        except Exception as e: print(f"ErroR {ip}:{port} - {e}") ; 
        if whisper_writer: whisper_writer.close(); await whisper_writer.wait_closed(); whisper_writer = None
        await asyncio.sleep(reconnect_delay)

async def MaiiiinE():
    global process_chat_message # Make it accessible
    async def _process_chat_message(data, key, iv, LoGinDaTaUncRypTinG, region, TarGeT):
        try:
            response = None
            try:
                # Attempt to decode as a whisper/guild message first
                response = await DecodeWhisperMessage(data.hex()[10:])
                uid = response.Data.uid
                chat_id = response.Data.Chat_ID
                XX = response.Data.chat_type
                inPuTMsG = response.Data.msg.lower()
                print(f"Received Whisper/Guild message: {inPuTMsG} from UID: {uid} in chat type: {XX}")
            except Exception as e1:
                # If that fails, attempt to decode as a team message
                try:
                    response = await decode_team_packet(data.hex()[10:])
                    uid = response.sender_id
                    chat_id = response.sender_id # For team chat, chat_id can be the sender's UID
                    XX = 0 # 0 for squad/team chat
                    inPuTMsG = response.message.lower()
                    print(f"Received Team message: {inPuTMsG} from UID: {uid}")
                except Exception as e2:
                    print(f"Failed to parse chat packet as whisper ({e1}) or team chat ({e2})")
                    response = None
            
            # This block should be outside the try/except for decoding
            if response:
                # ALL COMMANDS NOW WORK IN ALL CHAT TYPES (SQUAD, GUILD, PRIVATE)
                
                # AI Command - /ai
                if inPuTMsG.strip().startswith('/ai '):
                            print('Processing AI command in any chat type')
                            
                            question = inPuTMsG[4:].strip()
                            if question:
                                initial_message = f"[B][C]{get_random_color()}\n🤖 AI is thinking...\n"
                                await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                                
                                # Use ThreadPoolExecutor to avoid blocking the async loop
                                loop = asyncio.get_event_loop()
                                with ThreadPoolExecutor() as executor: # This might be better outside the loop if used frequently
                                    ai_response = await loop.run_in_executor(executor, talk_with_ai, question)
                                
                                # Format the AI response
                                ai_message = f"""
[B][C][00FF00]🤖 AI Response:

[FFFFFF]{ai_response}

[C][B][FFB300]Question: [FFFFFF]{question}
"""
                                await safe_send_message(XX, ai_message, uid, chat_id, key, iv)
                            else: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Please provide a question after /ai\nExample: /ai What is Free Fire?\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # Likes Command - /likes
                if inPuTMsG.strip().startswith('/likes '):
                            print('Processing likes command in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /likes (uid)\nExample: /likes 123456789\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                target_uid = parts[1]
                                initial_message = f"[B][C]{get_random_color()}\nSending 100 likes to {target_uid}...\n"
                                await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                                
                                # Use ThreadPoolExecutor to avoid blocking the async loop
                                loop = asyncio.get_event_loop()
                                with ThreadPoolExecutor() as executor:
                                    likes_result = await loop.run_in_executor(executor, send_likes, target_uid)
                                
                                await safe_send_message(XX, likes_result, uid, chat_id, key, iv)

                # Invite Command - /inv (creates 5-Player group and sends request)
                if inPuTMsG.strip().startswith('/inv '):
                            print('Processing invite command in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /inv (uid)\nExample: /inv 123456789\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                target_uid = parts[1]
                                initial_message = f"[B][C]{get_random_color()}\nCreating 5-Player Group and sending request to {target_uid}...\n"
                                await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                                
                                try:
                                    # Fast squad creation and invite for 5 players
                                    PAc = await OpEnSq(key, iv, region)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
                                    await asyncio.sleep(0.3)
                                    
                                    C = await cHSq(5, int(target_uid), key, iv, region)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C)
                                    await asyncio.sleep(0.3)
                                    
                                    V = await SEnd_InV(5, int(target_uid), key, iv, region)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
                                    await asyncio.sleep(0.3)
                                    
                                    E = await ExiT(None, key, iv)
                                    await asyncio.sleep(2)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)
                                    
                                    # SUCCESS MESSAGE
                                    success_message = f"[B][C][00FF00]✅ SUCCESS! 5-Player Group invitation sent successfully to {target_uid}!\n"
                                    await safe_send_message(XX, success_message, uid, chat_id, key, iv)
                                    
                                except Exception as e: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR sending invite: {str(e)}\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                if inPuTMsG.startswith(("/6")):
                            # Process /6 command - Create 4 player group
                            initial_message = f"[B][C]{get_random_color()}\n\nCreating 6-Player Group...\n\n"
                            await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                            
                            # Fast squad creation and invite for 4 players
                            PAc = await OpEnSq(key, iv, region)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
                            
                            C = await cHSq(6, uid, key, iv, region)
                            await asyncio.sleep(0.3)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C)
                            
                            V = await SEnd_InV(6, uid, key, iv, region)
                            await asyncio.sleep(0.3)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
                            
                            E = await ExiT(None, key, iv)
                            await asyncio.sleep(3.5)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)
                            
                            # SUCCESS MESSAGE
                            success_message = f"[B][C][00FF00]✅ SUCCESS! 6-Player Group invitation sent successfully to {uid}!\n"
                            await safe_send_message(XX, success_message, uid, chat_id, key, iv)

                if inPuTMsG.startswith(("/3")):
                            # Process /3 command - Create 3 player group
                            initial_message = f"[B][C]{get_random_color()}\n\nCreating 3-Player Group...\n\n"
                            await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                            
                            # Fast squad creation and invite for 6 players
                            PAc = await OpEnSq(key, iv, region)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
                            
                            C = await cHSq(3, uid, key, iv, region)
                            await asyncio.sleep(0.3)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C)
                            
                            V = await SEnd_InV(3, uid, key, iv, region)
                            await asyncio.sleep(0.3)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
                            
                            E = await ExiT(None, key, iv)
                            await asyncio.sleep(3.5)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)
                            
                            # SUCCESS MESSAGE
                            success_message = f"[B][C][00FF00]✅ SUCCESS! 6-Player Group invitation sent successfully to {uid}!\n"
                            await safe_send_message(XX, success_message, uid, chat_id, key, iv)

                if inPuTMsG.startswith(("/5")):
                            # Process /5 command in any chat type
                            initial_message = f"[B][C]{get_random_color()}\n\nSending Group Invitation...\n\n"
                            await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                            
                            # Fast squad creation and invite
                            PAc = await OpEnSq(key, iv, region)
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
                            
                            C = await cHSq(5, uid, key, iv, region)
                            await asyncio.sleep(0.3)  # Reduced delay
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C)
                            
                            V = await SEnd_InV(5, uid, key, iv, region)
                            await asyncio.sleep(0.3)  # Reduced delay
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
                            
                            E = await ExiT(None, key, iv)
                            await asyncio.sleep(3.5)  # Reduced from 3 seconds
                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)
                            
                            # SUCCESS MESSAGE
                            success_message = f"[B][C][00FF00]✅ SUCCESS! Group invitation sent successfully to {uid}!\n"
                            await safe_send_message(XX, success_message, uid, chat_id, key, iv)

                if inPuTMsG.strip() == "/admin":
                            # Process /admin command in any chat type
                            admin_message = """
[B][C][FFC0CB]Thinking about getting the bot at a good price?

Thinking about getting a panel without restrictions?

Thinking about getting a server in your name with a panel?

All of this is available, just contact me!

[b][i][FFC0CB]youtube: AYUSH[/b]

[b][c][FFC0CB]subcribe: DECIMAL CHEATS[FFFFFF]
 
[b][i][FFA500]Discord: @DECIMAL CHEATS[/b]
 
Enjoy the bot my friend.......

[C][B][0000FF] Created by AYUSH
"""
                            await safe_send_message(XX, admin_message, uid, chat_id, key, iv)

                # FIXED JOIN COMMAND
                if inPuTMsG.startswith('/join'):
                            # Process /join command in any chat type
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /join (team_code)\nExample: /join ABC123\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                CodE = parts[1]
                                initial_message = f"[B][C]{get_random_color()}\nJoining squad with code: {CodE}...\n"
                                await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                                
                                try:
                                    # Try using the regular join method first
                                    EM = await GenJoinSquadsPacket(CodE, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', EM)
                                    
                                    # SUCCESS MESSAGE
                                    success_message = f"[B][C][00FF00]✅ SUCCESS! Joining squad with code: {CodE}!\n"
                                    await safe_send_message(XX, success_message, uid, chat_id, key, iv)
                                    
                                except Exception as e: # pragma: no cover
                                    print(f"Regular join failed, trying ghost join: {e}")
                                    # If regular join fails, try ghost join
                                    try:
                                        # Get bot's UID from global context or login data
                                        bot_uid = LoGinDaTaUncRypTinG.AccountUID if hasattr(LoGinDaTaUncRypTinG, 'AccountUID') else TarGeT
                                        
                                        ghost_packet = await ghost_join_packet(bot_uid, CodE, key, iv)
                                        if ghost_packet:
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', ghost_packet)
                                            success_message = f"[B][C][00FF00]✅ SUCCESS! Ghost joining squad with code: {CodE}!\n"
                                            await safe_send_message(XX, success_message, uid, chat_id, key, iv)
                                        else: # pragma: no cover
                                            error_msg = f"[B][C][FF0000]❌ ERROR! Failed to create ghost join packet.\n"
                                            await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                            
                                    except Exception as ghost_error: # pragma: no cover
                                        print(f"Ghost join also failed: {ghost_error}")
                                        error_msg = f"[B][C][FF0000]❌ ERROR! Failed to join squad: {str(ghost_error)}\n"
                                        await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # NEW GHOST COMMAND
                if inPuTMsG.strip().startswith('/ghost'):
                            # Process /ghost command in any chat type
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /ghost (team_code)\nExample: /ghost ABC123\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                CodE = parts[1]
                                initial_message = f"[B][C]{get_random_color()}\nGhost joining squad with code: {CodE}...\n"
                                await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                                
                                try:
                                    # Get bot's UID from global context or login data
                                    bot_uid = LoGinDaTaUncRypTinG.AccountUID if hasattr(LoGinDaTaUncRypTinG, 'AccountUID') else TarGeT
                                    
                                    ghost_packet = await ghost_join_packet(bot_uid, CodE, key, iv)
                                    if ghost_packet:
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', ghost_packet)
                                        success_message = f"[B][C][00FF00]✅ SUCCESS! Ghost joined squad with code: {CodE}!\n"
                                        await safe_send_message(XX, success_message, uid, chat_id, key, iv)
                                    else: # pragma: no cover
                                        error_msg = f"[B][C][FF0000]❌ ERROR! Failed to create ghost join packet.\n"
                                        await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                        
                                except Exception as e: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR! Ghost join failed: {str(e)}\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # NEW LAG COMMAND
                if inPuTMsG.strip().startswith('/lag '):
                            print('Processing lag command in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /lag (team_code)\nExample: /lag ABC123\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                team_code = parts[1]
                                
                                # Stop any existing lag task
                                if lag_task and not lag_task.done():
                                    lag_running = False
                                    lag_task.cancel()
                                    await asyncio.sleep(0.1)
                                
                                # Start new lag task
                                lag_running = True
                                lag_task = asyncio.create_task(lag_team_loop(team_code, key, iv, region))
                                
                                # SUCCESS MESSAGE
                                success_msg = f"[B][C][00FF00]✅ SUCCESS! Lag attack started!\nTeam: {team_code}\nAction: Rapid join/leave\nSpeed: Ultra fast (milliseconds)\n"
                                await safe_send_message(XX, success_msg, uid, chat_id, key, iv)

                # STOP LAG COMMAND
                if inPuTMsG.strip() == '/stop lag':
                            if lag_task and not lag_task.done():
                                lag_running = False
                                lag_task.cancel()
                                success_msg = f"[B][C][00FF00]✅ SUCCESS! Lag attack stopped successfully!\n"
                                await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                            else: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! No active lag attack to stop!\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                if inPuTMsG.startswith('/exit'):
                            # Process /exit command in any chat type
                            initial_message = f"[B][C]{get_random_color()}\nLeaving current squad...\n"
                            await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                            
                            leave = await ExiT(uid,key,iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , leave)
                            
                            # SUCCESS MESSAGE
                            success_message = f"[B][C][00FF00]✅ SUCCESS! Left the squad successfully!\n"
                            await safe_send_message(XX, success_message, uid, chat_id, key, iv)

                if inPuTMsG.strip().startswith('/s'):
                            # Process /s command in any chat type
                            initial_message = f"[B][C]{get_random_color()}\nStarting match...\n"
                            await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                            
                            EM = await FS(key , iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM)
                            
                            # SUCCESS MESSAGE
                            success_message = f"[B][C][00FF00]✅ SUCCESS! Match starting command sent!\n"
                            await safe_send_message(XX, success_message, uid, chat_id, key, iv)

                # Emote command - works in all chat types
                if inPuTMsG.strip().startswith('/e'):
                            print(f'Processing emote command in chat type: {XX}')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 3: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /e (uid) (emote_id)\nExample: /e 123456789 909000001\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                return
                                
                            initial_message = f'[B][C]{get_random_color()}\nSending emote to target...\n'
                            await safe_send_message(XX, initial_message, uid, chat_id, key, iv)

                            uid2 = uid3 = uid4 = uid5 = None
                            s = False
                            target_uids = []

                            try:
                                target_uid = int(parts[1])
                                target_uids.append(target_uid)
                                uid2 = int(parts[2]) if len(parts) > 2 else None
                                if uid2: target_uids.append(uid2)
                                uid3 = int(parts[3]) if len(parts) > 3 else None
                                if uid3: target_uids.append(uid3)
                                uid4 = int(parts[4]) if len(parts) > 4 else None
                                if uid4: target_uids.append(uid4)
                                uid5 = int(parts[5]) if len(parts) > 5 else None
                                if uid5: target_uids.append(uid5)
                                idT = int(parts[-1])  # Last part is emote ID

                            except ValueError as ve:
                                print("ValueError:", ve) # pragma: no cover
                                s = True
                            except Exception as e:
                                print(f"Error parsing emote command: {e}") # pragma: no cover
                                s = True

                            if not s:
                                try:
                                    for target in target_uids:
                                        H = await Emote_k(target, idT, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        await asyncio.sleep(0.1)
                                    
                                    # SUCCESS MESSAGE
                                    success_msg = f"[B][C][00FF00]✅ SUCCESS! Emote {idT} sent to {len(target_uids)} player(s)!\nTargets: {', '.join(map(str, target_uids))}\n"
                                    await safe_send_message(XX, success_msg, uid, chat_id, key, iv)

                                except Exception as e: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR sending emote: {str(e)}\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Invalid UID format. Usage: /e (uid) (emote_id)\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # Fast emote spam command - works in all chat types
                if inPuTMsG.strip().startswith('/fast'):
                            print('Processing fast emote spam in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 3: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /fast uid1 [uid2] [uid3] [uid4] emoteid\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                # Parse uids and emoteid
                                uids = []
                                emote_id = None
                                
                                for part in parts[1:]:
                                    if part.isdigit():
                                        if len(part) > 3:  # Assuming UIDs are longer than 3 digits
                                            uids.append(part)
                                        else:
                                            emote_id = part
                                    else:
                                        break
                                
                                if not emote_id and parts[-1].isdigit():
                                    emote_id = parts[-1]
                                
                                if not uids or not emote_id: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR! Invalid format! Usage: /fast uid1 [uid2] [uid3] [uid4] emoteid\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                else:
                                    # Stop any existing fast spam
                                    if fast_spam_task and not fast_spam_task.done():
                                        fast_spam_running = False
                                        fast_spam_task.cancel()
                                    
                                    # Start new fast spam
                                    fast_spam_running = True
                                    fast_spam_task = asyncio.create_task(fast_emote_spam(uids, emote_id, key, iv, region))
                                    
                                    # SUCCESS MESSAGE
                                    success_msg = f"[B][C][00FF00]✅ SUCCESS! Fast emote spam started!\nTargets: {len(uids)} players\nEmote: {emote_id}\nSpam count: 25 times\n"
                                    await safe_send_message(XX, success_msg, uid, chat_id, key, iv)

                # Custom emote spam command - works in all chat types
                if inPuTMsG.strip().startswith('/p'):
                            print('Processing custom emote spam in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 4: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /p (uid) (emote_id) (times)\nExample: /p 123456789 909000001 10\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                try:
                                    target_uid = parts[1]
                                    emote_id = parts[2]
                                    times = int(parts[3])
                                    
                                    if times <= 0: # pragma: no cover
                                        error_msg = f"[B][C][FF0000]❌ ERROR! Times must be greater than 0!\n"
                                        await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                    elif times > 100: # pragma: no cover
                                        error_msg = f"[B][C][FF0000]❌ ERROR! Maximum 100 times allowed for safety!\n"
                                        await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                    else:
                                        # Stop any existing custom spam
                                        if custom_spam_task and not custom_spam_task.done():
                                            custom_spam_running = False
                                            custom_spam_task.cancel()
                                            await asyncio.sleep(0.5)
                                        
                                        # Start new custom spam
                                        custom_spam_running = True
                                        custom_spam_task = asyncio.create_task(custom_emote_spam(target_uid, emote_id, times, key, iv, region))
                                        
                                        # SUCCESS MESSAGE
                                        success_msg = f"[B][C][00FF00]✅ SUCCESS! Custom emote spam started!\nTarget: {target_uid}\nEmote: {emote_id}\nTimes: {times}\n"
                                        await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                                        
                                except ValueError: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR! Invalid number format! Usage: /p (uid) (emote_id) (times)\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                except Exception as e: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR! {str(e)}\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # Spam request command - works in all chat types
                if inPuTMsG.strip().startswith('/spm_inv'):
                            print('Processing spam request in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /spm_inv (uid)\nExample: /spm_inv 123456789\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                try:
                                    target_uid = parts[1]
                                    
                                    # Stop any existing spam request
                                    if spam_request_task and not spam_request_task.done():
                                        spam_request_running = False
                                        spam_request_task.cancel()
                                        await asyncio.sleep(0.5)
                                    
                                    # Start new spam request
                                    spam_request_running = True
                                    spam_request_task = asyncio.create_task(spam_request_loop(target_uid, key, iv, region))
                                    
                                    # SUCCESS MESSAGE
                                    success_msg = f"[B][C][00FF00]✅ SUCCESS! Spam request started!\nTarget: {target_uid}\nRequests: 30\nSpeed: Fast\n"
                                    await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                                        
                                except Exception as e: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR! {str(e)}\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # Stop spam request command - works in all chat types
                if inPuTMsG.strip() == '/stop spm_inv':
                            if spam_request_task and not spam_request_task.done():
                                spam_request_running = False
                                spam_request_task.cancel()
                                success_msg = f"[B][C][00FF00]✅ SUCCESS! Spam request stopped successfully!\n"
                                await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                            else: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! No active spam request to stop!\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # NEW EVO COMMANDS
                if inPuTMsG.strip().startswith('/evo '):
                            print('Processing evo command in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /evo uid1 [uid2] [uid3] [uid4] number(1-21)\nExample: /evo 123456789 1\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                # Parse uids and number
                                uids = []
                                number = None
                                
                                for part in parts[1:]:
                                    if part.isdigit():
                                        if len(part) <= 2:  # Number should be 1-21 (1 or 2 digits)
                                            number = part
                                        else:
                                            uids.append(part)
                                    else:
                                        break
                                
                                if not number and parts[-1].isdigit() and len(parts[-1]) <= 2:
                                    number = parts[-1]
                                
                                if not uids or not number: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR! Invalid format! Usage: /evo uid1 [uid2] [uid3] [uid4] number(1-21)\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                else:
                                    try:
                                        number_int = int(number)
                                        if number_int not in EMOTE_MAP: # pragma: no cover
                                            error_msg = f"[B][C][FF0000]❌ ERROR! Number must be between 1-21 only!\n"
                                            await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                        else:
                                            initial_message = f"[B][C]{get_random_color()}\nSending evolution emote {number_int}...\n"
                                            await safe_send_message(XX, initial_message, uid, chat_id, key, iv)
                                            
                                            success, result_msg = await evo_emote_spam(uids, number_int, key, iv, region)
                                            
                                            if success:
                                                success_msg = f"[B][C][00FF00]✅ SUCCESS! {result_msg}\n"
                                                await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                                            else: # pragma: no cover
                                                error_msg = f"[B][C][FF0000]❌ ERROR! {result_msg}\n"
                                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                            
                                    except ValueError: # pragma: no cover
                                        error_msg = f"[B][C][FF0000]❌ ERROR! Invalid number format! Use 1-21 only.\n"
                                        await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                if inPuTMsG.strip().startswith('/evo_fast '):
                            print('Processing evo_fast command in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /evo_fast uid1 [uid2] [uid3] [uid4] number(1-21)\nExample: /evo_fast 123456789 1\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                # Parse uids and number
                                uids = []
                                number = None
                                
                                for part in parts[1:]:
                                    if part.isdigit():
                                        if len(part) <= 2:  # Number should be 1-21 (1 or 2 digits)
                                            number = part
                                        else:
                                            uids.append(part)
                                    else:
                                        break
                                
                                if not number and parts[-1].isdigit() and len(parts[-1]) <= 2:
                                    number = parts[-1]
                                
                                if not uids or not number: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR! Invalid format! Usage: /evo_fast uid1 [uid2] [uid3] [uid4] number(1-21)\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                else:
                                    try:
                                        number_int = int(number)
                                        if number_int not in EMOTE_MAP: # pragma: no cover
                                            error_msg = f"[B][C][FF0000]❌ ERROR! Number must be between 1-21 only!\n"
                                            await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                        else:
                                            # Stop any existing evo_fast spam
                                            if evo_fast_spam_task and not evo_fast_spam_task.done():
                                                evo_fast_spam_running = False
                                                evo_fast_spam_task.cancel()
                                                await asyncio.sleep(0.5)
                                            
                                            # Start new evo_fast spam
                                            evo_fast_spam_running = True
                                            evo_fast_spam_task = asyncio.create_task(evo_fast_emote_spam(uids, number_int, key, iv, region))
                                            
                                            # SUCCESS MESSAGE
                                            emote_id = EMOTE_MAP[number_int]
                                            success_msg = f"[B][C][00FF00]✅ SUCCESS! Fast evolution emote spam started!\nTargets: {len(uids)} players\nEmote: {number_int} (ID: {emote_id})\nSpam count: 25 times\nInterval: 0.1 seconds\n"
                                            await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                                            
                                    except ValueError: # pragma: no cover
                                        error_msg = f"[B][C][FF0000]❌ ERROR! Invalid number format! Use 1-21 only.\n"
                                        await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # NEW EVO_CUSTOM COMMAND
                if inPuTMsG.strip().startswith('/evo_c '):
                            print('Processing evo_c command in any chat type')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 3: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! Usage: /evo_c uid1 [uid2] [uid3] [uid4] number(1-21) time(1-100)\nExample: /evo_c 123456789 1 10\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                            else:
                                # Parse uids, number, and time
                                uids = []
                                number = None
                                time_val = None
                                
                                for part in parts[1:]:
                                    if part.isdigit():
                                        if len(part) <= 2:  # Number or time should be 1-100 (1, 2, or 3 digits)
                                            if number is None:
                                                number = part
                                            elif time_val is None:
                                                time_val = part
                                            else:
                                                uids.append(part)
                                        else:
                                            uids.append(part)
                                    else:
                                        break
                                
                                # If we still don't have time_val, try to get it from the last part
                                if not time_val and len(parts) >= 3:
                                    last_part = parts[-1]
                                    if last_part.isdigit() and len(last_part) <= 3:
                                        time_val = last_part
                                        # Remove time_val from uids if it was added by mistake
                                        if time_val in uids:
                                            uids.remove(time_val)
                                
                                if not uids or not number or not time_val: # pragma: no cover
                                    error_msg = f"[B][C][FF0000]❌ ERROR! Invalid format! Usage: /evo_c uid1 [uid2] [uid3] [uid4] number(1-21) time(1-100)\n"
                                    await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                else:
                                    try:
                                        number_int = int(number)
                                        time_int = int(time_val)
                                        
                                        if number_int not in EMOTE_MAP: # pragma: no cover
                                            error_msg = f"[B][C][FF0000]❌ ERROR! Number must be between 1-21 only!\n"
                                            await safe_send_message(XX, error_msg, uid, chat_id, key, iv)
                                        elif time_int < 1 or time_int > 100: # pragma: no cover
                                            error_msg = f"[B][C][FF0000]❌ ERROR! Time must be between 1-100 only!\n"
                                            await safe_send_message(XX, error_msg, uid, chat_id, key, iv) # pragma: no cover
                                        else:
                                            # Stop any existing evo_custom spam
                                            if evo_custom_spam_task and not evo_custom_spam_task.done():
                                                evo_custom_spam_running = False
                                                evo_custom_spam_task.cancel()
                                                await asyncio.sleep(0.5)
                                            
                                            # Start new evo_custom spam
                                            evo_custom_spam_running = True
                                            evo_custom_spam_task = asyncio.create_task(evo_custom_emote_spam(uids, number_int, time_int, key, iv, region))
                                            
                                            # SUCCESS MESSAGE
                                            emote_id = EMOTE_MAP[number_int]
                                            success_msg = f"[B][C][00FF00]✅ SUCCESS! Custom evolution emote spam started!\nTargets: {len(uids)} players\nEmote: {number_int} (ID: {emote_id})\nRepeat: {time_int} times\nInterval: 0.1 seconds\n"
                                            await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                                            
                                    except ValueError: # pragma: no cover
                                        error_msg = f"[B][C][FF0000]❌ ERROR! Invalid number/time format! Use numbers only.\n"
                                        await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # Stop evo_fast spam command
                if inPuTMsG.strip() == '/stop evo_fast':
                            if evo_fast_spam_task and not evo_fast_spam_task.done():
                                evo_fast_spam_running = False
                                evo_fast_spam_task.cancel()
                                success_msg = f"[B][C][00FF00]✅ SUCCESS! Evolution fast spam stopped successfully!\n"
                                await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                            else: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! No active evolution fast spam to stop!\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # Stop evo_custom spam command
                if inPuTMsG.strip() == '/stop evo_c':
                            if evo_custom_spam_task and not evo_custom_spam_task.done():
                                evo_custom_spam_running = False
                                evo_custom_spam_task.cancel()
                                success_msg = f"[B][C][00FF00]✅ SUCCESS! Evolution custom spam stopped successfully!\n"
                                await safe_send_message(XX, success_msg, uid, chat_id, key, iv)
                            else: # pragma: no cover
                                error_msg = f"[B][C][FF0000]❌ ERROR! No active evolution custom spam to stop!\n"
                                await safe_send_message(XX, error_msg, uid, chat_id, key, iv)

                # FIXED HELP MENU SYSTEM - Now detects commands properly
                if inPuTMsG.strip().lower() in ("op", "/AYUSH", "hi", "/help"):
                            print(f"Help command detected from UID: {uid} in chat type: {XX}")
                            
                            # Menu 1 - Basic Commands
                            menu1 = '''[B][C][FFFFFF]FREE F[C][B][FFD700]I[B][C][FFFFFF]RE

[FFFFFF]Hey [FFFF00]User ❤️
[FFFFFF]Welcome to DECIMAL CHEATS
[C][B][FF0000]━━━━ MENU 1 ━━━━

[C][B][FFFF00]🎮 Basic Commands:
[B][C][FFFFFF]/3 [00FF00]- Create 3 Player Group
[B][C][FFFFFF]/5 [00FF00]- Create 5 Player Group  
[B][C][FFFFFF]/6 [00FF00]- Create 6 Player Group
[B][C][FFFFFF]/inv [uid] [00FF00]- Invite Player
[B][C][FFFFFF]/join [code] [00FF00]- Join Team
[B][C][FFFFFF]/exit [00FF00]- Leave Group
[B][C][FFFFFF]/s [00FF00]- Start Match

[C][B][FF0000]━━━━━━━━━━━━
[C][B][FFFF00]Type "menu2" for next page'''
                            
                            await safe_send_message(XX, menu1, uid, chat_id, key, iv)
                            
                            await asyncio.sleep(0.5)
                            
                            # Menu 2 - Advanced Commands
                            menu2 = '''[C][B][FF0000]━━━━ MENU 2 ━━━━
[C][B][FFFF00]⚡ Advanced Commands:
[B][C][FFFFFF]/spm_inv [uid] [00FF00]- Spam Invite (30x)
[B][C][FFFFFF]/stop spm_inv [00FF00]- Stop Spam Invite
[B][C][FFFFFF]/ghost [code] [00FF00]- Ghost Join Team
[B][C][FFFFFF]/lag [code] [00FF00]- Lag Attack
[B][C][FFFFFF]/stop lag [00FF00]- Stop Lag

[C][B][FF0000]━━━━ AI & LIKES ━━━━
[B][C][FFFFFF]/ai [question] [00FF00]- Ask AI Anything
[B][C][FFFFFF]/likes [uid] [00FF00]- Send 100 Likes

[C][B][FFFF00]Type "menu3" for next page'''
                            
                            await safe_send_message(XX, menu2, uid, chat_id, key, iv)
                            
                            await asyncio.sleep(0.5)
                            
                            # Menu 3 - Emote Commands
                            menu3 = '''[C][B][FF0000]━━━━ MENU 3 ━━━━
[C][B][FFFF00]😎 Emote Commands:
[B][C][FFFFFF]/e [uid] [emote_id] [00FF00]- Send Emote
[B][C][FFFFFF]/fast [uid] [emote_id] [00FF00]- Fast Emote (25x)
[B][C][FFFFFF]/p [uid] [emote_id] [times] [00FF00]- Custom Emote

[C][B][FF0000]━━━━ EVO ━━━━
[B][C][FFFFFF]/evo [uid] [1-21] [00FF00]- Evolution Emote
[B][C][FFFFFF]/evo_fast [uid] [1-21] [00FF00]- Fast Evo (25x)
[B][C][FFFFFF]/evo_c [uid] [1-21] [times] [00FF00]- Custom Evo

[C][B][FF0000]━━━━━━━━━━━━
[C][B][FFFF00]🤖 Bot Status: [00FF00]ONLINE
[C][B][FFB300]👑 Owner: AYUSH
[00FFFF]━━━━━━━━━━━━'''
                            
                            await safe_send_message(XX, menu3, uid, chat_id, key, iv)

                # ADDITIONAL MENU PAGES - Separate detection for menu2 and menu3
                elif inPuTMsG.strip().lower() in ("2"):
                            menu2 = '''[C][B][FF0000]━━━━ MENU 2 ━━━━
[C][B][FFFF00]⚡ Advanced Commands:
[B][C][FFFFFF]/spm_inv [uid] [00FF00]- Spam Invite (30x)
[B][C][FFFFFF]/stop spm_inv [00FF00]- Stop Spam Invite
[B][C][FFFFFF]/ghost [code] [00FF00]- Ghost Join Team
[B][C][FFFFFF]/lag [code] [00FF00]- Lag Attack
[B][C][FFFFFF]/stop lag [00FF00]- Stop Lag

[C][B][FF0000]━━━━ AI & LIKES ━━━━
[B][C][FFFFFF]/ai [question] [00FF00]- Ask AI Anything
[B][C][FFFFFF]/likes [uid] [00FF00]- Send 100 Likes

[C][B][FFFF00]Type "menu3" for next page'''
                            
                            await safe_send_message(XX, menu2, uid, chat_id, key, iv)

                elif inPuTMsG.strip().lower() in ("3"):
                            menu3 = '''[C][B][FF0000]━━━━ MENU 3 ━━━━
[C][B][FFFF00]😎 Emote Commands:
[B][C][FFFFFF]/e [uid] [emote_id] [00FF00]- Send Emote
[B][C][FFFFFF]/fast [uid] [emote_id] [00FF00]- Fast Emote (25x)
[B][C][FFFFFF]/p [uid] [emote_id] [times] [00FF00]- Custom Emote

[C][B][FF0000]━━━━ EVO ━━━━
[B][C][FFFFFF]/evo [uid] [1-21] [00FF00]- Evolution Emote
[B][C][FFFFFF]/evo_fast [uid] [1-21] [00FF00]- Fast Evo (25x)
[B][C][FFFFFF]/evo_c [uid] [1-21] [times] [00FF00]- Custom Evo

[C][B][FF0000]━━━━━━━━━━━━
[C][B][FFFF00]🤖 Bot Status: [00FF00]ONLINE
[C][B][FFB300]👑 Owner: AYUSH
[00FFFF]━━━━━━━━━━━━'''
                            
                            await safe_send_message(XX, menu3, uid, chat_id, key, iv)

                # BOT STATUS COMMAND
                elif inPuTMsG.strip().lower() in ("status"):
                            bot_status = f"""
[B][C][00FF00]🤖 BOT STATUS

[FFFFFF]🤖 Bot Name: [00FF00]{LoGinDaTaUncRypTinG.AccountName if hasattr(LoGinDaTaUncRypTinG, 'AccountName') else 'DECIMAL CHEATS Bot'}
[FFFFFF]🆔 Bot UID: [00FF00]{TarGeT}
[FFFFFF]🌍 Region: [00FF00]{region}
[FFFFFF]⚡ Status: [00FF00]ONLINE & WORKING
[FFFFFF]📊 Connection: [00FF00]STABLE
[FFFFFF]🎮 Features: [00FF00]ALL ACTIVE

[C][B][FFB300]👑 Developed by: AYUSH
[00FF00]━━━━━━━━━━━━"""
                            
                            await safe_send_message(XX, bot_status, uid, chat_id, key, iv)
                response = None
        except Exception as e:
            print(f"Error processing chat message: {e}")
    process_chat_message = _process_chat_message
    Uid , Pw = '4328483353','Ale_4YS9N_BY_SPIDEERIO_GAMING_VXZZB'
    

    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: print("ErroR - InvaLid AccounT") ; return None
    
    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ") ; return None
    
    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp
    
    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: print("ErroR - GeTinG PorTs From LoGin DaTa !") ; return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    #print(acc_name)
    print(ToKen)
    equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , key , iv)
    ready_event = asyncio.Event()

    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , key , iv , LoGinDaTaUncRypTinG , ready_event ,region, TarGeT)) # Handles whispers and guild chat
     
    await ready_event.wait()
    await asyncio.sleep(1)
    # Expose connection info for webhook handler
    global GLOBAL_KEY, GLOBAL_IV, GLOBAL_REGION, GLOBAL_AUTH_TOKEN
    GLOBAL_KEY = key
    GLOBAL_IV = iv
    GLOBAL_REGION = region
    GLOBAL_AUTH_TOKEN = ToKen
    # Start webhook server only if it hasn't been started yet
    global webhook_server_started
    if not webhook_server_started:
        try:
            asyncio.create_task(start_webhook_server(8080))
            webhook_server_started = True
        except Exception as e:
            print(f"Failed to start webhook server: {e}")

    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , key , iv , AutHToKen, LoGinDaTaUncRypTinG, region, TarGeT)) # Handles online presence and team chat
    os.system('cls')
    print(render('AYUSH', colors=['white', 'green'], align='center'))
    print('')
    #print(' - ReGioN => {region}'.format(region))
    print(f" - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n")
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")    
    print(f" - Subscribe > DECIMAL CHEATS | Gaming ! (:")    
    await asyncio.gather(task1 , task2)
    
async def StarTinG():
    while True:
        try: await asyncio.wait_for(MaiiiinE() , timeout = 7 * 60 * 60)
        except asyncio.TimeoutError: print("Token ExpiRed ! , ResTartinG")
        except Exception as e: print(f"ErroR TcP - {e} => ResTarTinG ...")

if __name__ == '__main__':
    asyncio.run(StarTinG())