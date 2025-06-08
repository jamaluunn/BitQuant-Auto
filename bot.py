import httpx
import sys
import asyncio
import base64
import random
import time
from datetime import datetime
import os

import pytz
import pyfiglet
from halo import Halo
from rich.console import Console
from rich.prompt import Prompt
from solders.keypair import Keypair
import base58
import nacl.signing
import nacl.encoding

# --- Configuration ---
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/119.0.0.0 (Edition cdf)',
    'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0',
]
API_KEY = 'AIzaSyBDdwO2O_Ose7LICa-A78qKJUCEE3nAwsM'
DOMAIN = 'bitquant.io'
URI = 'https://bitquant.io'
VERSION = '1'
CHAIN_ID = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
DAILY_CHAT_LIMIT = 20

console = Console()

# --- Helper Functions ---

def get_timestamp():
    return datetime.now(pytz.timezone('Asia/Jakarta')).strftime('%d/%m/%Y, %H:%M:%S')

def display_banner():
    width = os.get_terminal_size().columns
    banner = pyfiglet.figlet_format('Airdropversity', font='standard')
    for line in banner.split('\n'):
        console.print(f"[cyan]{line.center(width)}[/cyan]")
    console.print(f"[cyan]{'=== Telegram Channel 🚀 : Airdropversity ID ( t.me/AirdropversityID ) ==='.center(width)}[/cyan]")
    console.print(f"[magenta]{'✪  BITQUANT AUTO BOT  ✪'.center(width)}[/magenta]")
    console.print(f"[yellow]{'Modified from the original script by NTExhaust'.center(width)}[/yellow]\n")

async def type_text(text: str, no_type: bool = False):
    max_length = 80
    display_text = text if len(text) <= max_length else text[:max_length] + '...'
    if no_type:
        console.print(f" [magenta]┊ │[/magenta] {display_text}")
        return
    console.print(" [magenta]┊ ┌── Response Chat API ──[/magenta]")
    console.print(f" [magenta]┊ │[/magenta] ", end="")
    for char in display_text:
        print(char, end='', flush=True)
        await asyncio.sleep(0.02)
    print()
    console.print(" [magenta]┊ └──[/magenta]")

def create_progress_bar(current: int, total: int) -> str:
    bar_length = 30
    filled = int(bar_length * current / total)
    return f"[{'█' * filled}{' ' * (bar_length - filled)} {current}/{total}]"

def clear_console_line():
    sys.stdout.write("\r" + " " * os.get_terminal_size().columns + "\r")
    sys.stdout.flush()

async def with_retry(fn, max_retries=5, action_text='Operation'):
    spinner = Halo(text=f" ┊ → {action_text}...", spinner='bouncingBar', color='cyan')
    for i in range(max_retries):
        try:
            spinner.start()
            result = await fn()
            spinner.succeed(f" ┊ ✓ {action_text} Successfully")
            await asyncio.sleep(0.5)
            return result
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            if i < max_retries - 1:
                error_message = f'Error {status_code}' if status_code == 403 else str(e)
                spinner.text = f" ┊ → {action_text} [Retry {i + 1}/{max_retries} | {error_message}]..."
                await asyncio.sleep(5)
                continue
            else:
                spinner.fail(f" ┊ ✗ Failed {action_text.lower()}: Status {status_code}")
                try:
                    console.print(f" [red]┊ │ Error details: {e.response.json()}[/red]")
                except Exception:
                    console.print(f" [red]┊ │ Error details: {e.response.text}[/red]")
                await asyncio.sleep(0.5)
                raise e
        except Exception as e:
            spinner.fail(f" ┊ ✗ Failed {action_text.lower()}: {e}")
            await asyncio.sleep(0.5)
            raise e
        finally:
            clear_console_line()

# --- Core Logic Functions ---

def generate_message(address: str) -> str:
    nonce = int(time.time() * 1000)
    issued_at = datetime.utcnow().isoformat() + "Z"
    return f"{DOMAIN} wants you to sign in with your **blockchain** account:\n{address}\n\nURI: {URI}\nVersion: {VERSION}\nChain ID: {CHAIN_ID}\nNonce: {nonce}\nIssued At: {issued_at}"

def sign_message(message: str, secret_key: bytes) -> str:
    signing_key = nacl.signing.SigningKey(secret_key[:32])
    signed_message = signing_key.sign(message.encode('utf-8'))
    signature = signed_message.signature
    return base58.b58encode(signature).decode('utf-8')

def get_base_headers(user_agent: str) -> dict:
    return { 'accept': '*/*', 'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8', 'cache-control': 'no-cache', 'origin': 'https://www.bitquant.io', 'pragma': 'no-cache', 'priority': 'u=1, i', 'referer': 'https://www.bitquant.io/', 'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Opera";v="119"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site', 'user-agent': user_agent }

async def verify_signature(client: httpx.AsyncClient, address: str, message: str, signature: str) -> str:
    payload = {"address": address, "message": message, "signature": signature}
    response = await client.post('https://quant-api.opengradient.ai/api/verify/solana', json=payload)
    response.raise_for_status()
    return response.json()['token']

async def get_id_token(client: httpx.AsyncClient, token: str) -> dict:
    payload = {"token": token, "returnSecureToken": True}
    headers = { 'x-client-data': 'CJz7ygE=', 'x-client-version': 'Opera/JsCore/11.6.0/FirebaseCore-web', 'x-firebase-gmpid': '1:976084784386:web:bb57c2b7c2642ce85b1e1b' }
    client.headers.update(headers)
    response = await client.post(f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={API_KEY}', json=payload)
    response.raise_for_status()
    data = response.json()
    return {'idToken': data['idToken'], 'refreshToken': data['refreshToken']}

async def refresh_access_token(client: httpx.AsyncClient, refresh_token: str) -> dict:
    payload = f'grant_type=refresh_token&refresh_token={refresh_token}'
    headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'x-client-data': 'CJz7ygE=', 'x-client-version': 'Opera/JsCore/11.6.0/FirebaseCore-web', 'x-firebase-gmpid': '1:976084784386:web:bb57c2b7c2642ce85b1e1b' }
    client.headers.update(headers)
    response = await client.post(f'https://securetoken.googleapis.com/v1/token?key={API_KEY}', data=payload)
    response.raise_for_status()
    data = response.json()
    return {'accessToken': data['access_token'], 'refreshToken': data['refresh_token']}

async def send_chat(client: httpx.AsyncClient, access_token: str, context: dict, message: str) -> str:
    payload = {"context": context, "message": {"type": "user", "message": message}}
    headers = {'Authorization': f'Bearer {access_token}'}
    client.headers.update(headers)
    response = await client.post('https://quant-api.opengradient.ai/api/agent/run', json=payload)
    response.raise_for_status()
    return response.json()['message']

async def get_stats(client: httpx.AsyncClient, access_token: str, address: str) -> dict:
    headers = {'Authorization': f'Bearer {access_token}'}
    client.headers.update(headers)
    response = await client.get(f'https://quant-api.opengradient.ai/api/activity/stats?address={address}')
    response.raise_for_status()
    return response.json()

async def authenticate(address: str, secret_key: bytes, proxy: str | None, user_agent: str) -> dict:
    async def auth_attempt():
        headers = get_base_headers(user_agent)
        # ❗ WORKAROUND APPLIED HERE ❗
        async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
            if proxy:
                client.proxies = {"http://": proxy, "https://": proxy}
            
            message = generate_message(address)
            signature = sign_message(message, secret_key)
            token = await verify_signature(client, address, message, signature)
            tokens = await get_id_token(client, token)
            return {**tokens, 'base_headers': client.headers}
    return await with_retry(auth_attempt, action_text="Login")

async def process_accounts(private_keys, messages, account_proxies, chat_count, no_type):
    success_count, fail_count = 0, 0
    
    for i, private_key in enumerate(private_keys):
        proxy = account_proxies[i]
        try:
            keypair = Keypair.from_base58_string(private_key)
            address = str(keypair.pubkey())
        except Exception:
            console.print(f"[red]✗ Invalid private key for account {i + 1}[/red]")
            fail_count += 1
            continue
        
        short_address = f"{address[:8]}...{address[-6]}"
        console.print(f"═════[ [blue]Account {i + 1}/{len(private_keys)} | {short_address} @ {get_timestamp()}[/blue] ]═════")
        proxy_msg = f"Using proxy: {proxy}" if proxy else "No proxy"
        console.print(f" [cyan]┊ {proxy_msg}[/cyan]")
        
        session_state = {}

        try:
            auth_result = await authenticate(address, keypair.secret(), proxy, random.choice(USER_AGENTS))
            session_state.update({
                'id_token': auth_result['idToken'],
                'refresh_token': auth_result['refreshToken'],
                'base_headers': auth_result['base_headers'],
            })

            console.print(' [magenta]┊ ┌── Chat Process ──[/magenta]')
            
            for j in range(chat_count):
                console.print(f" [yellow]┊ ├─ Chat {create_progress_bar(j + 1, chat_count)} ──[/yellow]")
                random_message = random.choice(messages)
                console.print(f" [white]┊ │ Message:[yellow] {random_message}[/yellow][/white]")

                # ❗ WORKAROUND APPLIED HERE ❗
                async with httpx.AsyncClient(headers=session_state['base_headers'], timeout=30.0) as client:
                    if proxy:
                        client.proxies = {"http://": proxy, "https://": proxy}

                    try:
                        refresh_result = await with_retry(lambda: refresh_access_token(client, session_state['refresh_token']), action_text="Token Refreshed")
                        access_token = refresh_result['accessToken']
                        session_state['refresh_token'] = refresh_result['refreshToken']
                    except Exception as e:
                        console.print(f" [red]┊ │ Failed to refresh token. Re-authenticating...[/red]")
                        auth_result = await authenticate(address, keypair.secret(), proxy, random.choice(USER_AGENTS))
                        session_state.update({ 'id_token': auth_result['idToken'], 'refresh_token': auth_result['refreshToken'], 'base_headers': auth_result['base_headers'] })
                        access_token = session_state['id_token']
                        continue
                    
                    stats = await with_retry(lambda: get_stats(client, access_token, address), action_text="Getting Chat Statistic")
                    if stats['daily_message_count'] >= stats.get('daily_message_limit', DAILY_CHAT_LIMIT):
                        console.print(f" [red]┊ │ Daily chat limit reached.[/red]")
                        break

                    context = { "conversationHistory": [], "address": address, "poolPositions": [], "availablePools": [] }
                    response_msg = await with_retry(lambda: send_chat(client, access_token, context, random_message), action_text="Sending Message")
                    await type_text(response_msg, no_type)
                    updated_stats = await with_retry(lambda: get_stats(client, access_token, address), action_text="Getting Chat Statistic")
                    console.print(f" [cyan]┊ │ Chat Daily Usage: {updated_stats['daily_message_count']}/{updated_stats.get('daily_message_limit', DAILY_CHAT_LIMIT)}[/cyan]")

                console.print(' [yellow]┊ └──[/yellow]')
                await asyncio.sleep(8)
            
            console.print(' [yellow]┊ └──[/yellow]')
            console.print(' [magenta]┊ ┌── Account Statistics ──[/magenta]')
            
            # ❗ WORKAROUND APPLIED HERE ❗
            async with httpx.AsyncClient(headers=session_state['base_headers'], timeout=30.0) as client:
                if proxy:
                    client.proxies = {"http://": proxy, "https://": proxy}

                final_stats_access_token = (await refresh_access_token(client, session_state['refresh_token']))['accessToken']
                final_stats = await with_retry(lambda: get_stats(client, final_stats_access_token, address), action_text="Getting User Statistic")

                console.print(f" [white]┊ │ Address: {short_address}[/white]")
                console.print(f" [white]┊ │ Chat Daily Usage: {final_stats['daily_message_count']}[/white]")
                console.print(f" [white]┊ │ Chat Counted: {final_stats['message_count']}[/white]")
                console.print(f" [white]┊ │ Total Points: {final_stats['points']}[/white]")
                console.print(' [yellow]┊ └──[/yellow]')
                success_count += 1

        except Exception as e:
            console.print(f" [red]┊ ✗ Error processing account {i+1}: {e}[/red]")
            fail_count += 1
        finally:
            console.print(" [grey50]┊ ══════════════════════════════════════[/grey50]")
            
    console.print(f"═════[ [blue]Finished @ {get_timestamp()}[/blue] ]═════")
    console.print(f" [grey50]┊ ✅ {success_count} Account Success, ❌ {fail_count} Account Failed[/grey50]")


async def start_countdown(duration_seconds):
    end_time = time.time() + duration_seconds
    while (remaining := end_time - time.time()) > 0:
        hours, rem = divmod(remaining, 3600)
        minutes, seconds = divmod(rem, 60)
        sys.stdout.write(f"\033[96m┊ ⏳ Waiting To Next Loop: {int(hours):02}:{int(minutes):02}:{int(seconds):02}\033[0m\r")
        sys.stdout.flush()
        await asyncio.sleep(1)
    clear_console_line()

async def main():
    display_banner()
    no_type = '--no-type' in sys.argv
    try:
        with open('PrivateKeys.txt', 'r') as f:
            private_keys = [line.strip() for line in f if line.strip()]
        if not private_keys:
            console.print("[red]✗ No valid Private Key on PrivateKeys.txt![/red]")
            return
    except FileNotFoundError:
        console.print("[red]✗ File PrivateKeys.txt Not Found![/red]")
        return
        
    try:
        with open('command.txt', 'r', encoding='utf-8') as f:
            messages = [line.strip() for line in f if line.strip()]
        if not messages:
            console.print("[red]✗ File command.txt is empty![/red]")
            return
    except FileNotFoundError:
        console.print("[red]✗ File command.txt not found![/red]")
        return

    chat_count = int(Prompt.ask("[white]How Many Chats For Each Account[/white]", default=str(DAILY_CHAT_LIMIT)))
    if chat_count > DAILY_CHAT_LIMIT:
        console.print(f"[red]✗ Chat count cannot exceed daily limit ({DAILY_CHAT_LIMIT})![/red]")
        chat_count = DAILY_CHAT_LIMIT
        console.print(f"[cyan]┊ Setting chat count to {chat_count}[/cyan]")
    
    use_proxy = Prompt.ask("[white]Do You Want To Use Proxy? [/white]", choices=['y', 'n'], default='n')
    proxies = []
    if use_proxy.lower() == 'y':
        try:
            with open('proxy.txt', 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            if not proxies:
                console.print("[yellow]✗ proxy.txt is empty. Continuing without proxies.[/yellow]")
        except FileNotFoundError:
            console.print("[yellow]✗ proxy.txt not found. Continuing without proxies.[/yellow]")
    
    account_proxies = [random.choice(proxies) if proxies else None for _ in private_keys]
    
    while True:
        await process_accounts(private_keys, messages, account_proxies, chat_count, no_type)
        console.print(f"[green]┊ ⏰ All Processes Completed Successfully[/green]")
        await start_countdown(24 * 60 * 60)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]✗ Process interrupted by user. Exiting...[/yellow]")
