from flask import Flask, send_from_directory, jsonify


from flask import Flask, request, jsonify
import json
import os
import logging
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, constr, ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
import socket
from cryptography.fernet import Fernet
import uuid
from flask_cors import CORS
import subprocess
import threading
import requests
import random
import string
import mercadopago
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import time
import nest_asyncio
import asyncio
from telegram.ext import Application, ApplicationBuilder
import schedule
import pytz
from flask import Response

app = Flask(__name__, static_folder="static")
CORS(app)  # Permite requisições de qualquer origem

nest_asyncio.apply()
            
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
# Caminho oculto e local storage
HIDDEN_DIR = os.path.join(os.getenv('APPDATA') or '/tmp', 'AppCacheData')
LOCAL_STORAGE_PATH = os.path.join(HIDDEN_DIR, 'local_storage.json')

# Caminho para o diretório de cache e arquivo de chave
CACHE_DIR = os.path.join(os.getenv('APPDATA') or '/tmp', 'sys')
KEY_FILE_PATH = os.path.join(CACHE_DIR, 'fernet_key.key')

# Caminhos para os arquivos de login e de identificação
LOGIN_FILE_PATH = os.path.join(HIDDEN_DIR, 'login.json')
FUSO_HORARIO = pytz.timezone('America/Sao_Paulo')

LICENSES_FILE = 'licenses.json'

sdk = mercadopago.SDK(os.getenv('MERCADOPAGO_SDK'))

# Configurações do servidor
TOKEN_EXPIRY = timedelta(seconds=20)  # Tempo de validade do generated token (5 minutos)
tokens = {}
delete_commands = {}


# Configuração da API do Google Sheets
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)
client = gspread.authorize(creds)


# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class KeyValidation(BaseModel):
    key: constr(min_length=23, max_length=23) = Field(..., pattern=r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$')  # type: ignore # Verifica formato da chave
    mac_address: constr(min_length=17, max_length=17) = Field(..., pattern=r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')  # type: ignore # Verifica formato do MAC Address

def load_licenses():
    if os.path.exists(LICENSES_FILE):
        with open(LICENSES_FILE, 'r') as f:
            return json.load(f)
    return {"1m": {}, "3m": {}, "1y": {}}

def save_licenses(licenses):
    with open(LICENSES_FILE, 'w') as f:
        json.dump(licenses, f, indent=4)


# Configuração do log
logging.basicConfig(level=logging.INFO)

# Função para calcular a data de expiração com base no plano
def calculate_expiration_date(plan):
    if plan == '1m':
        return (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S.%f")
    elif plan == '3m':
        return (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S.%f")
    elif plan == '1y':
        return (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S.%f")

# Função para gerar uma nova chave de licença
def generate_license_key():
    return '-'.join([''.join(random.choices(string.ascii_uppercase + string.digits, k=5)) for _ in range(4)])

@app.route('/payment/create', methods=['POST'])
def create_payment():
    data = request.json
    logging.info(f"Dados recebidos para pagamento: {data}")

    if 'mac_address' not in data or 'plan' not in data:
        logging.warning("Dados incompletos. 'mac_address' ou 'plan' não encontrado.")
        return jsonify({"error": "Dados incompletos. 'mac_address' ou 'plan' não encontrado."}), 400

    mac_address = data['mac_address']
    plan = data['plan']

    # Definindo o preço com base no plano
    prices = {
        "1m": 90.00,   # 1 mês
        "3m": 240.00,   # 3 meses
        "1y": 840.00    # 1 ano
    }

    unit_price = prices.get(plan)
    if unit_price is None:
        logging.warning("Plano inválido. Verifique se o plano está correto.")
        return jsonify({"error": "Plano inválido."}), 400

    # Expiração para o Mercado Pago
    expiration_time = (datetime.now() + timedelta(minutes=120)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '-04:00'

    # Dados da preferência, incluindo o MAC address como external_reference
    preference_data = {
        "items": [
            {
                "title": f"Assinatura {plan}",
                "quantity": 1,
                "unit_price": unit_price  # Usando o preço definido
            }
        ],
        "expires": True,
        "date_of_expiration": expiration_time,  # Usando a variável correta
        "external_reference": f"{mac_address}:{plan}",  # Usando o mac_address e o plan aqui
        "payment_methods": {
            "excluded_payment_types": [
                {"id": "ticket"},  # Exclui boleto
                {"id": "credit_card"}  # Exclui cartões de crédito
            ],
            "excluded_payment_methods": [
                {"id": "debit_card"}  # Exclui cartões de débito
            ],
            "installments": 1,  # Configura para uma única parcela
            "payment_type": ["pix"]  # Inclui apenas o método de pagamento Pix
        }
    }

    logging.info(f"Dados da preferência de pagamento: {preference_data}")

    try:
        preference = sdk.preference().create(preference_data)
        logging.info(f"Preferência de pagamento criada: {preference['response']}")

        return jsonify({
            "init_point": preference["response"]["init_point"],
            "preference_id": preference["response"]["id"]
        }), 200

    except Exception as e:
        logging.error(f"Erro ao criar a preferência de pagamento: {e}")
        return jsonify({"error": "Erro ao criar a preferência de pagamento."}), 500




def send_ipn_notification(payment_id, license_key, mac_address, plan):
    ipn_data = {
        "payment_id": payment_id,
        "license_key": license_key,
        "mac_address": mac_address,
        "plan": plan
    }

    for attempt in range(3):  # Tentativas de reenvio
        try:
            response = requests.post("https://fishingbot-server.onrender.com/ipn", json=ipn_data)
            response.raise_for_status()  # Levanta um erro para códigos de status 4xx e 5xx
            logging.info("Notificação IPN enviada com sucesso.")
            return  # Se o envio foi bem-sucedido, saímos da função
        except requests.exceptions.HTTPError as http_err:
            logging.error(f"Erro ao enviar notificação IPN: {http_err}")
        except Exception as e:
            logging.error(f"Erro inesperado ao enviar notificação IPN: {e}")

        # Aguardar um curto período antes de tentar novamente (pode ajustar o tempo conforme necessário)
        time.sleep(2)

    logging.error("Falha ao enviar notificação IPN após várias tentativas.")





# Configurações para autenticação com a API do Google Sheets
def initialize_google_sheets():
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name("credentials.json", scope)
    client = gspread.authorize(creds)
    return client

# Rota para confirmação de pagamento
@app.route('/payment/confirm', methods=['POST'])
def confirm_payment():
    data = request.json
    logging.info(f"Dados recebidos para confirmação de pagamento: {data}")

    # Validação dos dados recebidos
    if not data or 'data' not in data or 'id' not in data.get('data', {}):
        logging.warning("Dados incompletos ou 'data' não contém 'id'. Verifique o payload.")
        return jsonify({"error": "Dados incompletos."}), 400

    payment_id = data['data']['id']
    logging.info(f"ID do pagamento: {payment_id}")

    try:
        # Recupera detalhes do pagamento usando a SDK
        payment = sdk.payment().get(payment_id)
        logging.info(f"Detalhes do pagamento recuperado: {payment}")

        if payment["response"]["status"] == "approved":
            external_reference = payment["response"].get("external_reference")
            if not external_reference:
                logging.warning("Referência externa não encontrada no pagamento.")
                return jsonify({"error": "Referência externa não encontrada."}), 400

            mac_address, plan = external_reference.split(':')
            licenses = load_licenses()

            # Verifica se já existe uma licença para o mac_address e plano
            existing_license = next((key for key, details in licenses[plan].items()
                                     if details['mac_address'] == mac_address and 
                                     details['expiration_date'] is None), None)

            if existing_license:
                logging.info(f"Uma licença já existe para {mac_address}. Chave: {existing_license}")
                return jsonify({"license_key": existing_license, "payment_id": payment_id, "message": "Licença já existente."}), 200

            # Calcula a data de expiração da nova licença
            expiration_date = calculate_expiration_date(plan)
            license_key = generate_license_key()

            # Atualiza as licenças com a nova licença
            updated_licenses = {**licenses}  # Clonando o dicionário de licenças
            updated_licenses[plan][license_key] = {
                "mac_address": mac_address,
                "expiration_date": expiration_date,
                "started_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            }

            save_licenses(updated_licenses)

            # Informações do pagamento aprovado
            approved_payment_info = {
                "mac_address": mac_address,
                "payment_id": payment_id,
                "license_key": license_key,
                "plan": plan,
                "expiration_date": expiration_date,
                "started_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            }
            save_approved_payment(approved_payment_info)

            # Enviar informações para o Google Sheets
            client = initialize_google_sheets()
            sheet = client.open_by_url("https://docs.google.com/spreadsheets/d/1FMrVu3ZoWS1SIgAPOVo7whAIK56IJEirKRfNpJWKTro/edit?gid=0#gid=0").sheet1
            row = [mac_address, payment_id, license_key, plan, expiration_date, approved_payment_info["started_date"]]
            sheet.append_row(row)

            logging.info(f"Pagamento aprovado. Chave gerada: {license_key}, Expiração: {expiration_date}")

            # Aqui, chamamos a função para enviar os dados ao IPN
            send_ipn_notification(payment_id, license_key, mac_address, plan)

            return jsonify({"license_key": license_key, "payment_id": payment_id, "expiration_date": expiration_date}), 200

        else:
            logging.warning(f"Pagamento não aprovado: {payment['response']['status']}")
            return jsonify({"error": "Pagamento não aprovado."}), 400

    except Exception as e:
        logging.error(f"Erro ao recuperar pagamento: {e}")
        return jsonify({"error": "Erro ao confirmar o pagamento."}), 500



last_ipn_data = {}

@app.route('/ipn', methods=['POST'])
def ipn_listener():
    global last_ipn_data
    data = request.json
    logging.info(f"Notificação IPN recebida: {data}")
    
    last_ipn_data = data  # Armazenar os dados da última IPN recebida

    return jsonify({"status": "success"}), 200

@app.route('/ipn/last', methods=['GET'])
def get_last_ipn():
    return jsonify(last_ipn_data), 200


def save_approved_payment(payment_info):
    try:
        # Tenta carregar pagamentos aprovados existentes
        try:
            with open('aprovados.json', 'r') as file:
                approved_payments = json.load(file)
        except FileNotFoundError:
            approved_payments = []

        # Adiciona a nova informação de pagamento
        approved_payments.append(payment_info)

        # Salva a lista de pagamentos aprovados de volta no arquivo
        with open('aprovados.json', 'w') as file:
            json.dump(approved_payments, file, indent=4)

    except Exception as e:
        logging.error(f"Erro ao salvar pagamento aprovado: {e}")


@app.route('/payment/confirm_status', methods=['GET'])
def confirm_status():
    payment_id = request.args.get('payment_id')  # Obtém o payment_id da query string
    if not payment_id:
        return jsonify({"error": "payment_id é necessário."}), 400

    # Tenta encontrar o pagamento aprovado em aprovados.json
    try:
        with open('aprovados.json', 'r') as file:
            approved_payments = json.load(file)

        # Procura pelo payment_id na lista de pagamentos aprovados
        payment_info = next((payment for payment in approved_payments if payment["payment_id"] == payment_id), None)

        if payment_info:
            return jsonify(payment_info), 200  # Retorna as informações do pagamento
        else:
            return jsonify({"error": "Pagamento não encontrado."}), 404

    except FileNotFoundError:
        return jsonify({"error": "Arquivo de pagamentos aprovados não encontrado."}), 404
    except Exception as e:
        logging.error(f"Erro ao verificar status do pagamento: {e}")
        return jsonify({"error": "Erro ao verificar status do pagamento."}), 500


@app.route('/payment/status', methods=['GET'])
def payment_status():
    preference_id = request.args.get('preference_id')

    if not preference_id:
        return jsonify({"error": "ID da preferência não fornecido."}), 400

    try:
        payment_info = sdk.payment().search({'preference_id': preference_id})
        
        if payment_info['paging']['total'] > 0:
            status = payment_info['results'][0]['status']
            return jsonify({"payment_status": status}), 200
        else:
            return jsonify({"message": "Nenhum pagamento encontrado para esse ID de preferência."}), 404

    except Exception as e:
        logging.error(f"Erro ao consultar status de pagamento: {e}")
        return jsonify({"error": "Erro ao consultar status de pagamento."}), 500


# Credenciais e escopo de acesso ao Google Sheets
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)
client = gspread.authorize(creds)

# Abra a planilha pelo ID (extraído do link da planilha)
spreadsheet = client.open_by_key('1wb8Axt25BHWTbfggoPxJx9JPCHQLHy5wMlogqcBxVTA')

# Seleciona a primeira aba (pode ajustar se necessário)
sheet = spreadsheet.sheet1

@app.route('/register', methods=['POST'])
def register():
    """Rota para registrar um novo usuário com nome, email e MAC address."""
    data = request.json
    print(f"Dados recebidos: {data}")  # Log dos dados recebidos

    if not data or 'name' not in data or 'email' not in data or 'mac_address' not in data:
        return jsonify({'status': 'error', 'message': 'Dados ausentes.'}), 400

    # Remove espaços em branco dos dados recebidos
    name = str(data['name']).strip()
    email = str(data['email']).strip()
    mac_address = str(data['mac_address']).strip().replace(':', '-').lower()

    # Obtenha todos os registros da planilha
    all_records = sheet.get_all_records()
    print(f"Registros encontrados na planilha: {all_records}")  # Log para verificar os registros

    for user in all_records:
        # Garante que os valores são strings antes de aplicar strip e outras operações
        user_name = str(user.get('Nome', '')).strip()
        user_email = str(user.get('Email', '')).strip()
        user_mac = str(user.get('MAC Address', '')).strip().replace(':', '-').lower()

        # Verifica se o MAC Address já está registrado
        if user_mac == mac_address:
            # Se o nome e o email também são iguais, não há erro
            if user_name == name and user_email == email:
                return jsonify({'status': 'success', 'message': 'Registro já existe com o mesmo nome e email.'}), 200
            # Caso contrário, retorna erro
            return jsonify({'status': 'error', 'message': 'MAC address já registrado com nome ou email diferentes.'}), 400

    # Verifica se o nome ou email já estão registrados
    if any(str(user.get('Nome', '')).strip() == name for user in all_records):
        return jsonify({'status': 'error', 'message': 'Nome já registrado. Tente outro.'}), 400
    if any(str(user.get('Email', '')).strip() == email for user in all_records):
        return jsonify({'status': 'error', 'message': 'Email já registrado. Tente outro.'}), 400

    # Adiciona os novos dados de login na planilha
    sheet.append_row([name, email, mac_address])  # Adiciona uma nova linha com os dados

    return jsonify({'status': 'success', 'message': 'Registro criado com sucesso!'}), 201



def get_expiry_date(period):
    periods = {
        '1m': timedelta(days=30),
        '3m': timedelta(days=90),
        '1y': timedelta(days=365)
    }
    return datetime.now() + periods.get(period, timedelta())

def get_client_ip():
    """Retorna o IP real do cliente a partir da solicitação."""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0]  # Considera o primeiro IP
    return request.remote_addr



def get_local_ip():
    """Obtém o IP local da máquina que está executando o Flask."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

LOCAL_IP = get_local_ip()  # Armazena o IP local

# Configuração do logger
@app.before_request
def log_request_info():
    client_ip = get_client_ip()
    app.logger.info(f'IP: {client_ip} - {request.method} {request.path}')

# Configurando o Limiter com limite global e backend adequado
limiter = Limiter(
    key_func=get_client_ip,  # Captura o IP real do cliente
    app=app,
    storage_uri="memory://",  # Armazenamento em memória (troque por Redis se precisar)
    default_limits=["5000 per day", "700 per hour", "100 per minute"],  # Limites globais
    strategy="fixed-window"  # Estratégia fixa
)

# Rota com limite de 10 requisições por minuto
@app.route("/api")
@limiter.limit("5 per minute")
def api():
    client_ip = get_client_ip()
    app.logger.info(f'Rate limit active for IP: {client_ip}')  # Log adicional para rate-limit
    return jsonify({"message": "This is a rate-limited response!"})

# Permitir apenas um IP específico
ALLOWED_IPS = ['143.255.2.159']  # Lista de IPs permitidos

@app.before_request
def limit_access_to_ip():
    """Bloqueia acessos não autorizados para determinadas rotas."""
    if request.endpoint in ['generate_token', 'send_delete_command']:
        client_ip = get_client_ip()  # Use get_client_ip aqui
        logger.info(f"IP: {client_ip} - POST {request.endpoint}")  # Log para verificação
        if client_ip not in ALLOWED_IPS:
            logger.warning(f"Acesso não autorizado do IP: {client_ip}. Apenas os IPs permitidos {ALLOWED_IPS} podem acessar essa rota.")
            return jsonify({"message": "Acesso não autorizado", "status": "error"}), 403



def check_password(password):
    return password == ADMIN_PASSWORD

@app.route('/generate_token', methods=['POST'])
def generate_token():
    """Rota para gerar um token de autenticação para um MAC address"""
    try:
        auth = request.headers.get('Authorization')
        if not auth or not check_password(auth.split(' ')[1]):
            return jsonify({"message": "Senha inválida", "status": "error"}), 403
        
        data = request.json
        mac_address = data.get('mac_address')

        if not mac_address:
            return jsonify({"message": "MAC address não fornecido", "status": "error"}), 400

        # Gera um token único e define sua expiração
        token = str(uuid.uuid4())
        tokens[token] = {
            'mac_address': mac_address,
            'expires_at': datetime.utcnow() + TOKEN_EXPIRY
        }

        return jsonify({"token": token, "status": "success"}), 200

    except Exception as e:
        logger.error(f"Erro na rota /generate_token: {e}")
        return jsonify({"message": "Erro ao processar a solicitação.", "status": "error"}), 500

@app.route('/send_delete_command', methods=['POST'])
def send_delete_command():
    try:
        auth = request.headers.get('Authorization')
        if not auth or not check_password(auth.split(' ')[1]):
            return jsonify({"message": "Senha inválida", "status": "error"}), 403
        
        data = request.json
        mac_address = data.get('mac_address')
        token = data.get('token')

        if not mac_address or not token:
            return jsonify({"message": "MAC address ou token não fornecido", "status": "error"}), 400

        # Verificar se o token existe e não expirou
        if token not in tokens:
            return jsonify({"message": "Token inválido ou expirado", "status": "error"}), 403

        # Verificar a expiração do token
        token_data = tokens[token]
        if datetime.utcnow() > token_data['expires_at']:
            del tokens[token]
            return jsonify({"message": "Token expirado", "status": "error"}), 403

        # Verifica se o MAC address do token corresponde ao enviado
        if token_data['mac_address'] != mac_address:
            return jsonify({"message": "MAC address não corresponde ao token", "status": "error"}), 403

        # Armazena o comando de exclusão para o MAC address específico
        delete_commands[mac_address] = True

        return jsonify({"message": f"Comando de exclusão enviado para {mac_address}", "status": "success"}), 200

    except Exception as e:
        print(f"Erro na rota /send_delete_command: {e}")
        return jsonify({"message": "Erro ao processar a solicitação.", "status": "error"}), 500


from flask import request

@app.route('/check_delete_command', methods=['POST'])
def check_delete_command():
    """Rota para verificar se há um comando de exclusão para um MAC address específico"""
    try:
        data = request.json
        mac_address = data.get('mac_address')
        days_remaining = data.get('days_remaining')  # Recebe os dias restantes enviados pelo bot
        
        # Verifica o IP do cliente
        if 'X-Forwarded-For' in request.headers:
            client_ip = request.headers['X-Forwarded-For'].split(',')[0]  # Pode ter múltiplos IPs
        else:
            client_ip = request.remote_addr  # IP do cliente

        if not mac_address:
            return jsonify({"message": "MAC address não fornecido", "status": "error"}), 400

        # Verifica se há um comando de exclusão para o MAC address
        if delete_commands.get(mac_address):
            del delete_commands[mac_address]  # Remove o comando após o uso
            logger.info(f"Comando de exclusão encontrado para MAC address: {mac_address} - IP: {client_ip}")
            return jsonify({"message": "Comando de exclusão encontrado.", "status": "success"}), 200
        else:
            logger.info(f"Exclusão não encontrada para MacAddress: {mac_address}, {days_remaining} dias restantes - IP: {client_ip}")
            return jsonify({"message": f"Exclusão não encontrada para MacAddress: {mac_address}, {days_remaining} dias restantes.", "status": "no_command"}), 200

    except Exception as e:
        logger.error(f"Erro na rota /check_delete_command: {e}")
        return jsonify({"message": "Erro ao processar a solicitação.", "status": "error"}), 500


# Função para salvar a licença atualizada
def save_license(row_index, mac_address, started_date_str, expiration_date_str):
    client = authenticate_google_sheets()
    sheet = client.open_by_url("https://docs.google.com/spreadsheets/d/1FMrVu3ZoWS1SIgAPOVo7whAIK56IJEirKRfNpJWKTro/edit#gid=0").sheet1

    # Atualiza a linha com os novos dados
    sheet.update_cell(row_index, 1, mac_address)  # Coluna MAC Address
    sheet.update_cell(row_index, 6, started_date_str)  # Coluna Started Date
    sheet.update_cell(row_index, 5, expiration_date_str)  # Coluna Expiration Date


# Configuração da autenticação do Google Sheets
# Função para autenticar no Google Sheets
# Define o fuso horário de Brasília
timezone_br = pytz.timezone("America/Sao_Paulo")
# Função para obter o horário atual em Brasília (UTC-3)
def get_current_time_brazil():
    timezone_brazil = pytz.timezone('America/Sao_Paulo')
    return datetime.now(timezone_brazil)

# Função ajustada para carregar e tratar a data de expiração como offset-aware
def parse_expiration_date(date_str):
    timezone_brazil = pytz.timezone('America/Sao_Paulo')
    # Converte a string para um objeto datetime e aplica o fuso horário de Brasília
    naive_date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f')
    return timezone_brazil.localize(naive_date)
            
def authenticate_google_sheets():
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)
    client = gspread.authorize(creds)
    return client


# Função para carregar as licenças da planilha
def load_license():
    client = authenticate_google_sheets()
    sheet = client.open_by_url("https://docs.google.com/spreadsheets/d/1FMrVu3ZoWS1SIgAPOVo7whAIK56IJEirKRfNpJWKTro/edit#gid=0").sheet1
    data = sheet.get_all_records()

    licenses = []
    for row in data:
        licenses.append({
            'mac_address': row.get('MAC Address'),
            'key': row.get('License Key'),
            'expiration_date': row.get('Expiration Date'),
            'started_date': row.get('Started Date'),
            'plan': row.get('Plan'),
            'row_index': data.index(row) + 2  # Mantém o índice da linha para futuras atualizações
        })

    return licenses

# Ajuste na função validate_key
@app.route('/validate', methods=['POST'])
def validate_key():
    data = request.json
    client_ip = get_client_ip()

    if not data or 'key' not in data or 'mac_address' not in data:
        logger.warning(f'[{client_ip}] Dados ausentes na solicitação de validação.')
        return jsonify({'status': 'error', 'message': 'Dados ausentes.'}), 400

    key = data['key']
    mac_address = data['mac_address']

    try:
        logger.info(f'[{client_ip}] Recebendo validação para chave: {key} e MAC address: {mac_address}')
        licenses = load_license()

        for license_info in licenses:
            if license_info['key'] == key:

                # Verifica se o MAC address é o mesmo
                if license_info['mac_address'] == mac_address:
                    # Ajuste para tornar a data de expiração offset-aware
                    expiration_date = parse_expiration_date(license_info['expiration_date'])
                    current_time_brazil = get_current_time_brazil()

                    if current_time_brazil > expiration_date:
                        logger.warning(f'[{client_ip}] A chave expirou: {key}')
                        return jsonify({'status': 'error', 'message': 'A chave expirou.'})

                    days_remaining = (expiration_date - current_time_brazil).days
                    logger.info(f'[{client_ip}] Chave validada com sucesso para MAC address: {mac_address}')
                    return jsonify({
                        'status': 'success',
                        'message': 'Chave já associada nesse MAC address.',
                        'expiration_date': license_info['expiration_date'],
                        'started_date': license_info['started_date'],
                        'plan': license_info['plan'],
                        'days_remaining': days_remaining
                    })

                # Se os campos estiverem vazios (não preenchidos)
                if not license_info['mac_address'] and not license_info['expiration_date'] and not license_info['started_date']:
                    expiration_date = get_expiry_date(license_info['plan'])
                    if expiration_date:
                        expiration_date_str = expiration_date.strftime('%Y-%m-%d %H:%M:%S.%f')
                        started_date_str = get_current_time_brazil().strftime('%Y-%m-%d %H:%M:%S.%f')

                        # Atualiza a planilha com os novos dados
                        save_license(license_info['row_index'], mac_address, started_date_str, expiration_date_str)

                        logger.info(f'[{client_ip}] A chave foi associada ao MAC address: {mac_address}')
                        return jsonify({
                            'status': 'success',
                            'message': 'A chave foi associada ao MAC address e validada.',
                            'expiration_date': expiration_date_str,
                            'started_date': started_date_str,
                            'plan': license_info['plan'],
                            'days_remaining': (expiration_date - get_current_time_brazil()).days
                        })

                logger.warning(f'[{client_ip}] Chave associada com outro MAC address: {key}')
                return jsonify({'status': 'error', 'message': 'Chave associada com outro MAC address.'})

        logger.warning(f'[{client_ip}] A chave não existe: {key}')
        return jsonify({'status': 'error', 'message': 'A chave não existe.'})

    except Exception as e:
        logger.error(f'[{client_ip}] Erro ao acessar a planilha: {e}')
        return jsonify({'status': 'error', 'message': 'Erro ao acessar a planilha.'}), 500
        
@app.route("/version.json")
def version():
    return send_from_directory("static", "version.json", mimetype="application/json")

@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory("static", filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
