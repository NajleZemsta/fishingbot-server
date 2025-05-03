import os
from flask import Flask, request, abort
import requests

app = Flask(__name__)

# --- Configuração Inicial (substitua pelos seus valores ou variáveis de ambiente) ---
WHATSAPP_TOKEN = os.environ['WHATSAPP_TOKEN']
PHONE_ID       = os.environ['PHONE_ID']
VERIFY_TOKEN   = os.environ['VERIFY_TOKEN']

API_URL = f'https://graph.facebook.com/v18.0/{PHONE_ID}/messages'
HEADERS = {
    'Authorization': f'Bearer {WHATSAPP_TOKEN}',
    'Content-Type': 'application/json'
}

# Rota de verificação do webhook (GET)
@app.route('/webhook', methods=['GET'])
def verify():
    mode      = request.args.get('hub.mode')
    token     = request.args.get('hub.verify_token')
    challenge = request.args.get('hub.challenge')

    if mode == 'subscribe' and token == VERIFY_TOKEN:
        # WhatsApp Cloud API espera que você retorne o 'challenge' puro
        return challenge, 200
    else:
        return abort(403)

# Rota de recebimento de mensagens (POST)
@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.get_json(force=True)
    # print(data)  # descomente para debug

    entry = data.get('entry', [])
    if entry:
        changes = entry[0].get('changes', [])
        if changes:
            value = changes[0].get('value', {})
            messages = value.get('messages', [])
            if messages:
                msg   = messages[0]
                phone = msg.get('from')
                text  = msg.get('text', {}).get('body', '').strip()

                # lógica de menu
                if text == '1':
                    resposta = "Você escolheu: Saber mais sobre nossos produtos."
                elif text == '2':
                    resposta = "Você escolheu: Falar com um atendente."
                else:
                    resposta = (
                        "Olá! 👋 Bem-vindo!\n"
                        "Digite uma das opções abaixo:\n"
                        "1️⃣ - Saber mais sobre nossos produtos\n"
                        "2️⃣ - Falar com um atendente"
                    )

                enviar_mensagem(phone, resposta)

    return 'OK', 200

def enviar_mensagem(to, text):
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": text}
    }
    requests.post(API_URL, json=payload, headers=HEADERS)

if __name__ == '__main__':
    # host=0.0.0.0 pra aceitar requisições externas
    app.run(host='0.0.0.0', port=5000)
