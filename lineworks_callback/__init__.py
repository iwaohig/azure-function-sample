import logging
import hmac
import hashlib
import base64
import requests
from flask import Request, jsonify

# LINE WORKS Bot Credentials
CHANNEL_SECRET = "+9/2qJd45/R3a18/6xUUlo1r5HSJYZ"
BOT_API_URL = "https://www.worksapis.com/v1.0/bots"
ACCESS_TOKEN = "jp1AAABHD12ezPpVQWI137q06Dk+w1OLLF3XxGkT1H/RIWdvY/TcNBADXGXeaQfcd3Ay6JQENlwK0xZ6PHB+gRG8kxMgnZLyUCC53Q7f9zYbCxH11k4q8qUswl8xzsWKOFK8aHU69zxjN0zcFZBXshkqZkNN8lgFE0UmYoYMJ5ItWLKV+klRcE9FdNpjSmlKu4Ng0GyeoUhOAdvvtiMielSfN93OYiM5rEJY2NWbFvqgmBACpsxrfIP1DSHRnhh3DQ3/vzXjz6ibTGekrJ5yjH1h3Jh8dUz7d90JfDqL7HqvsVKN6iM6gNMcBdg/k8wDuu/0skPSj1jFOro8Y0FtS84de0GhRnGKVyx67Er4nJfX1NrDBjessZ5/fKeM+z4HqEEpgIF0g==.kwiu9yNovfcs8Rumz2QSOg"

def main(req: Request) -> jsonify:
    logging.info('LINE WORKS Callback function received a request.')

    try:
        # Verify request signature
        signature = req.headers.get('X-WORKS-Signature', '')
        body = req.get_data(as_text=True)
        if not verify_signature(body, signature, CHANNEL_SECRET):
            return jsonify({"message": "Invalid signature"}), 401

        # Parse callback data
        data = req.get_json()
        source = data.get('source')
        if source is None:
            return jsonify({"message": "Invalid source"}), 400

        user_id = source.get('userId')
        text = data.get('content', {}).get('text', '')

        if user_id and text:
            # Reply to the sender
            reply_to_sender(user_id, text)
            return jsonify({"message": "Success"}), 200
        else:
            return jsonify({"message": "Missing user or text data"}), 400
    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return jsonify({"message": "Internal Server Error"}), 500


def verify_signature(body, signature, secret):
    mac = hmac.new(secret.encode('utf-8'), body.encode('utf-8'), hashlib.sha256)
    expected_signature = base64.b64encode(mac.digest()).decode('utf-8')
    return hmac.compare_digest(expected_signature, signature)


def reply_to_sender(user_id, message):
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Authorization": f"Bearer {ACCESS_TOKEN}"
    }
    payload = {
        "accountId": user_id,
        "content": {
            "type": "text",
            "text": f"You said: {message}"
        }
    }

    # メッセージ送信のエンドポイント
    url = f"{BOT_API_URL}/{your_bot_no}/messages"

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    logging.info(f"Message sent successfully: {response.json()}")

