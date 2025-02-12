import json
import os
import base58
import hashlib
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from bip_utils import (
    Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
)
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
import requests

# Конфигурация
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Открытие и загрузка данных из конфига в переменные
with open("config.json", "r") as f:
    CONFIG = json.load(f)

depth = CONFIG['depth']
node_file = CONFIG['node_file']
wallets_dir = CONFIG['wallets_dir']

os.makedirs(wallets_dir, exist_ok=True) # Создание директории для хранения файлов кошельков


class DashWalletManager:
    @staticmethod
    def generate_wallet(mnemonic: str) -> dict:
        """Генерирует кошелек Dash на основе мнемонической фразы"""
        # В данном коде генерируются адреса и приватные ключи
        wallets = {'receiving': [], 'change': []}
        try:
            # Получение seed на основе мнемонической фразы
            seed = Bip39SeedGenerator(mnemonic).Generate()
            # Получение мастер ключа
            master = Bip44.FromSeed(seed, Bip44Coins.DASH)

            def generate_addresses(change_type: Bip44Changes) -> list:
                return [
                    (
                        derived.PublicKey().ToAddress(),
                        DashWalletManager.private_to_wif(derived.PrivateKey().Raw().ToHex())
                    )
                    for idx in range(depth)
                    for derived in [master.Purpose().Coin().Account(0).Change(change_type).AddressIndex(idx)]
                ]

            wallets['receiving'] = generate_addresses(Bip44Changes.CHAIN_EXT)
            wallets['change'] = generate_addresses(Bip44Changes.CHAIN_INT)

        except Exception as e:
            print(f"Ошибка генерации кошелька: {e}")

        return wallets

    @staticmethod
    def private_to_wif(private_key_hex: str) -> str:
        """Конвертирует приватный ключ в WIF формат"""
        raw_key = bytes.fromhex(private_key_hex)
        key_suffix = raw_key + b'\x01'
        prefixed = b'\xcc' + key_suffix

        first_hash = hashlib.sha256(prefixed).digest()
        checksum = hashlib.sha256(first_hash).digest()[:4]

        return base58.b58encode(prefixed + checksum).decode()


class NodeManager:
    @staticmethod
    def parse_node(node_str: str) -> tuple:
        """Парсит строку подключения к ноде"""
        # Разбивает строку с адресом ноды на части (ссылка, логин, пароль или только ссылка)
        if "|" in node_str:
            url, auth = node_str.split("|", 1)
            login, password = auth.split(":", 1)
        else:
            url, login, password = node_str, None, None

        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        return url, login, password

    @staticmethod
    def send_rpc_command(node_str: str, method: str, params: list) -> dict:
        """Отправляет RPC команду к ноде Dash"""
        # В данной функции можно подставлять различные методы и параметры, поэтому она универсальная
        url, login, password = NodeManager.parse_node(node_str)

        # отправляемые данные
        payload = {
            "jsonrpc": "1.0",
            "id": "curltest",
            "method": method,
            "params": params
        }

        try:
            # Отправка POST запроса
            response = requests.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                auth=(login, password) if login and password else None,
                timeout=10
            )
            print (response.json())  # Принт сделан для дебага
            return response.json() if response.status_code == 200 else {"error": "Ошибка запроса"}
        except Exception as e:
            return {"error": str(e)}


class CryptoUtils:
    @staticmethod
    def encrypt(data: str, password: str) -> str:
        """Шифрует данные с использованием пароля"""
        # Для шифрования используется AES GCM, точно так же как и в большинстве холодных кошельков
        salt = get_random_bytes(16)
        key = scrypt(password.encode(), salt, key_len=32, N=2 ** 20, r=8, p=1)
        nonce = get_random_bytes(12)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        return base64.b64encode(salt + nonce + ciphertext + tag).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_data: str, password: str) -> str:
        """Дешифрует данные с использованием пароля"""
        # В функцию передаются шифрованные данные в виде строки и ключ для расшифровки
        # Используемое шифрование это AES GCM
        encrypted_bytes = base64.b64decode(encrypted_data)

        salt = encrypted_bytes[:16]
        nonce = encrypted_bytes[16:28]
        ciphertext = encrypted_bytes[28:-16]
        tag = encrypted_bytes[-16:]

        key = scrypt(password.encode(), salt, key_len=32, N=2 ** 20, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        except ValueError:
            raise ValueError("Неверный пароль или поврежденные данные")


# Вспомогательные функции
def validate_filename(filename: str) -> str:
    """Валидация и нормализация имени файла"""
    filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_')).strip()
    if not filename:
        raise ValueError("Недопустимое имя файла")
    return filename + '.txt' if not filename.endswith('.txt') else filename


# Функция вызывается в функции /login для того что бы передать список адресов нод на страницу профиля в кошельке
def load_nodes() -> list:
    """Загружает список нод из файла"""
    if not os.path.exists(node_file):
        return []

    with open(node_file, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


# Маршруты Flask
# Страница выбора, создать или импортировать кошелек
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/create', methods=['POST'])
def create_wallet():
    return render_template('create_wallet.html')

# Маршрут для генерации мнемонической фразы и переадресации на страницу enter_password.
# Вызывается на странице create_wallet (там где выбор создать кошелек со своей мнемоникой или сгенерировать)
# На странице enter_password вводится пароль для будущего кошелька
# Bip39MnemonicGenerator().FromWordsNumber(12).ToStr() генерирует мнемоническую фразу из 12 слов и передает ее на страницу enter_password.html
@app.route('/generate', methods=['POST'])
def generate_mnemonic():
    return render_template(
        'enter_password.html',
        mnemonic=Bip39MnemonicGenerator().FromWordsNumber(12).ToStr()
    )

# Маршрут для передачи мнемонической фразы на страницу enter_password
# На странице enter_password вводится пароль для будущего кошелька.
# Вызывается на странице enter_mnemonic (там где нужно вводить мнемонику самому при создании кошелька)
@app.route('/process_mnemonic', methods=['POST'])
def process_mnemonic():
    return render_template(
        'enter_password.html',
        mnemonic=request.form['mnemonic'].strip()
    )


# Вызывается на странице enter_password
# Тут вызывается функция для генерации адресов и приватных ключей, затем они записываются в тхт и шифруются с помощью другой функции
@app.route('/encrypt', methods=['POST'])
def encrypt_wallet():
    try:
        mnemonic = request.form['mnemonic']
        password = request.form['password']
        filename = validate_filename(request.form['wallet_name'])

        filepath = os.path.join(wallets_dir, filename)
        if os.path.exists(filepath):
            raise ValueError("Файл уже существует")

        # Вызов функции для генерации кошелька с передачей в нее мнемонической фразы
        wallets = DashWalletManager.generate_wallet(mnemonic)
        # Сбор всех данных в одну переменную, чтобы потом зашифровать все эти данные
        data = f"Mnemonic: {mnemonic}\n\n=== Receiving ===\n"
        data += "\n".join(f"Address: {a}\nPrivate: {p}\n" for a, p in wallets['receiving'])
        data += "\n=== Change ===\n"
        data += "\n".join(f"Address: {a}\nPrivate: {p}\n" for a, p in wallets['change'])

        # Записать все данные в тхт, но в зашифрованном виде с помощью функции encrypt в классе CryptoUtils
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(CryptoUtils.encrypt(data, password))

        flash(f"Кошелек {filename} успешно создан", "success")
        # При успешном создании кошелька вызывается маршрут auth
        return redirect(url_for('auth'))

    except Exception as e:

        return redirect(url_for('enter_password'))  # Перенаправляем на обработку GET


@app.route('/enter_password', methods=['GET'])
def enter_password():
    # Извлекаем сохраненные данные из сессии
    return render_template('enter_password.html')


# Маршрут вызывается при успешном создании кошелька и записи его в тхт или на главной странице сайта при нажатии на кнопку импортирование кошелька
# На страницу передается список файлов с кошельками для выбора нужного
# На самой странице после выбора кошелька и указания пароля вызывается маршрут /login
@app.route('/auth')
def auth():
    return render_template(
        'auth.html',
        wallet_files=[f for f in os.listdir(wallets_dir) if f.endswith('.txt')]
    )


# Функция для авторизации в кошельке.
# Расшифровывает файл кошелька используя переданный в функцию пароль с помощью функции расшифровки
# После расшифровки, отображает страницу профиля.
# Передает на страницу профиля адреса, приватные ключи, мнемонику, список адресов нод записанных в тхт
@app.route('/login', methods=['POST'])
def login():
    try:
        # Берет данные из формы
        filename = request.form['wallet_file']
        password = request.form['password']
        filepath = os.path.join(wallets_dir, filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError("Файл кошелька не найден")
        # Открытие файла кошелька и его расшифровка с помощью функции decrypt в классе CryptoUtils
        with open(filepath, 'r', encoding='utf-8') as f:
            data = CryptoUtils.decrypt(f.read(), password)

        parts = data.split('\n')
        wallets = {'receiving': [], 'change': []}
        current_section = None
        # Разбитие данных из файла на переменные
        for line in parts[2:]:
            line = line.strip()
            if line == '=== Receiving ===':
                current_section = 'receiving'
            elif line == '=== Change ===':
                current_section = 'change'
            elif line.startswith('Address:'):
                addr = line.split(': ')[1]
            elif line.startswith('Private:'):
                priv = line.split(': ')[1]
                if current_section:
                    wallets[current_section].append((addr, priv))

        return render_template(
            'profile.html',
            mnemonic=parts[0].split(': ')[1],
            receiving=wallets['receiving'],
            change=wallets['change'],
            nodes=load_nodes()
        )

    except Exception as e:
        flash(str(e), "error")
        return redirect(url_for('auth'))


# Функция проверки баланса используя отправку запроса на ноду
@app.route('/check_balances', methods=['POST'])
def check_balances():
    try:
        data = request.get_json()
        addresses = data.get('addresses', [])
        selected_node = session.get('selected_node', '127.0.0.1')

        results = {}
        for addr in addresses:
            # Отправка тела запроса в функцию для отправки запросов
            response = NodeManager.send_rpc_command(
                selected_node,
                'getaddressbalance',
                [{"addresses": [addr]}]
            )

            if response.get('error'):
                results[addr] = response['error']
            else:
                balance = response.get('result', {}).get('balance', 0) / 1e8
                results[addr] = balance

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# На странице профиля кошелька есть возможность добавлять адреса к нодам
# Со страницы передается адрес в функцию, а затем записывается в текстовый файл
@app.route('/save_node_settings', methods=['POST'])
def save_node_settings():
    try:
        node_str = request.form['node-address']
        if request.form.get('auth-required') == 'on':
            node_str += f"|{request.form['node-username']}:{request.form['node-password']}"

        with open(node_file, 'a', encoding='utf-8') as f:
            f.write(node_str + '\n')

        flash("Настройки ноды сохранены", "success")
        return '', 204

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Запись выбранной ноды на странице кошелька в сессию.
# Сохраненный адрес ноды в сессии будет использоваться для отправки запросов на ноду
@app.route('/select_node', methods=['POST'])
def select_node():
    # Из запроса с сайта берется нода и записывается в сессию в ключ selected_node
    session['selected_node'] = request.form['selected-node']
    flash(f"Выбрана нода: {session['selected_node']}", "success")
    return '', 204


# Функция отправки транзакции с помощью ноды
@app.route('/send_transaction', methods=['POST'])
def send_transaction():
    try:
        data = request.get_json()
        from_address, from_priv = data['from'].split('|')
        to_address = data['to']
        change_address = data['change'].split('|')[0]  # Берем только адрес для сдачи
        amount = int(float(data['amount']) * 1e8)  # Конвертация в сатоши

        # Получаем UTXO
        utxo_response = NodeManager.send_rpc_command(
            session.get('selected_node'),
            'getaddressutxos',
            [{"addresses": [from_address]}]
        )

        if utxo_response.get('error'):
            return jsonify(success=False, error=utxo_response['error'])

        utxos = utxo_response.get('result', [])
        if not utxos:
            return jsonify(success=False, error='Нет доступных UTXO')

        # Собираем входы и считаем баланс
        inputs = []
        total_input = 0
        for utxo in utxos:
            inputs.append({
                "txid": utxo['txid'],
                "vout": utxo['outputIndex']
            })
            total_input += utxo['satoshis']

        # Первоначальный расчет комиссии (1 выход)
        output_count = 1
        fee_rate = 10 + (len(inputs) * 148) + (output_count * 34)
        fee_rate = max(fee_rate, 227)  # Минимальная комиссия

        # Расчет остатка
        spend_change = total_input - amount - fee_rate

        # Если есть сдача, добавляем выход и корректируем комиссию
        if spend_change > 0:
            fee_rate += 34  # +34 байта за дополнительный выход
            output_count += 1

            # Повторная проверка баланса с новой комиссией
            if total_input < amount + fee_rate:
                return jsonify(success=False, error='Недостаточно средств с учетом сдачи')

            spend_change = total_input - amount - fee_rate

        # Формируем выходы
        outputs = [{to_address: round(amount / 1e8, 8)}]

        if spend_change > 0:
            outputs.append({change_address: round(spend_change / 1e8, 8)})

        # Создаем raw транзакцию
        raw_tx = NodeManager.send_rpc_command(
            session['selected_node'],
            'createrawtransaction',
            [inputs, outputs]
        )

        if raw_tx.get('error'):
            return jsonify(success=False, error=raw_tx['error'])

        # Подписываем транзакцию ТОЛЬКО ключом отправителя
        signed_tx = NodeManager.send_rpc_command(
            session['selected_node'],
            'signrawtransactionwithkey',
            [raw_tx['result'], [from_priv]]  # Только ключ отправителя
        )

        if not signed_tx.get('result', {}).get('complete'):
            return jsonify(success=False, error='Ошибка подписи транзакции')

        # Отправляем транзакцию
        send_result = NodeManager.send_rpc_command(
            session['selected_node'],
            'sendrawtransaction',
            [
                signed_tx['result']['hex'],  # Подписанная транзакция
                0,  # allowhighfees (0 = false)
                False,  # instantSend
                False  # bypasslimits
            ]
        )

        if send_result.get('error'):
            return jsonify(success=False, error=send_result['error'])

        return jsonify(success=True, txid=send_result['result'])

    except Exception as e:
        return jsonify(success=False, error=str(e))


# Страница с хешем транзакции которую создали
@app.route('/transaction_result')
def transaction_result():
    txid = request.args.get('txid')
    error = request.args.get('error')
    return render_template('transaction_result.html', txid=txid, error=error)


# Вызывается на странице create_wallet.
# Открывает страницу на которой нужно ввести свою мнемоническую фразу
@app.route('/enter_mnemonic')
def enter_mnemonic():
    return render_template('enter_mnemonic.html')

if __name__ == '__main__':
    app.run(debug=True)