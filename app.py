import os
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuração do MongoDB utilizando variáveis de ambiente
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)

@app.route('/add_record', methods=['POST'])
def add_record():
    data = request.json
    mongo.db.records.insert_one(data)
    return jsonify({"message": "Record added successfully!"}), 201

@app.route('/get_records', methods=['GET'])
def get_records():
    records = list(mongo.db.records.find())
    for record in records:
        record['_id'] = str(record['_id'])
    return jsonify(records), 200

@app.route('/update_record/<record_id>', methods=['PUT'])
def update_record(record_id):
    data = request.json
    mongo.db.records.update_one({'_id': ObjectId(record_id)}, {'$set': data})
    return jsonify({"message": "Record updated successfully!"}), 200

@app.route('/delete_record/<record_id>', methods=['DELETE'])
def delete_record(record_id):
    mongo.db.records.delete_one({'_id': ObjectId(record_id)})
    return jsonify({"message": "Record deleted successfully!"}), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if 'password' in data:
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        print(f"Hashed Password: {hashed_password}")  # Depuração
        user_data = {
            "username": data['username'],
            "password": hashed_password,
            "email": data['email'],
            "nome_completo": data['nome_completo'],
            "data_de_nascimento": data['data_de_nascimento']
        }
        mongo.db.users.insert_one(user_data)
        return jsonify({"message": "User registered successfully!"}), 201
    else:
        return jsonify({"message": "Password not provided!"}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = mongo.db.users.find_one({"username": data['username']})
    if user:
        print(f"Stored Password Hash: {user['password']}")  # Depuração
        print(f"Password Match: {check_password_hash(user['password'], data['password'])}")  # Depuração
    if user and check_password_hash(user['password'], data['password']):
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"message": "Invalid credentials!"}), 401

def hash_existing_passwords():
    users = mongo.db.users.find()
    for user in users:
        if not user['password'].startswith('pbkdf2:sha256'):  # Checa se a senha não está hashada
            hashed_password = generate_password_hash(user['password'], method='pbkdf2:sha256')
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'password': hashed_password}})
            print(f"Updated password for user: {user['username']}")

if __name__ == '__main__':
    hash_existing_passwords()  # Executa o script para corrigir senhas em texto simples
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)), debug=False)
