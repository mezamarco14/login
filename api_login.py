from flask import Flask, redirect, url_for, session, request, abort
from msal import ConfidentialClientApplication
from dotenv import load_dotenv
from pymongo import MongoClient
from oauthlib.oauth2 import WebApplicationClient
import certifi
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
import requests
from datetime import datetime  # Importar datetime

# Inicializar la aplicación Flask y cargar el archivo .env
app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Variables de entorno para Microsoft
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORITY = os.getenv("AUTHORITY")
REDIRECT_PATH = os.getenv("REDIRECT_PATH")
SCOPE = ["User.Read"]

# Variables de entorno para Google
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL")

# Configurar el cliente MSAL
app_msal = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

# Configurar el cliente Google OAuth
google_client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Conexión a MongoDB Atlas
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(
    MONGO_URI,
    tls=True,
    tlsCAFile=certifi.where()
)
db = client['db_Upt_Usuarios']
accesos_users_collection = db['Accesos_users']

@app.route('/')
def index():
    if session.get("user"):
        return f"Hola, {session['user']['name']}! Roles: {session.get('roles', [])}"
    else:
        return '''
            <h1>Bienvenido</h1>
            <p>Inicia sesión con:</p>
            <a href="/login">Microsoft</a><br>
            <a href="/google/login">Google</a>
        '''

# Inicio de sesión con Microsoft
@app.route('/login')
def login():
    auth_url = app_msal.get_authorization_request_url(
        SCOPE,
        redirect_uri=url_for("authorized", _external=True)
    )
    return redirect(auth_url)

@app.route(REDIRECT_PATH)
def authorized():
    code = request.args.get('code')
    if not code:
        return "Error al obtener el código de autorización", 400

    result = app_msal.acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=url_for("authorized", _external=True)
    )

    if "access_token" in result:
        session["user"] = result.get("id_token_claims")
        roles = result.get('id_token_claims', {}).get('roles', [])
        session['roles'] = roles

        email = session["user"].get("preferred_username")
        name = session["user"].get("name")

        if email:
            user_data = {
                "email": email,
                "name": name,
                "status": "attempted_login",
                "roles": roles,
                "last_login": datetime.utcnow()
            }
            accesos_users_collection.update_one(
                {"email": email}, 
                {"$set": user_data}, 
                upsert=True
            )

        return redirect(url_for("index"))
    else:
        return "Error al obtener el token de acceso", 400

# Cierre de sesión
@app.route('/logout')
def logout():
    session.clear()
    return redirect(
        AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True)
    )

# Inicio de sesión con Google
@app.route('/google/login')
def google_login():
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = google_client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for("google_authorized", _external=True),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route('/google/authorized')
def google_authorized():
    code = request.args.get("code")
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = google_client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=url_for("google_authorized", _external=True),
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    google_client.parse_request_body_response(token_response.text)

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = google_client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        email = userinfo_response.json()["email"]
        name = userinfo_response.json()["name"]
        roles = ["user"]

        session["user"] = {"name": name, "email": email}
        session["roles"] = roles

        user_data = {
            "email": email,
            "name": name,
            "status": "attempted_login",
            "roles": roles,
            "last_login": datetime.utcnow()
        }
        accesos_users_collection.update_one(
            {"email": email},
            {"$set": user_data},
            upsert=True
        )

        return redirect(url_for("index"))
    else:
        return "Error: No se pudo verificar el correo electrónico de Google.", 400

# Rutas protegidas por roles
@app.route('/admin')
def admin():
    if 'roles' in session and 'admin' in session['roles']:
        return "Bienvenido al área de administración."
    else:
        abort(403)

@app.route('/user')
def user():
    if 'roles' in session and 'user' in session['roles']:
        return "Bienvenido al área de usuario."
    else:
        abort(403)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
