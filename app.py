from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash, make_response
from datetime import datetime, timedelta, date
import json
import os
import hashlib
import secrets
import jwt
from functools import wraps

app = Flask(__name__)
# Генерируем безопасный секретный ключ
SECRET_KEY_FILE = 'secret_key.txt'
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_urlsafe(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(app.secret_key)

# JWT настройки
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_DAYS = 1  # Access token на 1 день
REFRESH_TOKEN_EXPIRE_DAYS = 30  # Refresh token на месяц

# Файлы для хранения данных
USERS_FILE = 'users.json'
TODO_FILE = 'todos.json'
REFRESH_TOKENS_FILE = 'refresh_tokens.json'

def load_users():
    """Загружает пользователей из файла"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_users(users):
    """Сохраняет пользователей в файл"""
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def load_todos():
    """Загружает задачи из файла"""
    if os.path.exists(TODO_FILE):
        with open(TODO_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_todos(todos):
    """Сохражает задачи в файл"""
    with open(TODO_FILE, 'w', encoding='utf-8') as f:
        json.dump(todos, f, ensure_ascii=False, indent=2)

def load_refresh_tokens():
    """Загружает refresh токены из файла"""
    if os.path.exists(REFRESH_TOKENS_FILE):
        with open(REFRESH_TOKENS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_refresh_tokens(tokens):
    """Сохраняет refresh токены в файл"""
    with open(REFRESH_TOKENS_FILE, 'w', encoding='utf-8') as f:
        json.dump(tokens, f, ensure_ascii=False, indent=2)

def hash_password(password):
    """Хеширует пароль"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_access_token(user_id, username):
    """Генерирует access token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS),
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    return jwt.encode(payload, app.secret_key, algorithm=JWT_ALGORITHM)

def generate_refresh_token(user_id, username):
    """Генерирует refresh token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        'iat': datetime.utcnow(),
        'type': 'refresh'
    }
    token = jwt.encode(payload, app.secret_key, algorithm=JWT_ALGORITHM)
    
    # Сохраняем refresh token
    tokens = load_refresh_tokens()
    tokens[token] = {
        'user_id': user_id,
        'username': username,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'expires_at': (datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).strftime('%Y-%m-%d %H:%M:%S')
    }
    save_refresh_tokens(tokens)
    
    return token

def verify_token(token, token_type='access'):
    """Проверяет и декодирует токен"""
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=[JWT_ALGORITHM])
        if payload.get('type') != token_type:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_user_from_token():
    """Получает пользователя из токена в заголовке или сессии"""
    # Проверяем токен в заголовке (для API)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        payload = verify_token(token, 'access')
        if payload:
            return payload.get('user_id'), payload.get('username')
    
    # Проверяем токен в cookies
    access_token = request.cookies.get('access_token')
    if access_token:
        payload = verify_token(access_token, 'access')
        if payload:
            return payload.get('user_id'), payload.get('username')
        # Если access token истек, пытаемся обновить через refresh token
        refresh_token = request.cookies.get('refresh_token')
        if refresh_token:
            refresh_payload = verify_token(refresh_token, 'refresh')
            if refresh_payload:
                # Проверяем наличие в хранилище
                tokens = load_refresh_tokens()
                if refresh_token in tokens:
                    user_id = refresh_payload.get('user_id')
                    username = refresh_payload.get('username')
                    # Генерируем новый access token
                    new_access_token = generate_access_token(user_id, username)
                    # Сохраняем в request для установки cookie
                    request._new_access_token = new_access_token
                    return user_id, username
    
    # Fallback на сессию (для веб-интерфейса)
    if 'user_id' in session:
        return session.get('user_id'), session.get('username')
    
    return None, None

def login_required(f):
    """Декоратор для защиты маршрутов"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id, username = get_user_from_token()
        if not user_id:
            # Для API запросов возвращаем JSON, для веб - редирект
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        # Сохраняем в request для использования в функции
        request.user_id = user_id
        request.username = username
        
        # Выполняем функцию
        response = f(*args, **kwargs)
        
        # Если был сгенерирован новый access token, устанавливаем его в cookie
        if hasattr(request, '_new_access_token'):
            if isinstance(response, tuple):
                # Если response это tuple (response, status_code)
                resp = make_response(response[0])
                if len(response) > 1:
                    resp.status_code = response[1]
                response = resp
            elif not hasattr(response, 'set_cookie'):
                response = make_response(response)
            response.set_cookie('access_token', request._new_access_token,
                              max_age=ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                              httponly=True, samesite='Lax', secure=False)
        
        return response
    return decorated_function

def token_required(f):
    """Декоратор для защиты API маршрутов (только токены)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id, username = get_user_from_token()
        if not user_id:
            return jsonify({'error': 'Unauthorized', 'message': 'Invalid or expired token'}), 401
        request.user_id = user_id
        request.username = username
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    """Главная страница"""
    user_id = request.user_id
    filter_type = request.args.get('filter', 'all')
    todos = load_todos()
    user_todos = [todo for todo in todos if todo.get('user_id') == user_id]
    
    # Фильтрация задач
    today = date.today()
    year_from_now = today + timedelta(days=365)
    
    if filter_type == 'today':
        filtered_todos = []
        for todo in user_todos:
            # Проверяем сохраненную категорию или определяем по дате
            todo_category = todo.get('category')
            if todo_category == 'today':
                filtered_todos.append(todo)
            elif not todo_category:
                # Если категория не сохранена, определяем по дате
                due_date_str = todo.get('due_date')
                if due_date_str:
                    try:
                        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                        if due_date == today:
                            filtered_todos.append(todo)
                    except:
                        pass
    elif filter_type == 'anytime':
        filtered_todos = []
        for todo in user_todos:
            todo_category = todo.get('category')
            if todo_category == 'anytime':
                filtered_todos.append(todo)
            elif not todo_category and not todo.get('due_date'):
                # Если категория не сохранена и нет даты
                filtered_todos.append(todo)
    elif filter_type == 'year':
        filtered_todos = []
        for todo in user_todos:
            todo_category = todo.get('category')
            if todo_category == 'year':
                filtered_todos.append(todo)
            elif not todo_category:
                # Если категория не сохранена, определяем по дате
                due_date_str = todo.get('due_date')
                if due_date_str:
                    try:
                        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                        if today <= due_date <= year_from_now:
                            filtered_todos.append(todo)
                    except:
                        pass
    else:
        filtered_todos = user_todos
    
    username = request.username or 'Пользователь'
    today_str = today.strftime('%Y-%m-%d')
    return render_template('index.html', todos=filtered_todos, all_todos=user_todos, 
                         username=username, current_filter=filter_type, today_str=today_str)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        users = load_users()
        hashed_password = hash_password(password)
        
        for user in users:
            if user['username'] == username and user['password'] == hashed_password:
                # Создаем токены
                access_token = generate_access_token(user['id'], user['username'])
                refresh_token = generate_refresh_token(user['id'], user['username'])
                
                # Сохраняем в сессию для веб-интерфейса
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                # Устанавливаем токены в cookies
                response = make_response(redirect(url_for('index')))
                response.set_cookie('access_token', access_token, 
                                  max_age=ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                                  httponly=True, samesite='Lax', secure=False)
                response.set_cookie('refresh_token', refresh_token,
                                  max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                                  httponly=True, samesite='Lax', secure=False)
                return response
        
        flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    """Регистрация нового пользователя"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not username or not password:
        flash('Заполните все поля', 'error')
        return redirect(url_for('login'))
    
    if password != confirm_password:
        flash('Пароли не совпадают', 'error')
        return redirect(url_for('login'))
    
    if len(password) < 4:
        flash('Пароль должен содержать минимум 4 символа', 'error')
        return redirect(url_for('login'))
    
    users = load_users()
    
    # Проверка на существующего пользователя
    for user in users:
        if user['username'] == username:
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('login'))
    
    # Создание нового пользователя
    new_user = {
        'id': len(users) + 1,
        'username': username,
        'password': hash_password(password),
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    users.append(new_user)
    save_users(users)
    
    # Создаем токены для нового пользователя
    access_token = generate_access_token(new_user['id'], new_user['username'])
    refresh_token = generate_refresh_token(new_user['id'], new_user['username'])
    
    # Сохраняем в сессию
    session['user_id'] = new_user['id']
    session['username'] = new_user['username']
    
    # Устанавливаем токены в cookies
    response = make_response(redirect(url_for('index')))
    response.set_cookie('access_token', access_token,
                      max_age=ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                      httponly=True, samesite='Lax', secure=False)
    response.set_cookie('refresh_token', refresh_token,
                      max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                      httponly=True, samesite='Lax', secure=False)
    flash('Регистрация успешна!', 'success')
    return response

@app.route('/logout')
def logout():
    """Выход из системы"""
    # Удаляем refresh token из хранилища
    refresh_token = request.cookies.get('refresh_token')
    if refresh_token:
        tokens = load_refresh_tokens()
        if refresh_token in tokens:
            del tokens[refresh_token]
            save_refresh_tokens(tokens)
    
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    return response

@app.route('/add', methods=['POST'])
@login_required
def add_todo():
    """Добавляет новую задачу"""
    user_id = request.user_id
    todos = load_todos()
    text = request.form.get('text', '').strip()
    due_date = request.form.get('due_date', '').strip()
    category = request.form.get('category', '').strip()
    
    # Определяем категорию
    section = 'anytime'  # По умолчанию
    
    # Если категория выбрана вручную, используем её
    if category and category in ['today', 'anytime', 'year']:
        section = category
    # Иначе автоматически определяем по дате
    elif due_date:
        try:
            due_date_obj = datetime.strptime(due_date, '%Y-%m-%d').date()
            today = date.today()
            year_from_now = today + timedelta(days=365)
            
            if due_date_obj == today:
                section = 'today'
            elif today <= due_date_obj <= year_from_now:
                section = 'year'
            else:
                section = 'anytime'
        except:
            due_date = None
            section = 'anytime'
    else:
        section = 'anytime'
    
    if text:
        # Генерируем уникальный ID
        max_id = max([todo.get('id', 0) for todo in todos], default=0)
        new_todo = {
            'id': max_id + 1,
            'user_id': user_id,
            'text': text,
            'completed': False,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'due_date': due_date if due_date else None,
            'category': section  # Сохраняем категорию
        }
        todos.append(new_todo)
        save_todos(todos)
    
    # Перенаправляем на соответствующий раздел
    filter_param = '?filter=' + section if section != 'all' else ''
    return redirect(url_for('index') + filter_param)

@app.route('/toggle/<int:todo_id>')
@login_required
def toggle_todo(todo_id):
    """Переключает статус выполнения задачи"""
    user_id = request.user_id
    todos = load_todos()
    for todo in todos:
        if todo['id'] == todo_id and todo.get('user_id') == user_id:
            todo['completed'] = not todo['completed']
            break
    save_todos(todos)
    return redirect(url_for('index'))

@app.route('/delete/<int:todo_id>')
@login_required
def delete_todo(todo_id):
    """Удаляет задачу"""
    user_id = request.user_id
    todos = load_todos()
    todos = [todo for todo in todos if not (todo['id'] == todo_id and todo.get('user_id') == user_id)]
    save_todos(todos)
    return redirect(url_for('index'))

@app.route('/api/todos', methods=['GET'])
@token_required
def api_get_todos():
    """API endpoint для получения всех задач пользователя"""
    user_id = request.user_id
    todos = load_todos()
    # Строгая проверка приватности - только свои задачи
    user_todos = [todo for todo in todos if todo.get('user_id') == user_id]
    return jsonify(user_todos)

@app.route('/api/refresh', methods=['POST'])
def refresh_token():
    """Обновляет access token используя refresh token"""
    refresh_token = request.cookies.get('refresh_token') or request.json.get('refresh_token') if request.is_json else None
    
    if not refresh_token:
        return jsonify({'error': 'Refresh token required'}), 400
    
    # Проверяем токен
    payload = verify_token(refresh_token, 'refresh')
    if not payload:
        return jsonify({'error': 'Invalid or expired refresh token'}), 401
    
    # Проверяем наличие токена в хранилище
    tokens = load_refresh_tokens()
    if refresh_token not in tokens:
        return jsonify({'error': 'Refresh token not found'}), 401
    
    user_id = payload.get('user_id')
    username = payload.get('username')
    
    # Генерируем новый access token
    new_access_token = generate_access_token(user_id, username)
    
    response = jsonify({'access_token': new_access_token, 'message': 'Token refreshed'})
    response.set_cookie('access_token', new_access_token,
                      max_age=ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                      httponly=True, samesite='Lax', secure=False)
    return response

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API endpoint для входа (возвращает токены)"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    users = load_users()
    hashed_password = hash_password(password)
    
    for user in users:
        if user['username'] == username and user['password'] == hashed_password:
            access_token = generate_access_token(user['id'], user['username'])
            refresh_token = generate_refresh_token(user['id'], user['username'])
            
            return jsonify({
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': ACCESS_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
            }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5432))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug, host='0.0.0.0', port=port)

