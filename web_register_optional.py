from flask import Flask, request, render_template_string, redirect, url_for, flash
from database import db
import re

app = Flask(__name__)
app.secret_key = 'icq_super_secret_key' 

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Регистрация ICQ</title>
    <style>
        body {
            font-family: 'Tahoma', 'Verdana', sans-serif;
            background-color: #e6f2ff;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background-color: #ffffff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            width: 350px;
            border-top: 5px solid #7cb900; /* Цвет QIP */
        }
        h2 {
            text-align: center;
            color: #333;
            margin-bottom: 20px;
        }
        .flower {
            display: block;
            margin: 0 auto 10px auto;
            width: 40px;
            height: 40px;
            background-color: #7cb900;
            border-radius: 50%;
            position: relative;
        }
        .flower::before { /* Лепесток */
            content: '';
            position: absolute;
            background-color: #cc0000; /* Красный лепесток */
            width: 12px; height: 12px;
            border-radius: 50%;
            bottom: -2px; right: 5px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-size: 14px;
            color: #666;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box; /* Чтобы padding не ломал ширину */
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #7cb900;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            font-size: 16px;
        }
        button:hover {
            background-color: #6da300;
        }
        .messages {
            margin-bottom: 15px;
            padding: 10px;
            border-radius: 4px;
            font-size: 14px;
            text-align: center;
        }
        .error { background-color: #ffe6e6; color: #cc0000; border: 1px solid #ffcccc; }
        .success { background-color: #e6fffa; color: #008000; border: 1px solid #b3ffe0; }
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 12px;
            color: #999;
        }
    </style>
</head>
<body>

<div class="container">
    <div class="flower"></div>
    <h2>Регистрация UIN</h2>
    
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="messages {{ category }}">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <form method="POST">
        <div class="form-group">
            <label for="uin">UIN (Номер ICQ):</label>
            <input type="text" id="uin" name="uin" placeholder="Например: 123456" required pattern="[0-9]+" title="Только цифры">
        </div>
        
        <div class="form-group">
            <label for="nickname">Никнейм:</label>
            <input type="text" id="nickname" name="nickname" placeholder="Ваше имя" required>
        </div>

        <div class="form-group">
            <label for="password">Пароль:</label>
            <input type="password" id="password" name="password" placeholder="Придумайте пароль" required>
        </div>

        <button type="submit">Зарегистрироваться</button>
    </form>
    
    <div class="footer">
        ICQ Server Project<br>
        Port: 5190
    </div>
</div>

</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uin = request.form.get('uin', '').strip()
        nickname = request.form.get('nickname', '').strip()
        password = request.form.get('password', '').strip()

        # Простая валидация
        if not uin.isdigit():
            flash('UIN должен состоять только из цифр!', 'error')
            return render_template_string(HTML_TEMPLATE)
        
        if len(uin) < 3 or len(uin) > 9:
            flash('UIN должен быть от 3 до 9 цифр!', 'error')
            return render_template_string(HTML_TEMPLATE)

        if not password:
            flash('Пароль не может быть пустым!', 'error')
            return render_template_string(HTML_TEMPLATE)

        # Проверка существования пользователя
        if db.user_exists(uin):
            flash(f'UIN {uin} уже занят. Выберите другой.', 'error')
        else:
            user = db.create_user(uin, password, nickname)
            if user:
                flash(f'Успешно! UIN: {uin} зарегистрирован.', 'success')
            else:
                flash('Ошибка базы данных.', 'error')

    return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    print("Web registration running on http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)
