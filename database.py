# database.py - SQLite хранилище пользователей

import sqlite3
import hashlib
import sys
from dataclasses import dataclass
from typing import Optional, List
from threading import Lock
from contextlib import contextmanager


@dataclass
class User:
    """Модель пользователя"""
    uin: str
    password_hash: str
    nickname: str = ""
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    gender: int = 0
    status_text: str = ""
    
    @property
    def contacts(self) -> List[str]:
        """Получает контакты из БД"""
        return db.get_contacts(self.uin)
    
    def check_password(self, password: str) -> bool:
        """Проверяет пароль"""
        return self.password_hash == self.hash_password(password)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Хеширует пароль"""
        salt = "icq_server_salt_2024"
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


class Database:
    """SQLite база данных"""
    
    def __init__(self, db_path: str = "icq_server.db"):
        self.db_path = db_path
        self.lock = Lock()
        self._init_db()
    
    @contextmanager
    def get_connection(self):
        """Контекстный менеджер для соединения"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[DB ERROR] {e}")
            raise
        finally:
            conn.close()
    
    def _init_db(self):
        """Инициализирует структуру БД"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    uin TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    nickname TEXT DEFAULT '',
                    email TEXT DEFAULT '',
                    first_name TEXT DEFAULT '',
                    last_name TEXT DEFAULT '',
                    gender INTEGER DEFAULT 0,
                    status_text TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_uin TEXT NOT NULL,
                    contact_uin TEXT NOT NULL,
                    nickname TEXT DEFAULT '',
                    group_name TEXT DEFAULT 'General',
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(owner_uin, contact_uin)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS offline_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_uin TEXT NOT NULL,
                    to_uin TEXT NOT NULL,
                    message TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    delivered INTEGER DEFAULT 0
                )
            ''')
    
    def get_user(self, uin: str) -> Optional[User]:
        """Получает пользователя по UIN"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE uin = ?', (uin,))
            row = cursor.fetchone()
            
            if row:
                return User(
                    uin=row['uin'],
                    password_hash=row['password_hash'],
                    nickname=row['nickname'] or f"User{row['uin']}",
                    email=row['email'] or f"{row['uin']}@icq.com",
                    first_name=row['first_name'] or '',
                    last_name=row['last_name'] or '',
                    gender=row['gender'] or 0,
                    status_text=row['status_text'] or ''
                )
            return None
    
    def user_exists(self, uin: str) -> bool:
        """Проверяет существование пользователя"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM users WHERE uin = ?', (uin,))
            return cursor.fetchone() is not None
    
    def create_user(self, uin: str, password: str, nickname: str = "") -> Optional[User]:
        """Создаёт нового пользователя"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Проверяем что UIN не занят
            cursor.execute('SELECT 1 FROM users WHERE uin = ?', (uin,))
            if cursor.fetchone():
                print(f"[DB] User {uin} already exists")
                return None
            
            password_hash = User.hash_password(password)
            nick = nickname if nickname else f"User{uin}"
            email = f"{uin}@icq.com"
            
            cursor.execute('''
                INSERT INTO users (uin, password_hash, nickname, email)
                VALUES (?, ?, ?, ?)
            ''', (uin, password_hash, nick, email))
            
            print(f"[DB] Created user: {uin}")
            
        # Получаем созданного пользователя
        return self.get_user(uin)
    
    def authenticate(self, uin: str, password: str) -> Optional[User]:
        """Аутентификация пользователя"""
        user = self.get_user(uin)
        if user and user.check_password(password):
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE uin = ?',
                    (uin,)
                )
            return user
        return None
    
    def change_password(self, uin: str, new_password: str) -> bool:
        """Меняет пароль пользователя"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            password_hash = User.hash_password(new_password)
            cursor.execute(
                'UPDATE users SET password_hash = ? WHERE uin = ?',
                (password_hash, uin)
            )
            return cursor.rowcount > 0
    
    def delete_user(self, uin: str) -> bool:
        """Удаляет пользователя"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM contacts WHERE owner_uin = ? OR contact_uin = ?', (uin, uin))
            cursor.execute('DELETE FROM offline_messages WHERE from_uin = ? OR to_uin = ?', (uin, uin))
            cursor.execute('DELETE FROM users WHERE uin = ?', (uin,))
            return cursor.rowcount > 0
    
    def list_users(self) -> List[User]:
        """Возвращает список всех пользователей"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users ORDER BY uin')
            
            users = []
            for row in cursor.fetchall():
                users.append(User(
                    uin=row['uin'],
                    password_hash=row['password_hash'],
                    nickname=row['nickname'] or f"User{row['uin']}",
                    email=row['email'] or '',
                    first_name=row['first_name'] or '',
                    last_name=row['last_name'] or '',
                    gender=row['gender'] or 0,
                    status_text=row['status_text'] or ''
                ))
            return users
    
    def get_contacts(self, uin: str) -> List[str]:
        """Получает список контактов пользователя"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT contact_uin FROM contacts WHERE owner_uin = ?',
                (uin,)
            )
            return [row['contact_uin'] for row in cursor.fetchall()]
    
    def add_contact(self, owner_uin: str, contact_uin: str) -> bool:
        """Добавляет контакт"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO contacts (owner_uin, contact_uin)
                    VALUES (?, ?)
                ''', (owner_uin, contact_uin))
                return cursor.rowcount > 0
            except sqlite3.Error as e:
                print(f"[DB ERROR] {e}")
                return False
    
    def remove_contact(self, owner_uin: str, contact_uin: str) -> bool:
        """Удаляет контакт"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM contacts WHERE owner_uin = ? AND contact_uin = ?',
                (owner_uin, contact_uin)
            )
            return cursor.rowcount > 0
    
    def save_offline_message(self, from_uin: str, to_uin: str, message: str) -> int:
        """Сохраняет offline сообщение"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO offline_messages (from_uin, to_uin, message)
                VALUES (?, ?, ?)
            ''', (from_uin, to_uin, message))
            return cursor.lastrowid
    
    def get_offline_messages(self, uin: str) -> List[dict]:
        """Получает offline сообщения для пользователя"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, from_uin, message, sent_at 
                FROM offline_messages 
                WHERE to_uin = ? AND delivered = 0
                ORDER BY sent_at
            ''', (uin,))
            return [dict(row) for row in cursor.fetchall()]
    
    def mark_offline_delivered(self, message_ids: List[int]):
        """Помечает сообщения как доставленные"""
        if not message_ids:
            return
        with self.get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ','.join('?' * len(message_ids))
            cursor.execute(
                f'UPDATE offline_messages SET delivered = 1 WHERE id IN ({placeholders})',
                message_ids
            )
    
    def get_stats(self) -> dict:
        """Возвращает статистику БД"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM contacts')
            contact_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM offline_messages WHERE delivered = 0')
            pending_messages = cursor.fetchone()[0]
            
            return {
                'users': user_count,
                'contacts': contact_count,
                'pending_offline_messages': pending_messages
            }


# Глобальный экземпляр БД
db = Database()


# ==================== CLI ====================

def main():
    """Командная строка для управления пользователями"""
    
    print(f"[DEBUG] Arguments: {sys.argv}")
    print(f"[DEBUG] Database path: {db.db_path}")
    
    if len(sys.argv) < 2:
        print_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == 'add':
        if len(sys.argv) < 4:
            print("Usage: python database.py add <uin> <password> [nickname]")
            return
        
        uin = sys.argv[2]
        password = sys.argv[3]
        nickname = sys.argv[4] if len(sys.argv) > 4 else ""
        
        print(f"[DEBUG] Creating user: uin={uin}, password={password}, nickname={nickname}")
        
        user = db.create_user(uin, password, nickname)
        if user:
            print(f"User created: UIN={uin}, Nickname={user.nickname}")
        else:
            print(f"Failed to create user")
    
    elif command == 'delete':
        if len(sys.argv) < 3:
            print("Usage: python database.py delete <uin>")
            return
        
        uin = sys.argv[2]
        if db.delete_user(uin):
            print(f"User {uin} deleted")
        else:
            print(f"User {uin} not found")
    
    elif command == 'list':
        users = db.list_users()
        print(f"\n[DEBUG] Found {len(users)} users in database")
        
        if users:
            print(f"\n{'UIN':<12} {'Nickname':<20} {'Email':<30}")
            print("-" * 62)
            for user in users:
                print(f"{user.uin:<12} {user.nickname:<20} {user.email:<30}")
            print(f"\nTotal: {len(users)} users")
        else:
            print("No users found")
    
    elif command == 'passwd':
        if len(sys.argv) < 4:
            print("Usage: python database.py passwd <uin> <new_password>")
            return
        
        uin = sys.argv[2]
        password = sys.argv[3]
        
        if db.change_password(uin, password):
            print(f"Password changed for {uin}")
        else:
            print(f"User {uin} not found")
    
    elif command == 'info':
        if len(sys.argv) < 3:
            print("Usage: python database.py info <uin>")
            return
        
        uin = sys.argv[2]
        user = db.get_user(uin)
        
        if user:
            print(f"\n{'='*40}")
            print(f"UIN:        {user.uin}")
            print(f"Nickname:   {user.nickname}")
            print(f"Email:      {user.email}")
            print(f"First Name: {user.first_name}")
            print(f"Last Name:  {user.last_name}")
            print(f"{'='*40}")
            
            contacts = db.get_contacts(uin)
            if contacts:
                print(f"\nContacts ({len(contacts)}):")
                for c in contacts:
                    print(f"  - {c}")
        else:
            print(f"User {uin} not found")
    
    elif command == 'addcontact':
        if len(sys.argv) < 4:
            print("Usage: python database.py addcontact <owner_uin> <contact_uin>")
            return
        
        owner = sys.argv[2]
        contact = sys.argv[3]
        
        if db.add_contact(owner, contact):
            print(f"Contact added: {owner} -> {contact}")
        else:
            print(f"Failed to add contact (maybe already exists?)")
    
    elif command == 'stats':
        stats = db.get_stats()
        print(f"\n Database Statistics:")
        print(f"   Database file: {db.db_path}")
        print(f"   Users:         {stats['users']}")
        print(f"   Contacts:      {stats['contacts']}")
        print(f"   Pending Msgs:  {stats['pending_offline_messages']}")
    
    elif command == 'init':
        print("Creating test users...")
        
        u1 = db.create_user("111111", "password", "Alice")
        u2 = db.create_user("222222", "password", "Bob")
        u3 = db.create_user("333333", "password", "Charlie")
        
        if u1 and u2 and u3:
            db.add_contact("111111", "222222")
            db.add_contact("111111", "333333")
            db.add_contact("222222", "111111")
            db.add_contact("222222", "333333")
            db.add_contact("333333", "111111")
            db.add_contact("333333", "222222")
            
            print("Test users created:")
            print("   111111 / password (Alice)")
            print("   222222 / password (Bob)")
            print("   333333 / password (Charlie)")
        else:
            print("Some users may already exist")
    
    elif command == 'test':
        # Тестовая команда для проверки БД
        print(f"Testing database: {db.db_path}")
        
        # Пробуем создать пользователя напрямую
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            print(f"Tables: {[t[0] for t in tables]}")
            
            cursor.execute("SELECT * FROM users")
            rows = cursor.fetchall()
            print(f"Users in DB: {len(rows)}")
            for row in rows:
                print(f"  - {dict(row)}")
    
    else:
        print_help()


def print_help():
    print("""
ICQ Server Database Management

Usage: python database.py <command> [args]

Commands:
  add <uin> <password> [nickname]  - Create new user
  delete <uin>                     - Delete user
  list                             - List all users
  passwd <uin> <new_password>      - Change password
  info <uin>                       - Show user info
  addcontact <owner> <contact>     - Add contact
  stats                            - Show database statistics
  init                             - Create test users
  test                             - Test database connection

Examples:
  python database.py init
  python database.py add 123456 mypassword "John Doe"
  python database.py list
""")


if __name__ == '__main__':
    main()