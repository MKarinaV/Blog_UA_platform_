import sqlite3
from flask import g
import os

DATABASE = 'blog.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'user',
            is_blocked    INTEGER NOT NULL DEFAULT 0,
            bio           TEXT,
            created_at    TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            title      TEXT    NOT NULL,
            content    TEXT    NOT NULL,
            tags       TEXT,
            author_id  INTEGER NOT NULL REFERENCES users(id),
            status     TEXT    NOT NULL DEFAULT 'draft',
            views      INTEGER NOT NULL DEFAULT 0,
            created_at TEXT    NOT NULL,
            updated_at TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS comments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id     INTEGER NOT NULL REFERENCES posts(id),
            author_id   INTEGER NOT NULL REFERENCES users(id),
            content     TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            is_approved INTEGER NOT NULL DEFAULT 0
        );
    ''')

    # Seed admin user
    existing = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        from werkzeug.security import generate_password_hash
        from datetime import datetime
        db.execute(
            "INSERT INTO users (username, email, password_hash, role, is_blocked, created_at) VALUES (?,?,?,?,?,?)",
            ('admin',
             'admin@blog.com',
             generate_password_hash('admin123'),
             'admin',
             0,
             datetime.now().isoformat()
             )
        )
        # Demo posts
        db.execute(
            "INSERT INTO posts (title, content, tags, author_id, status, views, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            ('Ласкаво просимо до BlogUA!',
             'Це перший пост нашої блогової платформи. Тут ви можете ділитися своїми думками, ідеями та досвідом. Реєструйтесь та починайте писати вже сьогодні!\n\nПлатформа підтримує: публікацію постів, коментування, систему ролей та модерацію контенту.',
             'ласкаво просимо, блог, старт', 1, 'published', 0,
             datetime.now().isoformat(), datetime.now().isoformat())
        )
        db.execute(
            "INSERT INTO posts (title, content, tags, author_id, status, views, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            ('Як писати гарні пости?',
             'Хороший пост має чіткий заголовок, структурований контент та конкретний висновок. Пишіть просто і зрозуміло. Використовуйте абзаци для поділу думок.\n\nПам\'ятайте: якість важливіша за кількість. Один добре написаний пост принесе більше користі, ніж десять поверхневих.',
             'поради, написання, блогінг', 1, 'published', 0,
             datetime.now().isoformat(), datetime.now().isoformat())
        )
        db.commit()
    db.close()
