from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from database import init_db, get_db
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')


@app.before_request
def check_user_status():
    """On every request, verify the logged-in user is still active."""
    from flask import request as req
    if 'user_id' not in session:
        return
    if req.endpoint in ('static', 'login', 'logout', 'register'):
        return
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user:
        session.clear()
        flash('Ваш акаунт було видалено адміністратором.', 'error')
        return redirect(url_for('login'))
    if user['is_blocked']:
        session.clear()
        flash('Ваш акаунт заблоковано адміністратором. Зверніться до підтримки.', 'error')
        return redirect(url_for('login'))

@app.teardown_appcontext
def close_db(error):
    from flask import g
    db = g.pop('db', None)
    if db is not None:
        db.close()

BANNED_WORDS = ['spam', 'casino', 'viagra', 'xxxxx', 'скам', 'шахрайство']

def hash_password(password):
    return generate_password_hash(password)

def filter_content(text):
    for word in BANNED_WORDS:
        pattern = re.compile(re.escape(word), re.IGNORECASE)
        text = pattern.sub('[***]', text)
    return text

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Будь ласка, увійдіть в систему.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Будь ласка, увійдіть в систему.', 'error')
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or user['role'] != 'admin':
            flash('Доступ заборонено. Тільки для адміністраторів.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


def moderator_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Будь ласка, увійдіть в систему.', 'error')
            return redirect(url_for('login'))

        db = get_db()

        user = db.execute(
            'SELECT * FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()

        if not user or user['role'] not in ('admin', 'moderator'):
            flash('Недостатньо прав.', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)

    return decorated

def get_current_user():
    if 'user_id' not in session:
        return None
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

#  Аунтифікація

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        errors = []
        if not username or len(username) < 3:
            errors.append('Ім\'я користувача має бути не менше 3 символів.')
        if not re.match(r'^[a-zA-Z0-9_а-яА-ЯіІїЇєЄ]+$', username):
            errors.append('Ім\'я користувача може містити лише літери, цифри та "_".')
        if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            errors.append('Введіть коректний email.')
        if len(password) < 6:
            errors.append('Пароль має бути не менше 6 символів.')
        if password != confirm:
            errors.append('Паролі не співпадають.')

        if not errors:
            db = get_db()
            existing = db.execute(
                'SELECT id FROM users WHERE username = ? OR email = ?', (username, email)
            ).fetchone()
            if existing:
                errors.append('Користувач з таким ім\'ям або email вже існує.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('register.html', username=username, email=email)

        db = get_db()
        db.execute(
            'INSERT INTO users (username, email, password_hash, role, is_blocked, created_at) VALUES (?,?,?,?,?,?)',
            (username, email, hash_password(password), 'user', 0, datetime.now().isoformat())
        )
        db.commit()
        flash('Реєстрація успішна! Тепер увійдіть.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute(
    'SELECT * FROM users WHERE username = ?',
    (username,)
).fetchone()

        if not user or not check_password_hash(user['password_hash'], password):
            flash('Невірне ім\'я користувача або пароль.', 'error')
            return render_template('login.html', username=username)

        if user['is_blocked']:
            return render_template('login.html', username=username, blocked=True)

        session['user_id']   = user['id']
        session['username']  = user['username']
        session['role']      = user['role']
        flash(f'Ласкаво просимо, {user["username"]}!', 'success')
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash('Ви вийшли з системи.', 'info')
    return redirect(url_for('index'))

# Пости

@app.route('/')
def index():
    db   = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 6
    offset   = (page - 1) * per_page

    total = db.execute(
        "SELECT COUNT(*) FROM posts WHERE status = 'published'"
    ).fetchone()[0]

    posts = db.execute(
        """SELECT p.*, u.username, u.role as author_role,
           (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.is_approved = 1) as comment_count
           FROM posts p JOIN users u ON p.author_id = u.id
           WHERE p.status = 'published'
           ORDER BY p.created_at DESC LIMIT ? OFFSET ?""",
        (per_page, offset)
    ).fetchall()

    total_pages = (total + per_page - 1) // per_page
    user = get_current_user()
    return render_template('index.html', posts=posts, page=page,
                           total_pages=total_pages, user=user)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    db = get_db()
    post = db.execute(
        """SELECT p.*, u.username, u.role as author_role
           FROM posts p JOIN users u ON p.author_id = u.id
           WHERE p.id = ?""", (post_id,)
    ).fetchone()

    if not post:
        flash('Пост не знайдено.', 'error')
        return redirect(url_for('index'))

    user = get_current_user()
    if post['status'] != 'published':
        if not user or (user['id'] != post['author_id'] and user['role'] != 'admin'):
            flash('Цей пост недоступний.', 'error')
            return redirect(url_for('index'))

    comments = db.execute(
        """SELECT c.*, u.username, u.role as commenter_role
           FROM comments c JOIN users u ON c.author_id = u.id
           WHERE c.post_id = ? AND c.is_approved = 1
           ORDER BY c.created_at ASC""", (post_id,)
    ).fetchall()

    db.execute('UPDATE posts SET views = views + 1 WHERE id = ?', (post_id,))
    db.commit()

    return render_template('post.html', post=post, comments=comments, user=user)

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    user = get_current_user()
    if request.method == 'POST':
        title   = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        tags    = request.form.get('tags', '').strip()
        status  = request.form.get('status', 'draft')

        if not title or len(title) < 5:
            flash('Заголовок має бути не менше 5 символів.', 'error')
            return render_template('post_form.html', user=user, title=title,
                                   content=content, tags=tags)
        if not content or len(content) < 20:
            flash('Текст має бути не менше 20 символів.', 'error')
            return render_template('post_form.html', user=user, title=title,
                                   content=content, tags=tags)

        title   = filter_content(title)
        content = filter_content(content)

        db = get_db()
        db.execute(
            'INSERT INTO posts (title, content, tags, author_id, status, created_at, updated_at, views) VALUES (?,?,?,?,?,?,?,?)',
            (title, content, tags, session['user_id'], status,
             datetime.now().isoformat(), datetime.now().isoformat(), 0)
        )
        db.commit()
        flash('Пост успішно створено!', 'success')
        return redirect(url_for('index'))

    return render_template('post_form.html', user=user)

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    db   = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    user = get_current_user()

    if not post:
        flash('Пост не знайдено.', 'error')
        return redirect(url_for('index'))

    if post['author_id'] != session['user_id'] and session.get('role') != 'admin':
        flash('Немає прав для редагування цього посту.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title   = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        tags    = request.form.get('tags', '').strip()
        status  = request.form.get('status', 'draft')

        title   = filter_content(title)
        content = filter_content(content)

        db.execute(
            'UPDATE posts SET title=?, content=?, tags=?, status=?, updated_at=? WHERE id=?',
            (title, content, tags, status, datetime.now().isoformat(), post_id)
        )
        db.commit()
        flash('Пост оновлено!', 'success')
        return redirect(url_for('view_post', post_id=post_id))

    return render_template('post_form.html', post=post, user=user, edit=True)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    db   = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if not post:
        flash('Пост не знайдено.', 'error')
        return redirect(url_for('index'))

    if post['author_id'] != session['user_id'] and session.get('role') != 'admin':
        flash('Немає прав для видалення.', 'error')
        return redirect(url_for('index'))

    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash('Пост видалено.', 'info')
    return redirect(url_for('index'))

# Коментарі

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    user    = get_current_user()
    content = request.form.get('content', '').strip()

    if not content or len(content) < 2:
        flash('Коментар не може бути порожнім.', 'error')
        return redirect(url_for('view_post', post_id=post_id))

    content    = filter_content(content)
    is_approved = 1 if user['role'] == 'admin' else 0

    db = get_db()
    db.execute(
        'INSERT INTO comments (post_id, author_id, content, created_at, is_approved) VALUES (?,?,?,?,?)',
        (post_id, session['user_id'], content, datetime.now().isoformat(), is_approved)
    )
    db.commit()

    if is_approved:
        flash('Коментар додано!', 'success')
    else:
        flash('Коментар надіслано на модерацію.', 'info')

    return redirect(url_for('view_post', post_id=post_id))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    db      = get_db()
    comment = db.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()

    if not comment:
        flash('Коментар не знайдено.', 'error')
        return redirect(url_for('index'))

    if comment['author_id'] != session['user_id'] and session.get('role') != 'admin':
        flash('Немає прав для видалення.', 'error')
        return redirect(url_for('view_post', post_id=comment['post_id']))

    post_id = comment['post_id']
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    flash('Коментар видалено.', 'info')
    return redirect(url_for('view_post', post_id=post_id))

# Профіль

@app.route('/profile/<username>')
def profile(username):
    db   = get_db()
    user = get_current_user()
    profile_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if not profile_user:
        flash('Користувача не знайдено.', 'error')
        return redirect(url_for('index'))

    posts = db.execute(
        """SELECT * FROM posts WHERE author_id = ? AND status = 'published'
           ORDER BY created_at DESC""", (profile_user['id'],)
    ).fetchall()

    return render_template('profile.html', profile_user=profile_user,
                           posts=posts, user=user)

@app.route('/my-posts')
@login_required
def my_posts():
    db    = get_db()
    user  = get_current_user()
    posts = db.execute(
        'SELECT * FROM posts WHERE author_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    return render_template('my_posts.html', posts=posts, user=user)

# Адмін

@app.route('/admin')
@admin_required
def admin_panel():
    db   = get_db()
    user = get_current_user()

    stats = {
        'users':    db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'posts':    db.execute('SELECT COUNT(*) FROM posts').fetchone()[0],
        'comments': db.execute('SELECT COUNT(*) FROM comments').fetchone()[0],
        'pending':  db.execute('SELECT COUNT(*) FROM comments WHERE is_approved=0').fetchone()[0],
        'blocked':  db.execute('SELECT COUNT(*) FROM users WHERE is_blocked=1').fetchone()[0],
        'drafts':   db.execute("SELECT COUNT(*) FROM posts WHERE status='draft'").fetchone()[0],
    }

    recent_users = db.execute(
        'SELECT * FROM users ORDER BY created_at DESC LIMIT 5'
    ).fetchall()

    pending_comments = db.execute(
        """SELECT c.*, u.username, p.title as post_title
           FROM comments c
           JOIN users u ON c.author_id = u.id
           JOIN posts p ON c.post_id = p.id
           WHERE c.is_approved = 0
           ORDER BY c.created_at DESC"""
    ).fetchall()

    return render_template('admin/panel.html', stats=stats, user=user,
                           recent_users=recent_users,
                           pending_comments=pending_comments)

@app.route('/admin/users')
@admin_required
def admin_users():
    db    = get_db()
    user  = get_current_user()
    users = db.execute(
        """SELECT u.*,
           (SELECT COUNT(*) FROM posts WHERE author_id = u.id) as post_count,
           (SELECT COUNT(*) FROM comments WHERE author_id = u.id) as comment_count
           FROM users u ORDER BY u.created_at DESC"""
    ).fetchall()
    return render_template('admin/users.html', users=users, user=user)

@app.route('/admin/user/<int:user_id>/toggle-block', methods=['POST'])
@admin_required
def toggle_block_user(user_id):
    db        = get_db()
    target    = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not target:
        flash('Користувача не знайдено.', 'error')
        return redirect(url_for('admin_users'))

    if target['role'] == 'admin':
        flash('Не можна заблокувати адміністратора.', 'error')
        return redirect(url_for('admin_users'))

    new_status = 0 if target['is_blocked'] else 1
    db.execute('UPDATE users SET is_blocked = ? WHERE id = ?', (new_status, user_id))
    db.commit()

    action = 'заблоковано' if new_status else 'розблоковано'
    flash(f'Користувача {target["username"]} {action}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/set-role', methods=['POST'])
@admin_required
def set_user_role(user_id):
    db     = get_db()
    role   = request.form.get('role')
    target = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not target or role not in ('user', 'moderator', 'admin'):
        flash('Помилка.', 'error')
        return redirect(url_for('admin_users'))

    db.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    db.commit()
    flash(f'Роль користувача {target["username"]} змінено на «{role}».', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    db     = get_db()
    target = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not target:
        flash('Користувача не знайдено.', 'error')
        return redirect(url_for('admin_users'))

    if target['role'] == 'admin':
        flash('Не можна видалити адміністратора.', 'error')
        return redirect(url_for('admin_users'))

    db.execute('DELETE FROM comments WHERE author_id = ?', (user_id,))
    db.execute('DELETE FROM posts WHERE author_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'Користувача {target["username"]} видалено.', 'info')
    return redirect(url_for('admin_users'))

@app.route('/admin/posts')
@admin_required
def admin_posts():
    db    = get_db()
    user  = get_current_user()
    posts = db.execute(
        """SELECT p.*, u.username
           FROM posts p JOIN users u ON p.author_id = u.id
           ORDER BY p.created_at DESC"""
    ).fetchall()
    return render_template('admin/posts.html', posts=posts, user=user)

@app.route('/admin/comments')
@moderator_required
def admin_comments():
    db       = get_db()
    user     = get_current_user()
    comments = db.execute(
        """SELECT c.*, u.username, p.title as post_title
           FROM comments c
           JOIN users u ON c.author_id = u.id
           JOIN posts p ON c.post_id = p.id
           ORDER BY c.is_approved ASC, c.created_at DESC"""
    ).fetchall()
    return render_template('admin/comments.html', comments=comments, user=user)

@app.route('/admin/comment/<int:comment_id>/approve', methods=['POST'])
@moderator_required
def approve_comment(comment_id):
    db = get_db()
    db.execute('UPDATE comments SET is_approved = 1 WHERE id = ?', (comment_id,))
    db.commit()
    flash('Коментар схвалено.', 'success')
    return redirect(request.referrer or url_for('admin_comments'))

@app.route('/admin/comment/<int:comment_id>/reject', methods=['POST'])
@moderator_required
def reject_comment(comment_id):
    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    flash('Коментар відхилено та видалено.', 'info')
    return redirect(request.referrer or url_for('admin_comments'))

if __name__ == '__main__':
    with app.app_context():
        init_db()

    app.run(debug=True, port=5000)
