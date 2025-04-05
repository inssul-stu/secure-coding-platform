import sqlite3
import uuid
from flask_wtf.csrf import generate_csrf
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect #CSRF 보호호
from datetime import datetime, timedelta
import re
import time

last_message_time = {}  # user_id: timestamp
FORBIDDEN_XSS_PATTERNS = [
    r'<\s*script',         # <script
    r'<\s*img',            # <img
    r'onerror\s*=',        # onerror=
    r'onload\s*=',         # onload=
    r'javascript:',        # javascript: 링크
    r'<\s*svg',            # <svg
    r'<\s*iframe',         # <iframe
]


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
csrf = CSRFProtect(app)
DATABASE = 'market.db'
socketio = SocketIO(app)
user_sid_map = {}  # username -> socket id
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.permanent_session_lifetime = timedelta(minutes=30)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                points INTEGER DEFAULT 100000,
                blocked INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                blocked INTEGER DEFAULT 0
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 관리자 계정 존재 여부 확인
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        admin = cursor.fetchone()
        
        if admin is None:
            admin_id = str(uuid.uuid4())
            admin_password = generate_password_hash('admin1234')  # 비밀번호는 원하는 것으로 설정
            cursor.execute("""
                INSERT INTO user (id, username, password, is_admin)
                VALUES (?, ?, ?, 1)
            """, (admin_id, 'admin', admin_password))
            print('관리자 계정이 생성되었습니다. (아이디: admin / 비밀번호: admin1234)')
        # 채팅 로그
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_log (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                recipient TEXT,
                message TEXT NOT NULL,
                type TEXT NOT NULL,  -- 'public' 또는 'private'
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 관리자 감사용
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_id TEXT,
                description TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

def contains_xss(text):
    """XSS 의심 패턴이 포함되어 있으면 True"""
    for pattern in FORBIDDEN_XSS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        # 실패 횟수 및 지연 체크
        now = datetime.utcnow()
        failure_count = session.get('login_failures', 0)
        last_failure = session.get('last_failure_time')

        if failure_count >= 5 and last_failure:
            last_failure_time = datetime.strptime(last_failure, "%Y-%m-%d %H:%M:%S")
            delay_end = last_failure_time + timedelta(seconds=30)
            if now < delay_end:
                remaining = int((delay_end - now).total_seconds())
                flash(f"로그인 시도 제한: {remaining}초 후 다시 시도해주세요.")
                return redirect(url_for('login'))

        # 로그인 성공 처리
        if user and check_password_hash(user['password'], password):
            if user['blocked']:
                flash('계정이 차단되었습니다.')
                return redirect(url_for('login'))

            # 로그인 성공 → 실패 기록 초기화
            session.pop('login_failures', None)
            session.pop('last_failure_time', None)
            session['user_id'] = user['id']
            session.permanent = True
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))

        # 로그인 실패 처리
        session['login_failures'] = failure_count + 1
        session['last_failure_time'] = now.strftime("%Y-%m-%d %H:%M:%S")
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            if user['is_admin'] != 1:
                flash('관리자 권한이 없습니다.')
                return redirect(url_for('admin_login'))
            session['user_id'] = user['id']
            session.permanent = True
            flash('관리자 로그인 성공!')
            return redirect(url_for('admin_panel'))
        else:
            flash('아이디 또는 비밀번호가 잘못되었습니다.')
            return redirect(url_for('admin_login'))

   
    return render_template('admin_login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product WHERE blocked = 0")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 사용자 검색 처리 (GET 파라미터 q 사용)
    query = request.args.get('q')
    results = []
    if query:
        cursor.execute("SELECT username, bio FROM user WHERE username LIKE ?", (f"%{query}%",))
        results = cursor.fetchall()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        password = request.form.get('password', '')

        # 비밀번호 재확인
        if not check_password_hash(current_user['password'], password):
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('profile'))

        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))

        if contains_xss(bio):
            flash('입력 내용에 금지된 코드가 포함되어 있습니다.')
            return redirect(url_for('report'))
        
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user, results=results)

# 상품 등록
@app.route('/new_product', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()

        if not title or len(title) > 50:
            flash('제목은 1~50자 이내여야 합니다.')
            return redirect(url_for('new_product'))

        if not description or len(description) > 300:
            flash('설명은 300자 이내로 작성해주세요.')
            return redirect(url_for('new_product'))

        try:
            price = int(request.form['price'])
            if price <= 0:
                raise ValueError
        except ValueError:
            flash('가격은 숫자 형식이며, 0보다 큰 숫자여야 합니다.')
            return redirect(url_for('new_product'))
        
        if contains_xss(title) or contains_xss(description):
            flash('입력 내용에 금지된 코드가 포함되어 있습니다.')
            return redirect(url_for('report'))


        # 등록
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO product (id, title, description, price, seller_id)
            VALUES (?, ?, ?, ?, ?)
        """, (product_id, title, description, price_value, session['user_id']))
        db.commit()

        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_username = request.form['target_id']
        reason = request.form['reason'].strip()
        today = datetime.now().date()

        # 사용자 정보 조회
        cursor.execute("SELECT * FROM user WHERE username = ?", (target_username,))
        target_user = cursor.fetchone()

        if not target_user:
            flash('해당 사용자명을 찾을 수 없습니다.')
            return redirect(url_for('report'))

        actual_id = target_user['id']

        # --- 동일 대상 중복 신고 방지 ---
        cursor.execute("""
            SELECT COUNT(*) AS cnt FROM report
            WHERE reporter_id = ? AND target_id = ?
        """, (session['user_id'], actual_id))
        duplicate_check = cursor.fetchone()['cnt']

        if duplicate_check >= 1:
            flash('이미 해당 사용자를 신고한 이력이 있습니다.')
            return redirect(url_for('report'))

        # --- 일일 신고 횟수 제한 ---
        # timestamp 컬럼이 없는 경우에도 실행 가능하게 처리
        try:
            cursor.execute("""
                SELECT COUNT(*) as count FROM report
                WHERE reporter_id = ?
                AND datetime(timestamp) >= datetime(?)
            """, (session['user_id'], today.isoformat()))
            if cursor.fetchone()['count'] >= 5:
                flash('하루 최대 신고 가능 횟수를 초과했습니다.')
                return redirect(url_for('report'))
        except sqlite3.OperationalError:
            pass  # timestamp 컬럼 없으면 제한 없이 넘어감

        # 자기 자신 신고 금지
        if actual_id == session['user_id']:
            flash('자기 자신을 신고할 수 없습니다.')
            return redirect(url_for('report'))

        # 관리자 신고 금지
        if target_user['is_admin'] == 1:
            flash('관리자는 신고할 수 없습니다.')
            return redirect(url_for('report'))

        # 공백 방지
        if not reason:
            flash('신고 사유를 입력해주세요.')
            return redirect(url_for('report'))

        # 길이 제한
        if len(reason) > 300:
            flash('신고 사유는 300자 이내로 작성해주세요.')
            return redirect(url_for('report'))

        # XSS 방어
        if contains_xss(reason):
            flash('입력 내용에 금지된 코드가 포함되어 있습니다.')
            return redirect(url_for('report'))

        # 신고 저장
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], actual_id, reason)
        )

        # 신고 로그 저장
        with open('report_audit.log', 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now()}] 신고자: {session['user_id']} → 대상: {actual_id}, 사유: {reason}\n")

        # 신고 2회 이상이면 자동 차단
        cursor.execute("SELECT COUNT(*) as count FROM report WHERE target_id = ?", (actual_id,))
        report_count = cursor.fetchone()['count']

        if report_count >= 2:
            cursor.execute("UPDATE user SET blocked = 1 WHERE id = ?", (actual_id,))
            cursor.execute("UPDATE product SET blocked = 1 WHERE seller_id = ?", (actual_id,))
            flash('2회 이상 신고되어 자동으로 차단되었습니다.')
        else:
            flash('신고가 접수되었습니다.')

        # 감사 로그 기록
        log_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO audit_log (id, user_id, action, target_id, description)
            VALUES (?, ?, 'report', ?, ?)
        """, (log_id, session['user_id'], actual_id, reason))

        db.commit()
        return redirect(url_for('dashboard'))

    return render_template('report.html')
# 상품 수정
@app.route('/product/<product_id>/edit', methods=['POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    price = request.form.get('price', '').strip()

    try:
        price_value = int(price)
        if price_value <= 0:
            raise ValueError
    except ValueError:
        flash('가격은 숫자이며 0보다 커야 합니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    if contains_xss(title) or contains_xss(description):
        flash('입력값에 금지된 코드가 포함되어 있습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    db = get_db()
    cursor = db.cursor()

    # 권한 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product or product['seller_id'] != session['user_id']:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    # 수정 실행
    cursor.execute("""
        UPDATE product SET title = ?, description = ?, price = ?
        WHERE id = ?
    """, (title, description, price_value, product_id))
    db.commit()

    flash('상품 정보가 수정되었습니다.')
    return redirect(url_for('view_product', product_id=product_id))

# 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 가져오기
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    # 상품이 없거나, 삭제 권한 없는 경우
    if not product or product['seller_id'] != session['user_id']:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    # 삭제 실행
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

ALLOWED_PATTERN = re.compile(r'^[\w\s가-힣.,!?@#$%^&*()\-+=~:;\'\"<>/\[\]{}|\\]*$')
# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
# send_message: 전체 채팅
@socketio.on('send_message')
def handle_send_message(data):
    message = data.get('message', '').strip()
    username = data.get('username', '').strip()

    # 메시지 속도 제한: 1.5초 이내 재전송 금지
    now = time.time()
    last_time = last_message_time.get(username, 0)
    if now - last_time < 1.5:
        emit('message', {
            'username': 'System',
            'message': '메시지를 너무 빠르게 보냈습니다. 잠시 후 다시 시도해주세요.'
        }, to=request.sid)
        return
    last_message_time[username] = now

    # 메시지 길이 제한
    if not message or len(message) > 200:
        emit('message',{ 
             'username': 'System',
             'message': '메시지는 200자 이내로 입력해주세요.'
        }, to=request.sid)
        return

    # 허용 문자 패턴 확인
    if not ALLOWED_PATTERN.match(message):
        emit('message', {
            'username': 'System',
            'message': '허용되지 않은 문자가 포함되어 있습니다.'
        }, to=request.sid)
        return

    # XSS 금지 태그 필터
    
    if contains_xss(message):
        emit('message', {
            'username': 'System',
            'message': '허용되지 않은 코드가 포함되어 있습니다.'
        }, to=request.sid)
        return

    # DB 로그 저장
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO chat_log (id, sender, message, type)
        VALUES (?, ?, ?, 'public')
    """, (str(uuid.uuid4()), username, message))
    db.commit()

    # 전체 브로드캐스트
    emit('message', {
        'username': username,
        'message': message
    }, broadcast=True)

last_private_message_time = {}
# private_message: 귓속말
@socketio.on('private_message')
def handle_private_message(data):
    recipient = data.get('recipient', '').strip()
    message = data.get('message', '').strip()
    sender_sid = request.sid

    # sender username 찾기
    sender_username = None
    for uname, sid in user_sid_map.items():
        if sid == sender_sid:
            sender_username = uname
            break

    if not sender_username or not message:
        return

    # 스팸 방지: 1.5초 제한
    now = time.time()
    last_time = last_private_message_time.get(sender_username, 0)
    if now - last_time < 1.5:
        emit('private_message', {
            'sender': 'System',
            'message': '귓속말을 너무 빠르게 보냈습니다. 잠시 후 다시 시도해주세요.'
        }, to=sender_sid)
        return
    last_private_message_time[sender_username] = now

    # 메시지 길이 제한
    if len(message) > 200:
        emit('private_message', {
            'sender': 'System',
            'message': '메시지는 200자 이내로 입력해주세요.'
        }, to=sender_sid)
        return

    # 허용 문자 제한
    if not ALLOWED_PATTERN.match(message):
        emit('private_message', {
            'sender': 'System',
            'message': '허용되지 않은 문자가 포함되어 있습니다.'
        }, to=sender_sid)
        return

    # XSS 금지
    if contains_xss(message):
        emit('message', {
            'username': 'System',
            'message': '허용되지 않은 코드가 포함되어 있습니다.'
        }, to=request.sid)
        return

    # DB 저장
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO chat_log (id, sender, recipient, message, type)
        VALUES (?, ?, ?, ?, 'private')
    """, (str(uuid.uuid4()), sender_username, recipient, message))
    db.commit()

    # 전송
    if recipient in user_sid_map:
        emit('private_message', {
            'sender': sender_username,
            'message': message
        }, to=user_sid_map[recipient])
    else:
        emit('private_message', {
            'sender': 'System',
            'message': f'{recipient}님은 현재 접속 중이 아닙니다.'
        }, to=sender_sid)

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if user:
            username = user['username']
            user_sid_map[username] = request.sid
            join_room(username)  # 귓속말용 방 참가

@app.route('/search')
def search():
    query = request.args.get('q', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT * FROM product
        WHERE title LIKE ? OR description LIKE ?
    """, (f'%{query}%', f'%{query}%'))
    results = cursor.fetchall()
    return render_template('search.html', products=results, query=query)



@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target_username = request.form['username']
        amount = int(request.form['amount'])
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        # 현재 유저 정보 가져오기
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        sender = cursor.fetchone()

        try:
            amount = int(request.form['amount'])
            if amount < 1:
                raise ValueError
        except ValueError:
            flash('송금 금액은 1 이상의 숫자여야 합니다.')
            return redirect(url_for('transfer'))

        # 비밀번호 재확인
        if not check_password_hash(sender['password'], password):
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('transfer'))

        if sender['points'] < amount:
            flash('포인트가 부족합니다.')
            return redirect(url_for('transfer'))

        # 수신자 정보 확인
        cursor.execute("SELECT id FROM user WHERE username = ?", (target_username,))
        receiver = cursor.fetchone()

        if not receiver:
            flash('수신자를 찾을 수 없습니다.')
            return redirect(url_for('transfer'))

        # 자기 자신에게 송금 제한
        if receiver['id'] == session['user_id']:
            flash('자기 자신에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        # 송금 처리
        cursor.execute("UPDATE user SET points = points - ? WHERE id = ?", (amount, session['user_id']))
        cursor.execute("UPDATE user SET points = points + ? WHERE id = ?", (amount, receiver['id']))
        db.commit()

        flash(f'{target_username}님에게 {amount}포인트를 송금했습니다.')
        return redirect(url_for('dashboard'))

    return render_template('transfer.html')

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 유저가 관리자 권한인지 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if not current_user:
        flash('유저 정보를 찾을 수 없습니다.')
        return redirect(url_for('login'))

    if 'is_admin' not in current_user.keys() or current_user['is_admin'] != 1:
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))

    # 신고 내역 불러오기
    cursor.execute("""
        SELECT r.*, u.username AS target_name
        FROM report r
        LEFT JOIN user u ON r.target_id = u.id
        ORDER BY r.id DESC
    """)
    reports = cursor.fetchall()

    # 차단된 사용자/상품 확인
    cursor.execute("SELECT * FROM user WHERE blocked = 1")
    blocked_users = cursor.fetchall()

    cursor.execute("SELECT * FROM product WHERE blocked = 1")
    blocked_products = cursor.fetchall()

    # 실제 채팅 로그 100건 가져오기
    cursor.execute("""
        SELECT * FROM chat_log
        ORDER BY timestamp DESC
        LIMIT 100
    """)
    chat_logs = cursor.fetchall()

    # 감사 로그는 따로 가져오기
    cursor.execute("""
        SELECT a.*, u.username AS actor_name, t.username AS target_name
        FROM audit_log a
        LEFT JOIN user u ON a.user_id = u.id
        LEFT JOIN user t ON a.target_id = t.id
        ORDER BY a.timestamp DESC
        LIMIT 100
    """)
    audit_logs = cursor.fetchall()

    return render_template('admin.html',
                           reports=reports,
                           blocked_users=blocked_users,
                           blocked_products=blocked_products,
                           chat_logs=chat_logs,
                           audit_logs=audit_logs)




@app.route('/admin/unblock_user/<user_id>', methods=['POST'])
def unblock_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET blocked = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash('사용자 차단이 해제되었습니다.')
    return redirect(url_for('admin_panel'))

@app.route('/admin/unblock_product/<product_id>', methods=['POST'])
def unblock_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE product SET blocked = 0 WHERE id = ?", (product_id,))
    db.commit()
    flash('상품 차단이 해제되었습니다.')
    return redirect(url_for('admin_panel'))

# 404 Not Found
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', code=404, message='페이지를 찾을 수 없습니다.'), 404

# 500 Internal Server Error
@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', code=500, message='서버 오류가 발생했습니다.'), 500

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    current_pw = request.form['current_password']
    new_pw = request.form['new_password']
    confirm_pw = request.form['confirm_password']

    cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if not check_password_hash(user['password'], current_pw):
        flash('현재 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('profile'))

    if len(new_pw) < 4:
        flash('새 비밀번호는 최소 4자 이상이어야 합니다.')
        return redirect(url_for('profile'))

    if new_pw != confirm_pw:
        flash('새 비밀번호와 확인이 일치하지 않습니다.')
        return redirect(url_for('profile'))

    new_pw_hashed = generate_password_hash(new_pw)
    cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_pw_hashed, session['user_id']))
    db.commit()

    flash('비밀번호가 성공적으로 변경되었습니다.')
    return redirect(url_for('profile'))


if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
