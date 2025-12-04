from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import time

# Import helper functions from existing modules
from api import auth as auth_mod
from api import check as check_mod
from api import global_logs as global_logs_mod

app = Flask(__name__)
CORS(app)


def require_admin(token):
    if not token:
        return False, 'Authorization required'
    ok, payload = auth_mod.verify_user_token(token)
    if not ok:
        return False, payload
    if payload.get('role') != 'admin':
        return False, 'Admin access required'
    return True, payload


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    success, result = auth_mod.authenticate_user(username, password)
    if success:
        return jsonify({'success': True, 'message': 'Login successful', 'data': result})
    return jsonify({'success': False, 'message': result}), 401


@app.route('/api/auth/verify', methods=['POST'])
def api_verify():
    data = request.get_json() or {}
    token = data.get('token', '')
    if not token:
        return jsonify({'success': False, 'message': 'Token required'}), 400
    ok, result = auth_mod.verify_user_token(token)
    if ok:
        return jsonify({'success': True, 'message': 'Token valid', 'data': result})
    return jsonify({'success': False, 'message': result}), 401


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    data = request.get_json() or {}
    token = data.get('token', '')
    if token:
        sessions = auth_mod.load_sessions()
        sessions['sessions'] = [s for s in sessions.get('sessions', []) if s.get('token') != token]
        auth_mod.save_sessions(sessions)
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@app.route('/api/auth/create_user', methods=['POST'])
def api_create_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    ok, payload = require_admin(token)
    if not ok:
        return jsonify({'success': False, 'message': payload}), 401

    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    days_valid = int(data.get('days_valid', 30))
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    success, result = auth_mod.create_user_account(username, password, days_valid, 'admin')
    if success:
        return jsonify({'success': True, 'message': f'User {username} created successfully for {days_valid} days', 'data': result})
    return jsonify({'success': False, 'message': result}), 400


@app.route('/api/auth/users', methods=['GET'])
def api_get_users():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    ok, payload = require_admin(token)
    if not ok:
        return jsonify({'success': False, 'message': payload}), 401
    users = auth_mod.get_all_users()
    return jsonify({'success': True, 'users': users})


@app.route('/api/auth/user/<username>', methods=['GET', 'DELETE'])
def api_user_operations(username):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    ok, payload = require_admin(token)
    if not ok:
        return jsonify({'success': False, 'message': payload}), 401

    if request.method == 'GET':
        user = auth_mod.get_user_stats(username)
        if user:
            return jsonify({'success': True, 'user': user})
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # DELETE
    success, message = auth_mod.delete_user(username)
    return jsonify({'success': success, 'message': message})


@app.route('/api/check', methods=['GET', 'POST'])
def api_check():
    if request.method == 'GET':
        action = request.args.get('action', '')
        if action == 'results':
            return jsonify(check_mod.checker_state['results'][-100:])
        if action == 'logs':
            # Build logs response similar to original
            valid_cookies = []
            for result in check_mod.checker_state['results']:
                if result.get('status') == 'valid':
                    valid_cookies.append({
                        'cookie_id': result.get('cookie_id'),
                        'username': result.get('username'),
                        'user_id': result.get('user_id'),
                        'display_name': result.get('display_name'),
                        'robux': result.get('robux', 0),
                        'premium': result.get('premium', False),
                        'friends': result.get('friends_count', 0),
                        'created_date': result.get('created_date', ''),
                        'timestamp': result.get('timestamp')
                    })
            response = {
                'total_results': len(check_mod.checker_state['results']),
                'valid_count': len(valid_cookies),
                'invalid_count': len(check_mod.checker_state['results']) - len(valid_cookies),
                'total_robux': sum([r.get('robux', 0) for r in check_mod.checker_state['results'] if r.get('status') == 'valid']),
                'valid_cookies': valid_cookies,
                'all_logs': check_mod.checker_state['results'][-50:]
            }
            return jsonify(response)

        # default status
        response = {
            'status': check_mod.checker_state['live_data']['status'],
            'is_checking': check_mod.checker_state['is_checking'],
            'stats': check_mod.checker_state['live_data']
        }
        return jsonify(response)

    # POST
    data = request.get_json() or {}
    action = data.get('action', '')

    try:
        if action == 'start':
            cookies = data.get('cookies', [])
            if not cookies:
                return jsonify({'success': False, 'message': 'No cookies provided'}), 400
            if check_mod.checker_state['is_checking']:
                return jsonify({'success': False, 'message': 'Checker is already running'}), 400

            check_mod.checker_state['is_checking'] = True
            check_mod.checker_state['results'] = []
            check_mod.checker_state['live_data'] = {
                'status': 'running',
                'total_checked': 0,
                'valid': 0,
                'invalid': 0,
                'robux': 0,
                'premium': 0,
                'friends': 0,
                'progress': 0,
                'current': 1,
                'total': len(cookies),
                'start_time': time.time()
            }

            thread = threading.Thread(target=check_mod.check_cookies_batch, args=(cookies,))
            thread.daemon = True
            thread.start()

            return jsonify({'success': True, 'message': f'Started checking {len(cookies)} cookies', 'total': len(cookies)})

        elif action == 'stop':
            check_mod.checker_state['is_checking'] = False
            check_mod.checker_state['live_data']['status'] = 'stopped'
            return jsonify({'success': True, 'message': 'Checker stopped'})

        elif action == 'test':
            cookie = data.get('cookie', '')
            if not cookie:
                return jsonify({'success': False, 'message': 'No cookie provided'}), 400
            result = check_mod.check_single_cookie(cookie, 0)
            check_mod.checker_state['results'].append(result)
            if result.get('status') == 'valid':
                check_mod.checker_state['live_data']['valid'] += 1
                check_mod.checker_state['live_data']['robux'] += result.get('robux', 0)
                if result.get('premium', False):
                    check_mod.checker_state['live_data']['premium'] += 1
                if result.get('friends_count', 0):
                    check_mod.checker_state['live_data']['friends'] += result.get('friends_count', 0)
            else:
                check_mod.checker_state['live_data']['invalid'] += 1
            check_mod.checker_state['live_data']['total_checked'] += 1
            return jsonify(result)

        elif action == 'clear':
            check_mod.checker_state['results'] = []
            check_mod.checker_state['live_data'] = {
                'status': 'idle',
                'total_checked': 0,
                'valid': 0,
                'invalid': 0,
                'robux': 0,
                'premium': 0,
                'friends': 0,
                'progress': 0,
                'current': 0,
                'total': 0,
                'start_time': None
            }
            return jsonify({'success': True, 'message': 'Results cleared'})

        elif action == 'export':
            valid_cookies = [r for r in check_mod.checker_state['results'] if r.get('status') == 'valid']
            export_data = "# VALID ROBLOX COOKIES EXPORT\n"
            for i, cookie in enumerate(valid_cookies):
                export_data += f"=== ACCOUNT {i+1} ===\n"
                export_data += f"Username: {cookie.get('username')}\n"
                export_data += f"User ID: {cookie.get('user_id')}\n"
                export_data += f"Robux: {cookie.get('robux', 0)}\n"
                export_data += f"Premium: {'Yes' if cookie.get('premium', False) else 'No'}\n"
                export_data += f"Cookie: {cookie.get('cookie', 'N/A')}\n\n"
            return jsonify({'success': True, 'export_data': export_data})

        elif action == 'save_state':
            check_mod.save_checker_state(check_mod.checker_state)
            return jsonify({'success': True, 'message': 'Checker state saved successfully'})

        elif action == 'load_state':
            loaded = check_mod.load_checker_state()
            if loaded and loaded.get('results'):
                check_mod.checker_state['results'] = loaded['results']
                check_mod.checker_state['live_data'] = loaded['live_data']
                return jsonify({'success': True, 'message': 'Checker state loaded successfully', 'total_results': len(check_mod.checker_state['results'])})
            return jsonify({'success': False, 'message': 'No saved state found'})

        else:
            return jsonify({'success': False, 'message': 'Invalid action'}), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    # Run development server
    app.run(host='0.0.0.0', port=8000, debug=True)
