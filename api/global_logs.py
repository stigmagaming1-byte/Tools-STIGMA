from http.server import BaseHTTPRequestHandler
import json, os, time, threading
from datetime import datetime, timezone

# Global logs and results storage
DATA_DIR = "/tmp/data"
GLOBAL_LOGS_FILE = os.path.join(DATA_DIR, "global_logs.json")
GLOBAL_RESULTS_FILE = os.path.join(DATA_DIR, "global_results.json")
file_lock = threading.Lock()

def init_global_data():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    if not os.path.exists(GLOBAL_LOGS_FILE):
        with file_lock:
            with open(GLOBAL_LOGS_FILE, 'w') as f:
                json.dump({"logs": []}, f)

    if not os.path.exists(GLOBAL_RESULTS_FILE):
        with file_lock:
            with open(GLOBAL_RESULTS_FILE, 'w') as f:
                json.dump({"results": []}, f)

init_global_data()

def load_global_logs():
    with file_lock:
        try:
            with open(GLOBAL_LOGS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {"logs": []}

def save_global_logs(data):
    with file_lock:
        with open(GLOBAL_LOGS_FILE, 'w') as f:
            json.dump(data, f, indent=2)

def load_global_results():
    with file_lock:
        try:
            with open(GLOBAL_RESULTS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {"results": []}

def save_global_results(data):
    with file_lock:
        with open(GLOBAL_RESULTS_FILE, 'w') as f:
            json.dump(data, f, indent=2)

def add_global_log(username, action, details=None, ip_address=None):
    """Add a log entry to global logs"""
    log_entry = {
        'id': str(time.time()) + '_' + username,
        'username': username,
        'action': action,
        'details': details or {},
        'ip_address': ip_address,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    logs_data = load_global_logs()
    logs_data['logs'].append(log_entry)

    # Keep only last 10000 logs to prevent file from growing too large
    if len(logs_data['logs']) > 10000:
        logs_data['logs'] = logs_data['logs'][-10000:]

    save_global_logs(logs_data)
    return log_entry

def add_global_result(username, result_data):
    """Add a result entry to global results"""
    result_entry = {
        'id': str(time.time()) + '_' + username,
        'username': username,
        'result': result_data,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    results_data = load_global_results()
    results_data['results'].append(result_entry)

    # Keep only last 50000 results to prevent file from growing too large
    if len(results_data['results']) > 50000:
        results_data['results'] = results_data['results'][-50000:]

    save_global_results(results_data)
    return result_entry

def get_global_logs(limit=100, username=None):
    """Get global logs with optional filtering"""
    logs_data = load_global_logs()
    logs = logs_data['logs']

    if username:
        logs = [log for log in logs if log['username'] == username]

    # Return most recent logs first
    return sorted(logs, key=lambda x: x['timestamp'], reverse=True)[:limit]

def get_global_results(limit=100, username=None):
    """Get global results with optional filtering"""
    results_data = load_global_results()
    results = results_data['results']

    if username:
        results = [result for result in results if result['username'] == username]

    # Return most recent results first
    return sorted(results, key=lambda x: x['timestamp'], reverse=True)[:limit]

def get_global_stats():
    """Get global statistics"""
    logs_data = load_global_logs()
    results_data = load_global_results()

    logs = logs_data['logs']
    results = results_data['results']

    # Calculate stats
    total_logs = len(logs)
    total_results = len(results)

    # User activity stats
    user_activity = {}
    for log in logs[-1000:]:  # Last 1000 logs for performance
        user = log['username']
        if user not in user_activity:
            user_activity[user] = 0
        user_activity[user] += 1

    # Results stats
    valid_results = [r for r in results if r['result'].get('status') == 'valid']
    total_valid = len(valid_results)
    total_robux = sum([r['result'].get('robux', 0) for r in valid_results])

    return {
        'total_logs': total_logs,
        'total_results': total_results,
        'total_valid_cookies': total_valid,
        'total_robux_found': total_robux,
        'active_users': len(user_activity),
        'user_activity': user_activity
    }

class handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        try:
            admin_token = self.headers.get('Authorization', '').replace('Bearer ', '')

            if not admin_token:
                raise ValueError("Authorization required")

            # Import here to avoid circular imports
            from api.auth import verify_token
            admin_payload = verify_token(admin_token)
            if not admin_payload or admin_payload.get('role') != 'admin':
                raise ValueError("Admin access required")

            path = self.path

            if path == '/api/global/logs':
                limit = int(self.headers.get('X-Limit', 100))
                username = self.headers.get('X-Username')

                logs = get_global_logs(limit=limit, username=username)

                response = {
                    'success': True,
                    'logs': logs,
                    'total': len(logs)
                }

            elif path == '/api/global/results':
                limit = int(self.headers.get('X-Limit', 100))
                username = self.headers.get('X-Username')

                results = get_global_results(limit=limit, username=username)

                response = {
                    'success': True,
                    'results': results,
                    'total': len(results)
                }

            elif path == '/api/global/stats':
                stats = get_global_stats()

                response = {
                    'success': True,
                    'stats': stats
                }

            else:
                raise ValueError("Invalid endpoint")

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': False,
                'message': str(e)
            }).encode())
