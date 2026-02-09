# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'app.py'
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import database
import crawler
import threading
from datetime import datetime, timedelta
from collections import deque
import json
import os
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
import time
import sys
import logic
import playlist
import uuid
import random
import random
import string
app = Flask(__name__)
app.secret_key = 'your_secret_key_here_change_in_production'
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
@app.before_request
def require_login():
    if request.path.startswith('/static') or request.path.startswith('/jk/') or request.path.startswith('/sub') or request.path.startswith('/playlist') or (request.endpoint in ['authorize', 'api_authorize', 'login', 'setup', 'api_logs']):
        return None
    else:
        # 修改说明：此处删除了 logic.is_key_authorized() 的判断，直接进入密码检查
        if not logic.is_password_set():
            if request.endpoint!= 'setup':
                return redirect(url_for('setup'))
            else:
                return None
        else:
            if 'logged_in' not in session:
                if request.endpoint!= 'login':
                    return redirect(url_for('login'))
@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """授权页面"""
    if request.method == 'POST':
        key = request.form.get('key', '').strip()
        if key:
            if logic.is_key_valid(key):
                config = logic.load_config()
                config['key'] = key
                logic.save_config(config)
                flash('授权成功！', 'success')
                if logic.is_password_set():
                    return redirect(url_for('login'))
                else:
                    return redirect(url_for('setup'))
            else:
                flash('授权密钥无效，请检查后重试', 'danger')
        else:
            flash('请输入授权密钥', 'danger')
    return render_template('authorize.html')
@app.route('/api/authorize', methods=['POST'])
def api_authorize():
    """API授权接口"""
    data = request.json
    key = data.get('key', '').strip()
    if key:
        if logic.is_key_valid(key):
            config = logic.load_config()
            config['key'] = key
            logic.save_config(config)
            return jsonify({'status': 'success', 'message': '授权成功'})
        else:
            return jsonify({'status': 'error', 'message': '授权密钥无效'})
    else:
        return jsonify({'status': 'error', 'message': '请输入授权密钥'})
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if logic.check_password(password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('密码错误', 'danger')
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if logic.is_password_set():
        return redirect(url_for('login'))
    else:
        if request.method == 'POST':
            password = request.form.get('password')
            if password:
                logic.save_config({'password': password})
                session['logged_in'] = True
                return redirect(url_for('index'))
            else:
                flash('密码不能为空', 'danger')
        return render_template('setup.html')
@app.route('/api/change_password', methods=['POST'])
def api_change_password():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        data = request.json
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        if not logic.check_password(old_password):
            return jsonify({'status': 'error', 'message': '原密码错误'})
        else:
            config = logic.load_config()
            config['password'] = new_password
            logic.save_config(config)
            return jsonify({'status': 'success', 'message': '密码修改成功'})
@app.route('/api/get_settings')
def api_get_settings():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        config = logic.load_config()
        return jsonify({'status': 'success', 'auto_api_type': config.get('auto_api_type', 'all'), 'auto_pages': config.get('auto_pages', 5), 'auto_days': config.get('auto_days', 1), 'log_retention_days': config.get('log_retention_days', 7), 'failure_threshold': config.get('failure_threshold', 3), 'auto_delete_failed': config.get('auto_delete_failed', False), 'epg_url': config.get('epg_url', ''), 'logo_url': config.get('logo_url', ''), 'auto_schedules': config.get('auto_schedules', [])})
@app.route('/api/get_history_logs')
def api_get_history_logs():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        logs = crawler.load_history_logs()
        logs.sort(key=lambda x: x['collection_time'], reverse=True)
        return jsonify({'status': 'success', 'logs': logs})
@app.route('/api/save_settings', methods=['POST'])
def api_save_settings():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        data = request.json
        config = logic.load_config()
        if 'auto_api_type' in data:
            config['auto_api_type'] = data.get('auto_api_type')
        if 'auto_pages' in data:
            config['auto_pages'] = int(data.get('auto_pages'))
        if 'auto_days' in data:
            config['auto_days'] = int(data.get('auto_days'))
        if 'log_retention_days' in data:
            config['log_retention_days'] = int(data.get('log_retention_days'))
        if 'failure_threshold' in data:
            config['failure_threshold'] = int(data.get('failure_threshold'))
        if 'auto_delete_failed' in data:
            config['auto_delete_failed'] = data.get('auto_delete_failed')
        if 'epg_url' in data:
            config['epg_url'] = data.get('epg_url', '').strip()
        if 'logo_url' in data:
            config['logo_url'] = data.get('logo_url', '').strip()
        if 'auto_schedules' in data:
            raw_schedules = data.get('auto_schedules', [])
            valid_schedules = []
            for s in raw_schedules:
                if len(s) == 5 and ':' in s:
                        valid_schedules.append(s)
            config['auto_schedules'] = valid_schedules
        logic.save_config(config)
        return jsonify({'status': 'success', 'message': '设置已保存'})
@app.route('/api/check_update')
def api_check_update():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        result = logic.check_app_update()
        if result['status'] == 'success':
            return jsonify(result)
        else:
            return jsonify(result)
@app.route('/api/update_api', methods=['POST'])
def api_update_api():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        result = logic.fetch_remote_api_config()
        if result['status'] == 'success':
            try:
                new_config = result['data']
                if 'multicast' in new_config or 'common_headers' in new_config:
                    json_str = json.dumps(new_config, ensure_ascii=False)
                    encrypted = logic.process_payload(json_str, logic.PROCESS_KEY)
                    config_dir = os.environ.get('IPTV_DATA_DIR') or os.environ.get('DATA_DIR') or 'data'
                    if not os.path.exists(config_dir):
                        os.makedirs(config_dir)
                    cache_file = os.path.join(config_dir, 'api.cache')
                    with open(cache_file, 'w') as f:
                        f.write(encrypted)
                    return jsonify({'status': 'success', 'message': 'API配置更新成功'})
                else:
                    return jsonify({'status': 'error', 'message': '返回数据格式不正确'})
            except:
                return jsonify({'status': 'error', 'message': '解析返回数据失败'})
        else:
            return jsonify(result)
@app.route('/api/reset_api', methods=['POST'])
def api_reset_api():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        try:
            default_config = logic.get_default_api_config()
            json_str = json.dumps(default_config, ensure_ascii=False)
            encrypted = logic.process_payload(json_str, logic.PROCESS_KEY)
            config_dir = os.environ.get('IPTV_DATA_DIR') or os.environ.get('DATA_DIR') or 'data'
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            cache_file = os.path.join(config_dir, 'api.cache')
            with open(cache_file, 'w') as f:
                f.write(encrypted)
            return jsonify({'status': 'success', 'message': 'API配置已恢复默认'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'重置失败: {e}'})
LOG_BUFFER = deque(maxlen=2000)
LOG_lock = threading.Lock()
def log_message(message):
    timestamp = datetime.now().strftime('%H:%M:%S')
    full_msg = f'[{timestamp}] {message}'
    print(full_msg, flush=True)
    with LOG_lock:
        LOG_BUFFER.append(full_msg)
@app.route('/api/logs')
def api_logs():
    with LOG_lock:
        return jsonify({'logs': list(LOG_BUFFER)})
@app.route('/api/get_system_logs')
def api_get_system_logs():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        log_file = os.environ.get('LOG_FILE')
        if not log_file:
            log_file = 'info.log'
        if not os.path.exists(log_file):
            return jsonify({'status': 'success', 'logs': []})
        else:
            try:
                lines = []
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines = f.readlines()
                    lines = all_lines[(-2000):]
                return jsonify({'status': 'success', 'logs': [l.strip() for l in lines]})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Failed to read logs: {str(e)}'})
@app.route('/api/clear_system_logs', methods=['POST'])
def api_clear_system_logs():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        log_file = os.environ.get('LOG_FILE')
        if not log_file:
            log_file = 'info.log'
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write('')
            return jsonify({'status': 'success', 'message': '日志已清理'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Failed to clear logs: {str(e)}'})
database.init_db()
@app.route('/')
def index():
    return redirect(url_for('collection'))
@app.route('/collection')
def collection():
    return redirect(url_for('ip_manager'))
@app.route('/auto')
def auto():
    return render_template('auto.html', active_tab='auto')
@app.route('/ip_manager')
def ip_manager():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    filter_type = request.args.get('type', 'all')
    keyword = request.args.get('keyword', '').strip()
    ips, total = database.get_ips(page, per_page, filter_type, keyword)
    total_pages = (total + per_page - 1) // per_page
    return render_template('ip_manager.html', active_tab='ip_manager', ips=ips, page=page, per_page=per_page, total_pages=total_pages, total_items=total, filter_type=filter_type, keyword=keyword)
@app.route('/logs')
def logs():
    return render_template('logs.html', active_tab='logs')
@app.route('/settings')
def settings():
    return render_template('settings.html', active_tab='settings')
@app.route('/api/collect', methods=['POST'])
def api_collect():
    data = request.json
    api_type = data.get('api_type')
    pages = int(data.get('pages', 5))
    date_filter = data.get('date')
    def run_collection_task():
        with LOG_lock:
            LOG_BUFFER.clear()
        try:
            if api_type == 'all':
                log_message('=== 开始采集组播源 ===')
                crawler.run_collection('multicast', pages, date_filter, log_callback=log_message)
                log_message('=== 开始采集酒店源 ===')
                crawler.run_collection('hotel', pages, date_filter, log_callback=log_message)
            else:
                crawler.run_collection(api_type, pages, date_filter, log_callback=log_message)
            log_message('=== 开始存量IP检测 ===')
            crawler.run_verification(log_callback=log_message)
            log_message('后台采集任务结束。')
        except Exception as e:
            log_message(f'采集任务出错: {e}')
    thread = threading.Thread(target=run_collection_task)
    thread.start()
    return jsonify({'status': 'success', 'message': 'Collection started in background'})
scheduler_thread = threading.Thread(target=crawler.run_scheduler_loop, args=(log_message,), daemon=True)
scheduler_thread.start()
@app.route('/api/delete_ips', methods=['POST'])
def api_delete_ips():
    data = request.json
    ip_ports = data.get('ip_ports', [])
    database.delete_ips(ip_ports)
    return jsonify({'status': 'success'})
@app.route('/api/stop_collection', methods=['POST'])
def api_stop_collection():
    try:
        crawler.stop_collection()
        return jsonify({'status': 'success', 'message': '停止指令已发送'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
@app.route('/subscriptions')
def subscriptions():
    return render_template('subscriptions.html', active_tab='subscriptions')
@app.route('/api/subscriptions/list')
def api_list_subscriptions():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        subs = database.get_subscriptions()
        for sub in subs:
            try:
                sub['types'] = json.loads(sub['types'])
            except:
                sub['types'] = []
            try:
                sub['provinces'] = json.loads(sub['provinces'])
            except:
                sub['provinces'] = []
            try:
                sub['isps'] = json.loads(sub.get('isps') or '[]')
            except:
                sub['isps'] = []
        return jsonify({'status': 'success', 'subscriptions': subs, 'all_types': database.get_distinct_types(), 'all_provinces': database.get_distinct_provinces(), 'all_isps': database.get_distinct_isps()})
@app.route('/api/subscriptions/create', methods=['POST'])
def api_create_subscription():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        data = request.json
        token = data.get('token')
        if not token:
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        types = data.get('types', [])
        provinces = data.get('provinces', [])
        isps = data.get('isps', [])
        try:
            database.create_subscription({'token': token, 'types': json.dumps(types, ensure_ascii=False), 'provinces': json.dumps(provinces, ensure_ascii=False), 'isps': json.dumps(isps, ensure_ascii=False)})
            return jsonify({'status': 'success', 'message': '订阅创建成功', 'token': token})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'创建失败: {str(e)}'})
@app.route('/api/subscriptions/update', methods=['POST'])
def api_update_subscription():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        data = request.json
        token = data.get('token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Token不能为空'})
        else:
            types = data.get('types', [])
            provinces = data.get('provinces', [])
            isps = data.get('isps', [])
            try:
                database.update_subscription({'token': token, 'types': json.dumps(types, ensure_ascii=False), 'provinces': json.dumps(provinces, ensure_ascii=False), 'isps': json.dumps(isps, ensure_ascii=False)})
                return jsonify({'status': 'success', 'message': '订阅更新成功'})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'更新失败: {str(e)}'})
@app.route('/api/subscriptions/delete', methods=['POST'])
def api_delete_subscription():
    if 'logged_in' not in session:
        return jsonify({'status': 'error', 'message': '未登录'})
    else:
        data = request.json
        token = data.get('token')
        database.delete_subscription(token)
        return jsonify({'status': 'success'})
@app.route('/sub')
def sub_handler():
    token = None
    fmt = 'm3u'
    for key, value in request.args.items():
        sub = database.get_subscription_by_token(key)
        if sub:
            token = key
            fmt = value if value in ['txt', 'm3u'] else 'm3u'
            break
    if not token:
        return ('Subscription not found', 404)
    else:
        try:
            types = json.loads(sub['types'])
        except:
            types = []
        try:
            provinces = json.loads(sub['provinces'])
        except:
            provinces = []
        try:
            isps = json.loads(sub.get('isps') or '[]')
        except:
            isps = []
        ips = database.get_ips_for_subscription(types, provinces, isps)
        all_channels = playlist.parse_channel_data(ips)
        categorized = playlist.categorize_and_sort(all_channels)
        content = ''
        if fmt == 'txt':
            content = playlist.generate_txt(categorized)
            return (content, 200, {'Content-Type': 'text/plain; charset=utf-8'})
        else:
            config = logic.load_config()
            epg_url = config.get('epg_url')
            logo_url = config.get('logo_url')
            content = playlist.generate_m3u(categorized, epg_url=epg_url, logo_base_url=logo_url)
            return (content, 200, {'Content-Type': 'text/plain; charset=utf-8'})
@app.route('/player')
def player():
    config = logic.load_config()
    epg_url = config.get('epg_url', '')
    return render_template('player.html', epg_url=epg_url)
@app.route('/playlist/<fmt>/<ip_port>')
def playlist_handler(fmt, ip_port):
    """\n    Generate playlist for a single IP.\n    fmt: txt or m3u\n    ip_port: ip:port string\n    """
    ip_data = database.get_ip_by_address(ip_port)
    if not ip_data:
        return ('IP not found', 404)
    else:
        all_channels = playlist.parse_channel_data([ip_data])
        categorized = playlist.categorize_and_sort(all_channels)
        if fmt == 'txt':
            content = playlist.generate_txt(categorized)
            return (content, 200, {'Content-Type': 'text/plain; charset=utf-8'})
        else:
            if fmt == 'm3u':
                config = logic.load_config()
                epg_url = config.get('epg_url')
                logo_url = config.get('logo_url')
                content = playlist.generate_m3u(categorized, epg_url=epg_url, logo_base_url=logo_url)
                return (content, 200, {'Content-Type': 'text/plain; charset=utf-8'})
            else:
                return ('Invalid format', 400)
def serve_channel_list(ip_port):
    ip_data = database.get_ip_by_address(ip_port)
    if not ip_data:
        return ('IP not found', 404)
    else:
        content = ip_data.get('channel_lists', '')
        return (content, 200, {'Content-Type': 'text/plain; charset=utf-8'})
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=50085, debug=True)