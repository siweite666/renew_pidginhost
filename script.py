#!/usr/bin/env python3
import os
import sys
import re
import json
import requests
import time
from urllib.parse import urljoin

# ---------- 配置 ----------
API_TOKEN = os.getenv('PIDGINHOST_API_TOKEN')
PANEL_BASE = 'https://www.pidginhost.com/'
PROXY = os.getenv('PROXY_SERVER')
TG_TOKEN = os.getenv('TG_BOT_TOKEN')
TG_CHAT = os.getenv('TG_CHAT_ID')
EMAIL = (os.getenv('EMAIL') or '').strip()
PASSWORD = (os.getenv('PASSWORD') or '').strip()

if not API_TOKEN:
    # token 已不具备 cloud/servers 读权限（403），列表走 panel cookie
    print('ℹ️ 未提供 PIDGINHOST_API_TOKEN，服务器列表将走 panel 会话')

if not EMAIL or not PASSWORD:
    print('❌ 缺少 EMAIL / PASSWORD')
    sys.exit(1)

proxies = {'http': PROXY, 'https': PROXY} if PROXY else None

api_session = requests.Session()
api_session.headers.update({'Authorization': f'Token {API_TOKEN}', 'Content-Type': 'application/json'})
if proxies:
    api_session.proxies.update(proxies)

panel_session = requests.Session()
if proxies:
    panel_session.proxies.update(proxies)

# ---------- 脱敏（仓库 public，Actions 日志公开可见）----------
def mask_email(v):
    if not v or '@' not in v:
        return '***'
    u, d = v.split('@', 1)
    return (u[:2] + '***@' + d) if len(u) > 2 else '***@' + d

def mask_ip(v):
    parts = str(v).split('.')
    return f'{parts[0]}.{parts[1]}.x.x' if len(parts) == 4 else 'x.x.x.x'

def mask_url(u):
    u = re.sub(r'([?&](?:token|code|key|session|next)=)[^&\s]+', r'\1***', str(u))
    return re.sub(r'/panel/[\w-]{16,}/', '/panel/***/', u)

# ---------- 登录（站点已取消长效 cookie，改走账号密码）----------
LOGIN_URL = urljoin(PANEL_BASE, 'panel/account/login')
LOCAL_LOGIN_URL = urljoin(PANEL_BASE, 'panel/account/login/local')

def _csrf(html):
    m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
    return m.group(1) if m else None

def login_panel(session):
    """两步登录：先交 email 换出密码页，再提交密码。
    每次运行都重新登录 —— 不依赖任何会过期的 cookie。"""
    last_err = None
    for attempt in range(1, 4):
        try:
            session.cookies.clear()
            r = session.get(LOGIN_URL, timeout=30)
            if r.status_code != 200:
                last_err = f'登录页返回 {r.status_code}'
                time.sleep(3); continue

            tok = _csrf(r.text)
            if not tok:
                last_err = '登录页未找到 csrfmiddlewaretoken'
                time.sleep(3); continue

            # 第 1 步：提交邮箱
            r1 = session.post(
                LOGIN_URL,
                data={'csrfmiddlewaretoken': tok, 'email': EMAIL},
                headers={'Referer': LOGIN_URL}, allow_redirects=True, timeout=30)

            tok2 = _csrf(r1.text) or tok
            # 第 2 步：提交密码（hidden username 由页面带入，这里显式带上）
            r2 = session.post(
                LOCAL_LOGIN_URL,
                data={'csrfmiddlewaretoken': tok2, 'username': EMAIL,
                      'password': PASSWORD, 'remember_me': 'on'},
                headers={'Referer': r1.url}, allow_redirects=True, timeout=30)

            # 第 3 步：验证 —— 访问需要登录的页面
            probe = session.get(urljoin(PANEL_BASE, 'panel/cloud/servers/'),
                                allow_redirects=True, timeout=30)
            if '/account/login' in probe.url or probe.status_code != 200:
                last_err = f'登录后仍被重定向到登录页（{mask_url(probe.url)}，{probe.status_code}）'
                time.sleep(2); continue

            print(f'✅ 账号密码登录成功（{mask_email(EMAIL)}），已进入 panel')
            return True
        except Exception as e:
            last_err = str(e)
            time.sleep(2)

    print(f'❌ 登录失败：{last_err}')
    return False

# ---------- 工具函数 ----------
def send_tg(text):
    if TG_TOKEN and TG_CHAT:
        try:
            requests.post(f'https://api.telegram.org/bot{TG_TOKEN}/sendMessage',
                          data={'chat_id': TG_CHAT, 'text': text[:4096]}, timeout=10)
        except Exception as e:
            print(f'⚠️ TG 通知失败: {e}')

def get_csrf_token_and_action(session, url):
    resp = session.get(url, timeout=30)
    if resp.status_code != 200:
        return None, None, resp

    csrf_cookie = None
    for c in session.cookies:
        if c.name == 'csrftoken':
            csrf_cookie = c.value
            break
    if not csrf_cookie:
        match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        csrf_cookie = match.group(1) if match else None

    # 提取 action 值
    action_value = None
    action_match = re.search(r'name="action"\s+value="([^"]+)"', resp.text)
    if action_match:
        action_value = action_match.group(1)
    else:
        if 'extend_renewal' in resp.text:
            action_value = 'extend_renewal'
        elif 'renew' in resp.text:
            renew_match = re.search(r'value="([^"]*renew[^"]*)"', resp.text, re.I)
            action_value = renew_match.group(1) if renew_match else 'extend_renewal'
        else:
            action_value = 'extend_renewal'

    return csrf_cookie, action_value, resp

def extract_expiry_days(html_text):
    patterns = [
        r'This\s+free\s+server\s+expires\s+in\s+(\d+)\s+days?',
        r'expires\s+in\s+(\d+)\s+days?',
        r'remaining\s+(\d+)\s+days?',
        r'(\d+)\s+days?\s+remaining',
        r'剩余\s*(\d+)\s*天',
        r'(\d+)\s+days?\s+left',
    ]
    for pat in patterns:
        match = re.search(pat, html_text, re.IGNORECASE)
        if match:
            return int(match.group(1))
    # 清理标签再试
    clean = re.sub(r'<[^>]+>', ' ', html_text)
    clean = re.sub(r'\s+', ' ', clean).strip()
    for pat in patterns:
        match = re.search(pat, clean, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None

def get_page(url, session, allow_redirects=True, cache_control=True):
    headers = {}
    if cache_control:
        headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp = session.get(url, headers=headers, allow_redirects=allow_redirects, timeout=30)
    return resp, resp.url if allow_redirects else url

def get_current_days_for_url(url, session, max_retries=3, delay=2):
    if not url:
        return None, None, None
    for attempt in range(max_retries):
        if attempt > 0:
            time.sleep(delay)
        resp, final_url = get_page(url, session, allow_redirects=True)
        if resp.status_code != 200:
            print(f'  ⚠️ 获取页面失败，状态码 {resp.status_code} (尝试 {attempt+1}/{max_retries})')
            continue
        days = extract_expiry_days(resp.text)
        if days is not None:
            return days, resp, final_url
        snippet = resp.text[:300].replace('\n', ' ')
        snippet = re.sub(r'[\w.+-]+@[\w-]+\.[\w.]+', '***@***', snippet)   # public 仓库，别泄露邮箱
        snippet = re.sub(r'\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b', r'\1.x.x', snippet)
        print(f'  ⚠️ 未解析到天数 (尝试 {attempt+1}/{max_retries})，页面开头片段：{snippet}')
    return None, None, None

def renew_server_via_panel(server_id):
    detail_url = urljoin(PANEL_BASE, f'panel/cloud/servers/{server_id}/')
    print('  ⏳ 获取续期前剩余天数...')
    old_days, _, _ = get_current_days_for_url(detail_url, panel_session, max_retries=2, delay=1)
    if old_days is None:
        print('  ⚠️ 无法获取续期前天数，将视为 0')
        old_days = 0

    # 获取 CSRF token 和 action
    csrf_token, action_value, resp = get_csrf_token_and_action(panel_session, detail_url)
    if not csrf_token:
        if resp.status_code == 302:
            # 检查是否重定向到登录页
            location = resp.headers.get('Location', '')
            if '/login' in location:
                return False, "Cookie 已过期（重定向到登录页）", None
        return False, f"无法获取 CSRF token (状态码 {resp.status_code})", None

    # 发送续期 POST
    print('  🔄 发送续期请求...')
    data = {
        'csrfmiddlewaretoken': csrf_token,
        'action': action_value if action_value else 'extend_renewal'
    }
    headers = {'Referer': detail_url, 'X-CSRFToken': csrf_token}
    post_resp = panel_session.post(detail_url, data=data, headers=headers, allow_redirects=False, timeout=30)

    if post_resp.status_code == 302:
        location = post_resp.headers.get('Location', '')
        if '/login' in location:
            return False, "续期请求重定向到登录页，Cookie 已失效", None
        if not location.startswith('http'):
            location = urljoin(PANEL_BASE, location)
        print(f'  ✅ 收到续期重定向，Location: {mask_url(location)}')
        final_url = location
    else:
        return False, f"续期请求失败 (状态码 {post_resp.status_code})", None

    # 等待并获取续期后的天数
    print('  ⏳ 等待并获取续期后剩余天数...')
    new_days = None
    for attempt in range(6):
        if attempt > 0:
            time.sleep(2)
        days, resp, final_url = get_current_days_for_url(final_url, panel_session, max_retries=1, delay=0)
        if days is not None:
            new_days = days
            break
        print(f'  ⚠️ 未解析到天数，重试 {attempt+1}/6')

    if new_days is None:
        return False, "续期后未能获取剩余天数", None

    if new_days >= old_days and new_days > 0:
        return True, f"续期成功（剩余 {new_days} 天）", new_days
    else:
        return False, f"续期异常（旧：{old_days}，新：{new_days}）", new_days

def fetch_all_servers_via_panel():
    """从 panel 的已登录会话取服务器列表。

    schema（/api/schema/）明确列出 /api/cloud/servers/ 同时接受
    tokenAuth 和 cookieAuth，所以这里复用 panel_session 的 cookie，
    不再依赖 PIDGINHOST_API_TOKEN —— 那个 token 在 2026-10-31 的
    run 里返回 403（认证通过但无权限，不是 401 Invalid token）。
    """
    # 首选：同一个 API，改用 cookie 认证
    url = urljoin('https://www.pidginhost.com/api/', 'cloud/servers/')
    items = []
    try:
        while url:
            resp = panel_session.get(
                url, timeout=30,
                headers={'Accept': 'application/json',
                         'Cache-Control': 'no-cache, no-store, must-revalidate'})
            if resp.status_code in (301, 302) or '/account/login' in resp.url:
                raise RuntimeError('panel 会话失效，重定向到登录页')
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get('results', []))
            url = data.get('next')
        if items:
            print(f'  ✅ 经 panel cookie 取到 {len(items)} 台服务器（API）')
            return items
    except Exception as e:
        print(f'  ⚠️ panel cookie 调 API 失败（{e}），改用页面解析')
        try:
            _r = panel_session.get(url, timeout=30, headers={'Accept': 'application/json'})
            print(f'  🔍 诊断: API {_r.status_code}, body={_r.text[:200]}')
        except Exception:
            pass

    # 兜底：从 panel 页面 HTML 里抓服务器 ID
    page_url = urljoin(PANEL_BASE, 'panel/cloud/servers/')
    resp = panel_session.get(page_url, timeout=30,
                             headers={'Cache-Control': 'no-cache, no-store, must-revalidate'})
    print(f'  🔍 诊断: 页面 {resp.status_code}, {len(resp.text)} 字符, url={mask_url(resp.url)}')
    if '/account/login' in resp.url:
        raise RuntimeError('panel 会话失效，重定向到登录页')
    resp.raise_for_status()

    html = resp.text
    # 多种可能的 ID 呈现方式
    ids = []

    # a) 链接样式 /panel/cloud/servers/{id}/ 或 /panel/cloud/servers/{id}
    for m in re.finditer(r'/panel/cloud/servers/([0-9A-Za-z_-]+)', html):
        v = m.group(1)
        if v not in ('new', 'create') and v not in ids:
            ids.append(v)

    # b) data-* 属性
    if not ids:
        for m in re.finditer(r'data-(?:server|vps|id)[\w-]*="(\d+)"', html, re.I):
            if m.group(1) not in ids:
                ids.append(m.group(1))

    # c) 内嵌 JSON 里的 "id": 123
    if not ids:
        for m in re.finditer(r'"id"\s*:\s*(\d{2,7})', html):
            if m.group(1) not in ids:
                ids.append(m.group(1))

    if not ids:
        # 最后一招：把结构打出来（脱敏），供人工判断
        hrefs = sorted({re.sub(r'\?.*$', '', h) for h in
                        re.findall(r'href="([^"]+)"', html)
                        if 'server' in h.lower() or 'cloud' in h.lower()})
        print(f'  🔍 诊断: 含 server/cloud 的 href ({len(hrefs)} 个): {hrefs[:15]}')
        print(f'  🔍 诊断: 页面是否含 "expires": {"expires" in html.lower()}')
        print(f'  🔍 诊断: 页面开头: '
              + re.sub(r'[\w.+-]+@[\w-]+\.[\w.]+', '***@***', html[:400].replace("\n", " ")))
        # profile_incomplete 时把表单字段列出来（只看 name/type/required，不取值）
        try:
            prof = panel_session.get(urljoin(PANEL_BASE, 'panel/account/profile/'), timeout=30)
            print(f'  🔍 profile 页: {prof.status_code}, {len(prof.text)} 字符, url={mask_url(prof.url)}')
            fields = re.findall(r'<(input|select|textarea)\s+([^>]*)>', prof.text, re.I)
            seen = []
            for tag, attrs in fields:
                nm = re.search(r'name="([^"]+)"', attrs)
                ty = re.search(r'type="([^"]+)"', attrs)
                rq = 'required' in attrs.lower()
                if nm:
                    seen.append(f'{nm.group(1)}[{ty.group(1) if ty else tag}{",req" if rq else ""}]')
            print(f'  🔍 profile 表单字段: {seen}')
            # 页面里的提示文字
            hints = re.findall(r'(?:alert|text-danger|form-text)[^>]*>([^<]{10,140})', prof.text)
            print(f'  🔍 profile 提示: {[h.strip()[:100] for h in hints[:8]]}')
        except Exception as e:
            print(f'  🔍 profile 探测失败: {e}')
        raise RuntimeError('页面里没找到任何服务器 ID（panel 结构可能变了）')

    print(f'  ✅ 经页面解析取到 {len(ids)} 台服务器: {ids}')
    return [{'id': sid, 'name': '未命名'} for sid in ids]

# ---------- 主逻辑 ----------
def main():
    try:
        # 每次运行重新登录（站点已取消长效 cookie）
        print('🔑 正在登录 panel...')
        if not login_panel(panel_session):
            send_tg('❌ PidginHost 续期失败：账号密码登录失败')
            sys.exit(1)

        # 获取服务器列表
        print('📄 获取所有云服务器...')
        servers = fetch_all_servers_via_panel()
        print(f'📋 找到 {len(servers)} 台服务器')

        renewed = 0
        failed = 0
        details = []

        for server in servers:
            sid = server['id']
            name = server.get('name', '未命名')
            print(f'🔄 尝试续期服务器 {sid} ({name})')

            success, msg, new_days = renew_server_via_panel(sid)
            if success:
                print(f'✅ {msg}')
                renewed += 1
                details.append(f'✅ 服务器 {sid} 续期成功（剩余 {new_days} 天）')
            else:
                print(f'❌ {msg}')
                failed += 1
                details.append(f'❌ 服务器 {sid} 续期失败: {msg}')

        summary = f'续期完成：成功 {renewed} 台，失败 {failed} 台'
        print(f'🎉 {summary}')
        full_text = f"PidginHost 续期\n{summary}\n详情：\n" + '\n'.join(details[-5:])
        send_tg(('✅ ' if failed == 0 else '⚠️ ') + full_text)
        sys.exit(0 if failed == 0 else 1)

    except Exception as e:
        error_msg = f'❌ 脚本异常: {e}'
        print(error_msg)
        send_tg(f'❌ 续期脚本崩溃\n{error_msg}')
        sys.exit(1)

if __name__ == '__main__':
    main()
