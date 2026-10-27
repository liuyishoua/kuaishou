"""Live Agent selection, account-scoped execution and immutable local history."""
from pathlib import Path
from flask import request
from .channel_client import ChannelClient, ChannelError
from .config import CONFIG


def register_channel(app, service, config_path, record_lookup=None):
    app.register_error_handler(ChannelError, lambda error: ({'error': str(error)}, 502))
    def account():
        identity = service.platform.identity()
        return str(identity['id']) if identity else 'anonymous'
    def client():
        return ChannelClient(config_path)
    def snapshot(binding):
        route = binding['route']
        agent = binding.get('agent') or route.get('agent') or {}
        return {'agent_id': route['agent_id'], 'agent_name': agent.get('name', ''),
                'route_id': route['id'], 'route_version': route.get('version')}
    def saved(owner, purpose):
        try: return service.record('channel-binding', purpose, owner)
        except LookupError: return None
    def bind(channel, owner, purpose, agent_id):
        if purpose not in ('content', 'comment', 'research'):
            raise ValueError('不支持的用途')
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError('请选择一个 Agent')
        binding = channel.bind(owner, purpose, agent_id)
        value = snapshot(binding)
        service.put('channel-binding', {'id': purpose, **value}, owner)
        return value
    def catalog():
        owner = account()
        result = client().catalog()  # No cached directory fallback.
        bindings = {p: saved(owner, p) for p in ('content','comment','research')}
        identity = service.platform.identity() or {}
        expected = CONFIG['name'].removesuffix('工作台') + '-' + str(identity.get('name', ''))
        matches = [a for a in result['agents'] if identity.get('name') and a.get('name') == expected]
        if len(matches) == 1:
            for purpose, existing in bindings.items():
                if existing is None:
                    bindings[purpose] = {'agent_id': matches[0]['id'], 'agent_name': matches[0]['name']}
        return {**result, 'account_id': owner, 'bindings': bindings}
    def bindings():
        owner = account(); data = request.get_json() or {}
        if data.get('account_id', owner) != owner: raise ValueError('账号不匹配')
        return bind(client(), owner, data.get('purpose'), data.get('agent_id'))
    def history():
        return {'account_id': account(), 'items': service.records('channel-task', account())[:100]}
    def channel_meta():
        return {'configured': Path(config_path).is_file(), 'console_url': 'https://d.58nft.net:9456/'}
    def submit():
        data = request.get_json() or {}; owner = account()
        if data.get('account_id', owner) != owner: raise ValueError('账号不匹配')
        prompt = data.get('text', '分析这条内容，提炼要点并给出建议。')
        if not isinstance(prompt, str) or len(prompt) > 4000:
            raise ValueError('处理要求最多 4000 字')
        context = data.get('context', {})
        if not isinstance(context, dict): raise ValueError('上下文必须是对象')
        item_id = data.get('item_id')
        if item_id and record_lookup:
            item = record_lookup(str(item_id), owner)
            context = {**context, 'topic_id': str(item_id), 'item': {k: item.get(k) for k in ('id','title','text','url','author','uid','price','note') if item.get(k) is not None}}
        category = data.get('category', 'product_research' if 'price' in context.get('item', {}) else 'content_analysis')
        purposes = {'content_analysis':'content','product_research':'research','comment_analysis':'comment'}
        if category not in purposes: raise ValueError('不支持的用途')
        purpose = purposes[category]
        message_id = data.get('message_id') or data.get('request_id')
        if not isinstance(message_id, str) or not 8 <= len(message_id) <= 160:
            raise ValueError('请提供稳定的唯一消息 ID')
        channel = client()
        previous = saved(owner, purpose) or {}
        identity = bind(channel, owner, purpose, data.get('agent_id') or previous.get('agent_id'))
        result = channel.send(owner, message_id, prompt, data.get('images', []), category,
                               str(data.get('conversation_id') or ('item:' + str(item_id) if item_id else '')),
                               context, data.get('reply_to', ''), data.get('new_task', False),
                               surface='comment' if category == 'comment_analysis' or channel.source == 'zhihu' else 'content',
                               event_type='comment.analysis_requested' if category == 'comment_analysis' or channel.source == 'zhihu' else 'content.analysis_requested',
                               route_id=identity['route_id'])
        event_id = result.get('id') or result.get('event_id')
        if not event_id: raise ValueError('Channel 未返回任务标识')
        try: record = service.record('channel-task', event_id, owner)
        except LookupError:
            record = service.put('channel-task', {'id': event_id, 'purpose': purpose,
                       'item_id': str(item_id or ''), 'message_id': message_id, **identity}, owner)
        return {**result, 'agent_snapshot': {k: record.get(k) for k in identity}}, 202
    def status(event_id):
        owner = account(); result = client().status(event_id, owner)
        try: record = service.record('channel-task', event_id, owner)
        except LookupError: record = {}
        return {**result, 'agent_snapshot': {k: record.get(k) for k in ('agent_id','agent_name','route_id','route_version')}}
    app.add_url_rule('/api/channel/meta', 'channel_meta', channel_meta)
    app.add_url_rule('/api/channel/catalog', 'channel_catalog', catalog)
    app.add_url_rule('/api/channel/bindings', 'channel_bindings', bindings, methods=['POST'])
    app.add_url_rule('/api/channel/history', 'channel_history', history)
    app.add_url_rule('/api/channel/messages', 'channel_submit', submit, methods=['POST'])
    app.add_url_rule('/api/channel/messages/<event_id>', 'channel_status', status)
