
const $ = id => document.getElementById(id);
const transfers = new Map();
let connected = false;
let chatSubmitting = false;
const history = [];
function renderMessages() {
    const selected = $('to').value;
    const visible = history.filter(item => item.channel === selected);
    const nodes = visible.map(item => {
        if (item.transfer) return item.transfer.row;
        const row = document.createElement('article');
        row.className = 'message-row ' + item.kind;
        if (item.peer) {
            const meta = document.createElement('div'); meta.className = 'message-meta';
            const name = document.createElement('strong'); name.textContent = item.peer;
            const time = document.createElement('time'); time.textContent = item.time;
            meta.append(name, time); row.append(meta);
        }
        const text = document.createElement('p'); text.textContent = item.text; row.append(text);
        return row;
    });
    if (!nodes.length) {
        const empty = document.createElement('div'); empty.className = 'empty-chat';
        const title = document.createElement('h3'); title.textContent = 'A conversation starts here.';
        const hint = document.createElement('p'); hint.textContent = selected === '*' ? 'Say hello to everyone in your workspace.' : 'Send a message or share a file with ' + selected + '.';
        empty.append(title, hint); nodes.push(empty);
    }
    $('messages').replaceChildren(...nodes);
    $('messages').scrollTop = $('messages').scrollHeight;
    $('chat-title').textContent = selected === '*' ? 'Everyone' : 'Chat with ' + selected;
    $('chat-subtitle').textContent = selected === '*' ? 'Messages shared with everyone online.' : 'A private conversation in your network.';
}
function remember(item) {
    history.push(item);
    if (history.length > 500) {
        const removed = history.shift();
        if (removed.transfer) transfers.delete(removed.transfer.key);
    }
}
function line(text, kind='notice', peer='', channel=$('to').value) {
    remember({text,kind,peer,channel,time:new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})});
    if (channel === $('to').value) renderMessages();
}
function connection(status) {
    connected = status === 'connected';
    $('connection').textContent = connected ? 'Connected' : 'Disconnected';
    $('send-chat').disabled = !connected || chatSubmitting;
    $('send-file').disabled = !connected;
}
async function req(path, data) {
    const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    const result = await response.json();
    if (response.status === 401) location.replace('/login');
    if (!response.ok) throw Error(result.error || 'Request failed');
    return result;
}
async function sendChat() {
    if (!connected || chatSubmitting) return;
    const text = $('message').value;
    if (!text.trim()) return;
    const recipient = $('to').value;
    chatSubmitting = true;
    $('send-chat').disabled = true;
    try {
        await req('/chat', {to:recipient, text});
        if ($('message').value === text) $('message').value = '';
    } catch (error) { line('ERROR: ' + error.message, 'notice', '', recipient); }
    finally {
        chatSubmitting = false;
        $('send-chat').disabled = !connected;
    }
}
async function sendFile() {
    if (!connected) return;
    const file = $('file').files[0];
    if (!file) return;
    const recipient = $('to').value;
    if (file.size > 25*1024*1024) { line('File exceeds 25 MiB'); return; }
    try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const parts = [];
        for (let offset=0; offset<bytes.length; offset+=32768) {
            parts.push(String.fromCharCode(...bytes.subarray(offset, offset+32768)));
        }
        $('status').textContent = 'Uploading to local client...';
        await req('/file', {to:recipient, filename:file.name, data:btoa(parts.join(''))});
        if ($('to').value === recipient) $('status').textContent = 'File queued for transfer';
    } catch (error) { line('ERROR: ' + error.message, 'notice', '', recipient); if ($('to').value === recipient) $('status').textContent = 'File could not be queued'; }
}
function transfer(event, direction, phase) {
    const key = JSON.stringify([direction, event.sender_session || event.from || '', event.transfer]);
    let item = transfers.get(key);
    if (!item) {
        const channel = direction === 'receive' ? (event.channel === '*' ? '*' : event.from) : (event.channel || event.to);
        if (!channel) return null;
        const peer = direction === 'receive' ? event.from : 'You';
        const row = document.createElement('article');
        row.className = 'message-row file-message ' + (direction === 'receive' ? 'incoming' : 'own');
        row.setAttribute('aria-label', 'File message');
        const meta = document.createElement('div'); meta.className = 'message-meta';
        const name = document.createElement('strong'); name.textContent = peer;
        const time = document.createElement('time'); time.textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
        meta.append(name, time);
        const title = document.createElement('p'); title.className = 'file-name';
        const progress = document.createElement('progress'); progress.max = 100; progress.value = 0;
        const label = document.createElement('p'); label.className = 'file-state'; label.setAttribute('role', 'status');
        const location = document.createElement('p'); location.className = 'file-location';
        row.append(meta, title, progress, label, location);
        item = {key,row,title,progress,label,location,channel,done:false,filename:event.filename || 'File'};
        transfers.set(key, item);
        remember({channel,transfer:item});
        if (channel === $('to').value) renderMessages();
    }
    if (item.done) return item;
    if (event.filename) item.filename = event.filename;
    item.title.textContent = item.filename;
    const current = direction === 'receive' ? event.received : event.sent;
    if (Number.isFinite(current) && event.total > 0) {
        item.progress.value = Math.min(100, 100*current/event.total);
        item.label.textContent = Math.floor(item.progress.value) + '% · ' + current + '/' + event.total + ' chunks';
        if (current === event.total) item.label.textContent += direction === 'receive' ? ' · Checking and saving file...' : ' · Waiting for recipient confirmation...';
    } else if (phase === 'start') item.label.textContent = direction === 'receive' ? 'Receiving file…' : 'Sending file…';
    if (phase === 'complete') {
        item.progress.value = 100;
        item.label.textContent = direction === 'receive' ? 'Received and saved · SHA-256 verified' : 'Delivered to recipient(s)';
        if (direction === 'receive' && event.path) item.location.textContent = 'Saved to ' + event.path;
        item.done = true;
    } else if (phase === 'failed') {
        item.label.textContent = 'Failed: ' + (event.reason || event.message || 'Transfer failed');
        item.done = true;
    }
    return item;
}
function receiveEvent(event) {
    if (event.type === 'chat') line(event.text, 'incoming', event.from, event.channel === '*' ? '*' : event.from);
    else if (event.type === 'sent') line(event.text, 'own', 'You', event.to);
    else if (event.type === 'connection') connection(event.status);
    else if (event.type === 'file_receiving') transfer(event, 'receive', 'start');
    else if (event.type === 'file_sending') transfer(event, 'send', 'start');
    else if (event.type === 'file_progress') transfer(event, 'receive', 'progress');
    else if (event.type === 'file_send_progress') transfer(event, 'send', 'progress');
    else if (event.type === 'file_complete') {
        const item = transfer(event, 'receive', 'complete');
        if (item?.channel === $('to').value) $('status').textContent = 'File verified and saved';
    } else if (event.type === 'file_sent') {
        const item = transfer(event, 'send', 'complete');
        if (item?.channel === $('to').value) $('status').textContent = 'File delivered to recipient(s)';
    } else if (event.type === 'file_send_failed') transfer(event, 'send', 'failed');
    else if (event.type === 'error') {
        if (event.transfer && event.from) transfer(event, 'receive', 'failed');
        else line('ERROR: ' + event.message);
    }
}
async function poll() {
    try {
        const response = await fetch('/events');
        if (response.status === 401) { location.replace('/login'); return; }
        if (!response.ok) throw Error('Could not read updates');
        const snapshot = await response.json();
        $('self').textContent = snapshot.self;
        $('avatar').textContent = (snapshot.self || '?').slice(0,1).toUpperCase();
        $('online-count').textContent = snapshot.names.length + ' online';
        $('conversation-count').textContent = snapshot.names.length + ' online';
        $('online').textContent = snapshot.names.length ? snapshot.names.join(', ') : 'No active users';
        const old = $('to').value;
        $('to').replaceChildren(new Option('Everyone', '*'));
        for (const name of snapshot.names) if (name !== snapshot.self) $('to').add(new Option(name, name));
        if ([...$('to').options].some(option => option.value === old)) $('to').value = old;
        else {
            $('to').add(new Option(old + ' (offline)', old));
            $('to').value = old;
        }
        for (const event of snapshot.events) receiveEvent(event);
        connection(snapshot.status);
        if (old !== $('to').value) renderMessages();
    } catch (error) {
        connection('disconnected');
        $('status').textContent = 'Connection error: ' + error.message;
    } finally { setTimeout(poll, 800); }
}
poll();
$('message').addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.isComposing) {
        event.preventDefault();
        if (!event.repeat) sendChat();
    }
});

$('to').addEventListener('change', renderMessages);
$('chat-form').addEventListener('submit', event => { event.preventDefault(); sendChat(); });
$('send-file').addEventListener('click', sendFile);
$('logout').addEventListener('click', async () => {
    $('logout').disabled = true;
    try { await req('/auth/logout', {}); location.replace('/login'); }
    catch(error) { $('status').textContent = error.message; $('logout').disabled = false; }
});
if (window.matchMedia('(max-width: 640px)').matches) $('to').size = 1;

renderMessages();
