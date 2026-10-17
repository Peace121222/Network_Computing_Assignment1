
const $ = id => document.getElementById(id);
const transfers = new Map();
let connected = false;
let chatSubmitting = false;
function line(text) {
    $('messages').textContent += text + '\n';
    $('messages').scrollTop = $('messages').scrollHeight;
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
    if (!response.ok) throw Error(result.error || 'Request failed');
    return result;
}
async function sendChat() {
    if (!connected || chatSubmitting) return;
    const text = $('message').value;
    if (!text.trim()) return;
    const recipient = $('to').value;
    // Claim the submission before awaiting HTTP so repeated clicks/Enter cannot
    // create distinct packet IDs for the same pending input.
    chatSubmitting = true;
    $('send-chat').disabled = true;
    try {
        await req('/chat', {to:recipient, text});
        if ($('message').value === text) $('message').value = '';
    } catch (error) { line('ERROR: ' + error.message); }
    finally {
        chatSubmitting = false;
        $('send-chat').disabled = !connected;
    }
}
async function sendFile() {
    if (!connected) return;
    const file = $('file').files[0];
    if (!file) return;
    if (file.size > 25*1024*1024) { line('File exceeds 25 MiB'); return; }
    try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const parts = [];
        for (let offset=0; offset<bytes.length; offset+=32768) {
            parts.push(String.fromCharCode(...bytes.subarray(offset, offset+32768)));
        }
        $('status').textContent = 'Uploading to local client...';
        await req('/file', {to:$('to').value, filename:file.name, data:btoa(parts.join(''))});
        $('status').textContent = 'File queued for transfer';
    } catch (error) { line('ERROR: ' + error.message); $('status').textContent = 'File could not be queued'; }
}
function transfer(event, direction, phase) {
    const key = JSON.stringify([direction, event.sender_session || event.from || '', event.transfer]);
    let item = transfers.get(key);
    if (!item) {
        const row = document.createElement('div');
        row.className = 'transfer';
        const title = document.createElement('p');
        const progress = document.createElement('progress');
        progress.max = 100;
        progress.value = 0;
        const label = document.createElement('p');
        label.setAttribute('role', 'status');
        row.append(title, progress, label);
        $('transfers').append(row);
        item = {title, progress, label, done:false, filename:event.filename || 'File'};
        transfers.set(key, item);
    }
    if (item.done) return;
    const peer = direction === 'receive' ? event.from : event.to;
    item.title.textContent = (direction === 'receive' ? 'Receiving ' : 'Sending ') + item.filename + (peer ? ' · ' + peer : '');
    const current = direction === 'receive' ? event.received : event.sent;
    if (Number.isFinite(current) && event.total > 0) {
        item.progress.value = Math.min(100, 100*current/event.total);
        item.label.textContent = Math.floor(item.progress.value) + '% · ' + current + '/' + event.total + ' chunks';
        if (current === event.total) item.label.textContent += direction === 'receive' ? ' · Checking and saving file...' : ' · Waiting for recipient confirmation...';
    } else if (phase === 'start') item.label.textContent = 'Preparing transfer...';
    if (phase === 'complete') {
        item.progress.value = 100;
        item.label.textContent = direction === 'receive' ? 'Received and saved' : 'Delivered to recipient(s)';
        item.done = true;
    } else if (phase === 'failed') {
        item.label.textContent = 'Failed: ' + (event.reason || event.message || 'Transfer failed');
        item.done = true;
    }
}
function receiveEvent(event) {
    if (event.type === 'chat') line(event.from + ': ' + event.text);
    else if (event.type === 'sent') line('You → ' + event.to + ': ' + event.text);
    else if (event.type === 'connection') connection(event.status);
    else if (event.type === 'file_receiving') transfer(event, 'receive', 'start');
    else if (event.type === 'file_sending') transfer(event, 'send', 'start');
    else if (event.type === 'file_progress') transfer(event, 'receive', 'progress');
    else if (event.type === 'file_send_progress') transfer(event, 'send', 'progress');
    else if (event.type === 'file_complete') {
        transfer(event, 'receive', 'complete');
        line('File received from ' + event.from + ': ' + event.filename + ' saved to ' + event.path);
    } else if (event.type === 'file_sent') {
        transfer(event, 'send', 'complete');
        line('File delivered to ' + event.to + ': ' + event.filename);
    } else if (event.type === 'file_send_failed') transfer(event, 'send', 'failed');
    else if (event.type === 'error') {
        line('ERROR: ' + event.message);
        if (event.transfer && event.from) transfer(event, 'receive', 'failed');
    }
}
async function poll() {
    try {
        const response = await fetch('/events');
        if (!response.ok) throw Error('Could not read updates');
        const snapshot = await response.json();
        $('self').textContent = snapshot.self;
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
