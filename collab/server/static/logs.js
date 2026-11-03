const $ = id => document.getElementById(id);
let entries = [], paused = false, lastGood = null;
const expanded = new Set();

function sizeLabel(bytes) {
  if (!Number.isFinite(bytes)) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}
function activity(entry) {
  const d = entry.details || {}, user = d.user || 'User';
  const recipient = d.recipient === '*' ? 'everyone' : d.recipient;
  const target = recipient ? ` to ${recipient}` : '';
  switch (entry.event) {
    case 'server.started': return `Server started${d.peer ? ' · ' + d.peer : ''}`;
    case 'server.stopped': return 'Server stopped';
    case 'server.failed': return 'Server stopped with an error';
    case 'tcp.accepted': return `TCP connection accepted · ${d.source || d.peer || 'client'}`;
    case 'tls.established': return `TLS handshake successful · ${d.tls_version || 'TLS'}`;
    case 'connection.welcome_sent': return `Login acknowledgment (welcome) sent · ${d.destination || 'client'}`;
    case 'connection.accepted': return `Connection accepted${d.peer ? ' from ' + d.peer : ''}`;
    case 'connection.ended': return `${d.user ? user + ': ' : ''}Connection ended${d.reason ? ' · ' + d.reason : ''}`;
    case 'account.registered': return `${user} created an account`;
    case 'account.rejected': return `Account registration rejected for ${user}`;
    case 'login.succeeded': return `${user} logged in${Number.isFinite(d.online) ? ' · ' + d.online + ' online' : ''}`;
    case 'login.failed': return `Login failed for ${user}`;
    case 'login.duplicate': return `${user} is already logged in`;
    case 'auth.rate_limited': return `Too many login attempts${d.peer ? ' from ' + d.peer : ''}`;
    case 'session.closed': return `${user} ${d.reason === 'expired' ? 'timed out' : 'disconnected'}${Number.isFinite(d.online) ? ' · ' + d.online + ' online' : ''}`;
    case 'session.udp_verified': return `${user} is ready to exchange messages and files`;
    case 'chat.result': return `${user}: Message ${d.state === 'delivered' ? 'delivered' : d.state === 'rejected' ? 'rejected' : 'failed'}${target}`;
    case 'file.started': return `${user}: Sending a file${target}${sizeLabel(d.bytes) ? ' · ' + sizeLabel(d.bytes) : ''}`;
    case 'file.chunk_received': return `${user}: Received chunk ${d.index + 1}/${d.count}${target}`;
    case 'file.end_received': return `${user}: File end marker received · ${d.count} chunks accepted`;
    case 'security.encrypted': return `${user}: Encrypted ${d.message === 'chat' ? 'chat' : d.message === 'file_chunk' ? 'file chunk' : 'file control packet'} sent${target}`;
    case 'delivery.retry': return `Retrying ${d.message === 'chat' ? 'message' : 'file packet'}${target} · attempt ${d.attempt}`;
    case 'file.rejected': return `${user}: File transfer rejected${target}`;
    case 'file.result': return `${user}: File ${d.state === 'delivered' ? 'delivered' : d.state === 'rejected' ? 'transfer rejected' : 'transfer failed'}${target}`;
    case 'udp.retry_exhausted': return `Delivery timed out${target} after ${d.attempt || 'multiple'} attempts`;
    case 'worker.failed': return `Server worker failed${d.reason ? ' · ' + d.reason : ''}`;
    default: return entry.event.replaceAll('.', ' ');
  }
}
function isActivity(entry) {
  return !/^(tcp|udp|tls)\./.test(entry.event) || ['tcp.accepted','tls.established','udp.retry_exhausted'].includes(entry.event);
}
function render() {
  const query = $('search').value.trim().toLowerCase(), level = $('level').value;
  const rows = entries.filter(e => (!level || e.level === level) &&
    `${activity(e)} ${e.level}`.toLowerCase().includes(query)).slice().reverse();
  $('rows').replaceChildren(...rows.map(entry => {
    const tr = document.createElement('tr'); tr.dataset.level = entry.level;
    const time = new Date(entry.time);
    const values = [time.toLocaleTimeString([], {hour12:false}), entry.level, activity(entry)];
    values.forEach((value, index) => {
      const td = document.createElement('td'); td.textContent = value;
      if (index === 0) td.title = time.toLocaleString();
      if (index === 2) {
        const d = entry.details || {};
        const selected = {};
        for (const key of ['source','destination','tls_version','cipher','transfer','index','count','reason']) {
          if (d[key] !== undefined) selected[key] = d[key];
        }
        if (d.packet_example || d.ciphertext_hex || Object.keys(selected).length) {
          const disclosure = document.createElement('details');
          disclosure.open = expanded.has(entry.id);
          const summary = document.createElement('summary');
          summary.textContent = d.ciphertext_hex ? 'Packet & encryption details' : 'Details';
          disclosure.append(summary);
          function section(label, value) {
            const p = document.createElement('p'); p.textContent = label;
            const pre = document.createElement('pre');
            pre.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
            disclosure.append(p, pre);
          }
          if (Object.keys(selected).length) section('Connection / transfer', selected);
          if (d.packet_example) section('Actual packet structure · content redacted', d.packet_example);
          if (d.ciphertext_hex) {
            section(`${d.encryption} · ${d.ciphertext_bytes} ciphertext bytes · ${d.bytes} UDP payload bytes`,
                    d.ciphertext_hex.match(/.{1,2}/g).join(' '));
            section('Actual on-wire Fernet token · first 64 ASCII bytes', d.fernet_wire_prefix);
          }
          disclosure.addEventListener('toggle', () => {
            if (disclosure.open) expanded.add(entry.id); else expanded.delete(entry.id);
          });
          td.append(disclosure);
        }
      }
      tr.append(td);
    });
    return tr;
  }));
  $('count').textContent = `${rows.length} event${rows.length === 1 ? '' : 's'}`;
  $('empty').hidden = rows.length > 0;
  $('empty').textContent = entries.length ? 'No activity matches your filters.' : 'Waiting for server activity.';
}
async function refresh() {
  if (!paused) {
    try {
      const response = await fetch('/api/activity', {signal:AbortSignal.timeout(4000)});
      if (!response.ok) throw Error('Could not load server activity');
      const data = await response.json();
      entries = data.activity || data.events.filter(isActivity);
      const retainedIds = new Set(entries.map(entry => entry.id));
      for (const id of expanded) if (!retainedIds.has(id)) expanded.delete(id);
      lastGood = new Date().toLocaleTimeString();
      $('connection').textContent = 'Live · ' + lastGood;
      $('health').hidden = !data.dropped && !data.write_errors;
      $('health').textContent = `File log: ${data.dropped || 0} events dropped, ${data.write_errors || 0} write errors.`;
      const evicted = data.activity_evicted || 0;
      $('retention').textContent = `Latest 1,000 activity events · newest first · updates every second.${evicted ? ' ' + evicted + ' older activity events are no longer in this view.' : ''}`;
      render();
    } catch (error) {
      $('connection').textContent = 'Disconnected · retrying' + (lastGood ? ' · last update ' + lastGood : '');
    }
  }
  setTimeout(refresh, 1000);
}
$('search').addEventListener('input', render);
$('level').addEventListener('change', render);
$('pause').addEventListener('click', () => {
  paused = !paused;
  $('pause').textContent = paused ? 'Resume updates' : 'Pause updates';
  $('connection').textContent = paused ? 'Updates paused' : 'Resuming…';
});
refresh();
