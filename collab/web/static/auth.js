const $ = id => document.getElementById(id);
const signup = document.body.dataset.mode === 'signup';
let submitting = false;
async function session(){
    try {
        const response = await fetch('/session', {cache:'no-store'});
        if (!response.ok) throw Error('Could not load connection settings');
        const data = await response.json();
        if (!$('username').value) $('username').value = data.prefill || '';
        if (new URLSearchParams(location.search).get('registered')) $('auth-status').textContent = 'Account created. Log in to continue.';
    } catch(error) { $('auth-status').textContent = error.message; }
}
$('auth-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (submitting) return;
    const username = $('username').value.trim(), password = $('password').value;
    const confirmation = signup ? $('confirmation').value : undefined;
    $('auth-status').className = 'auth-status';
    if (signup && password !== confirmation) { $('auth-status').textContent = 'Passwords do not match.'; return; }
    submitting = true; $('auth-submit').disabled = true;
    $('auth-status').textContent = signup ? 'Creating your account…' : 'Connecting to your workspace…';
    try {
        const response = await fetch(signup ? '/auth/signup' : '/auth/login', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({username,password,confirmation})
        });
        const data = await response.json();
        if (!response.ok) throw Error(data.error || 'Could not complete the request');
        $('password').value = '';
        if (signup) $('confirmation').value = '';
        location.replace(data.redirect);
    } catch(error) {
        $('auth-status').className = 'auth-status error';
        $('auth-status').textContent = error.message;
    } finally { submitting = false; $('auth-submit').disabled = false; }
});
session();
