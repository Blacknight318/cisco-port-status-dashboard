const form = document.querySelector('#connection-form');
const button = document.querySelector('#connect-button');
const statusBox = document.querySelector('#connection-status');
const results = document.querySelector('#results');
const portsElement = document.querySelector('#ports');
const summary = document.querySelector('#summary');
const trustPanel = document.querySelector('#trust-panel');
const fingerprint = document.querySelector('#fingerprint');
let pendingPayload = null;

function setStatus(text, type = 'idle') { statusBox.textContent = text; statusBox.className = `status ${type}`; }
function clearPasswords() { form.elements.primary_password.value = ''; form.elements.secondary_password.value = ''; }
function payloadFromForm() { return Object.fromEntries(new FormData(form).entries()); }
function render(result) {
  const count = result.counts;
  summary.textContent = `${result.host} — refreshed ${new Date(result.refreshed_at).toLocaleString()} — ${result.ports.length} interfaces: ${count.active} active, ${count.disconnected} disconnected, ${count.disabled} disabled, ${count.error} error-disabled, ${count.unknown} other.`;
  portsElement.replaceChildren(...result.ports.map(port => {
    const card = document.createElement('article'); card.className = `port ${port.category}`;
    const preferredLabel = port.description || port.name;
    const fields = [[port.status, 'state'], [preferredLabel, 'description'], [port.vlan && `VLAN: ${port.vlan}`], [port.duplex && port.speed ? `${port.duplex} / ${port.speed}` : port.speed], [port.media_type, 'media']];
    card.innerHTML = `<h3></h3>`;
    card.querySelector('h3').textContent = port.interface;
    fields.filter(([value]) => value).forEach(([value, cls = 'details']) => { const item = document.createElement('div'); item.className = cls; item.textContent = value; card.append(item); });
    const macDetails = document.createElement('details');
    macDetails.className = 'mac-details';
    const macSummary = document.createElement('summary');
    const macs = port.mac_addresses || [];
    macSummary.textContent = `MAC addresses (${macs.length})`;
    macDetails.append(macSummary);
    if (macs.length) {
      const macList = document.createElement('ul');
      macList.className = 'mac-list';
      macs.forEach(entry => { const item = document.createElement('li'); item.textContent = `${entry.mac} — VLAN ${entry.vlan} (${entry.entry_type})`; macList.append(item); });
      macDetails.append(macList);
    } else {
      const empty = document.createElement('div'); empty.className = 'details'; empty.textContent = 'No MAC addresses currently learned.'; macDetails.append(empty);
    }
    card.append(macDetails);
    const linkDetails = document.createElement('details');
    const events = port.link_events || [];
    linkDetails.className = `link-details${events.length ? ' has-events' : ''}`;
    const linkSummary = document.createElement('summary');
    linkSummary.textContent = `Link events in switch log (${events.length})`;
    linkDetails.append(linkSummary);
    if (events.length) {
      const eventList = document.createElement('ul'); eventList.className = 'link-list';
      events.forEach(event => { const item = document.createElement('li'); item.textContent = `${event.timestamp} — ${event.source}: ${event.state}`; eventList.append(item); });
      linkDetails.append(eventList);
    } else {
      const empty = document.createElement('div'); empty.className = 'details'; empty.textContent = 'No matching LINK or LINEPROTO transitions in the current switch log buffer.'; linkDetails.append(empty);
    }
    card.append(linkDetails);
    return card;
  }));
  results.classList.remove('hidden');
  setStatus(`Connected to ${result.host}`, 'ok');
}
async function connect(payload) {
  button.disabled = true; setStatus('Connecting…', 'loading');
  try {
    const response = await fetch('/api/connect', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const data = await response.json();
    if (response.status === 409 && data.detail?.code === 'unknown_host_key') {
      pendingPayload = payload; fingerprint.textContent = data.detail.fingerprint; trustPanel.classList.remove('hidden'); setStatus('Host-key confirmation required', 'loading'); return;
    }
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Connection failed.');
    trustPanel.classList.add('hidden'); render(data);
  } catch (error) { setStatus(error.message, 'error'); }
  finally { clearPasswords(); button.disabled = false; }
}
form.addEventListener('submit', event => { event.preventDefault(); connect(payloadFromForm()); });
document.querySelector('#trust-button').addEventListener('click', () => { if (pendingPayload) { const approved = {...pendingPayload, trust_fingerprint:fingerprint.textContent}; trustPanel.classList.add('hidden'); connect(approved); } });
document.querySelector('#cancel-trust').addEventListener('click', () => { pendingPayload = null; trustPanel.classList.add('hidden'); clearPasswords(); setStatus('Connection cancelled', 'idle'); });
document.querySelector('#clear-button').addEventListener('click', () => { form.reset(); pendingPayload = null; results.classList.add('hidden'); trustPanel.classList.add('hidden'); setStatus('Not connected', 'idle'); });
