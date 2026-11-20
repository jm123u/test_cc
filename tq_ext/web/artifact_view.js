(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const SCORE_LABEL = { notable: 'Notable', likely: 'Likely notable', '': 'Not flagged' };
  const RANK = { notable: 2, likely: 1, '': 0 };
  const jobId = new URLSearchParams(location.search).get('job') || '';
  const RENDER_LIMIT = 1000;
  const state = { view: null, current: 'notable', flaggedOnly: false, text: '', open: null };

  function show(id) {
    for (const name of ['view', 'picker', 'message', 'loading']) $(name).hidden = name !== id;
  }
  function fail(title, text) {
    $('message-title').textContent = title;
    $('message-text').textContent = text;
    show('message');
  }
  async function getJson(url) {
    const response = await fetch(url, { headers: { Accept: 'application/json' } });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    return payload;
  }

  function notableCategory() {
    const rows = [];
    for (const category of state.view.categories) {
      for (const row of category.rows) {
        if (!row.score) continue;
        rows.push({ ...row, cells: [category.name, row.cells.filter(Boolean).slice(0, 3).join(' · '), row.why[0] || ''] });
      }
    }
    rows.sort((a, b) => RANK[b.score] - RANK[a.score] || String(a.sort).localeCompare(String(b.sort)));
    return {
      id: 'notable', group: 'Review', name: 'Notable Items',
      description: 'Everything scored Notable or Likely notable, across all categories. Start here.',
      columns: ['Category', 'Item', 'Why it stands out'], mono: [], rows,
      notable: rows.filter(r => r.score === 'notable').length,
      likely: rows.filter(r => r.score === 'likely').length,
      notable_events: state.view.categories.reduce((sum, c) => sum + c.notable_events, 0),
      likely_events: state.view.categories.reduce((sum, c) => sum + c.likely_events, 0),
      truncated_rows: 0, sampled: state.view.categories.some(c => c.sampled || c.truncated_rows),
    };
  }
  function categories() {
    return [notableCategory(), ...state.view.categories];
  }
  function currentCategory() {
    return categories().find(c => c.id === state.current) || categories()[0];
  }

  function renderNav() {
    const all = categories();
    const groups = [...new Set(all.map(c => c.group))];
    $('nav').innerHTML = groups.map(group => `<div class="group"><h2>${esc(group)}</h2><ul>${all.filter(c => c.group === group).map(c => {
      const flagged = c.notable_events + c.likely_events;
      const shown = flagged > 9999 ? `${Math.round(flagged / 1000)}k` : String(flagged);
      const badge = flagged ? `<span class="badge ${c.notable_events ? 'notable' : 'likely'}" title="${c.notable_events} notable and ${c.likely_events} likely notable event(s)">${shown}</span>` : '';
      return `<li><button class="nav${c.rows.length ? '' : ' is-empty'}" type="button" data-id="${esc(c.id)}" aria-current="${c.id === state.current}"><span>${esc(c.name)}</span>${badge}</button></li>`;
    }).join('')}</ul></div>`).join('');
  }

  function eventHtml(event) {
    const meta = [
      event.source_path ? `Source: <span>${esc(event.source_path)}</span>` : '',
      event.detections ? `Detections: <span>${esc(event.detections)}</span>` : '',
      event.mitre ? `ATT&amp;CK: <span>${esc(event.mitre)}</span>` : '',
      event.event_id ? `Event: <span>${esc(event.event_id)}</span>` : '',
    ].filter(Boolean).join(' &nbsp; ');
    return `<div class="ev"><div class="ev-head"><span class="ev-time">${esc(event.timestamp || 'no timestamp')}</span><span class="pill ${event.score || 'none'}">${esc(event.severity || 'informational')}</span><span>${esc(event.summary)}</span></div>${event.raw ? `<pre>${esc(event.raw)}</pre>` : ''}<div class="ev-meta">${meta}</div></div>`;
  }
  function detailHtml(row, span) {
    const why = row.why.length
      ? `<div class="why"><b>Why this is flagged</b><ul>${row.why.map(text => `<li>${esc(text)}</li>`).join('')}</ul></div>`
      : '<p class="why">Not flagged. No detection matched this item.</p>';
    const hidden = row.event_count - row.events.length;
    const more = hidden > 0 ? `<div class="more">${hidden} more event(s) in this group are not listed here; search the timeline for the full set.</div>` : '';
    return `<tr class="detail"><td colspan="${span}">${why}${row.events.map(eventHtml).join('')}${more}</td></tr>`;
  }

  function renderTable() {
    const category = currentCategory();
    $('title').textContent = category.name;
    $('sub').textContent = category.description;
    const needle = state.text.trim().toLowerCase();
    let rows = category.rows.map((row, index) => ({ row, index }));
    const total = rows.length;
    if (state.flaggedOnly) rows = rows.filter(item => item.row.score);
    if (needle) rows = rows.filter(item => item.row.cells.join(' ').toLowerCase().includes(needle));
    const matched = rows.length;
    rows = rows.slice(0, RENDER_LIMIT);
    $('count').textContent = matched > rows.length ? `first ${rows.length} of ${matched} matching rows` : `${matched} of ${total} shown`;
    const span = category.columns.length + 1;
    $('head').innerHTML = `<tr>${category.columns.map(c => `<th>${esc(c)}</th>`).join('')}<th>Score</th></tr>`;
    $('body').innerHTML = rows.length ? rows.map(({ row, index }) => {
      const cells = row.cells.map((cell, k) => `<td${category.mono.includes(k) ? ' class="m"' : ''}>${esc(cell)}</td>`).join('');
      const open = state.open === index;
      return `<tr class="row ${row.score}" tabindex="0" data-i="${index}" aria-expanded="${open}">${cells}<td class="score"><span class="pill ${row.score || 'none'}">${SCORE_LABEL[row.score]}</span></td></tr>${open ? detailHtml(row, span) : ''}`;
    }).join('') : `<tr><td class="empty" colspan="${span}">${total ? 'No rows match the current filter.' : 'No evidence of this kind was parsed from the collection.'}</td></tr>`;
    const notes = ['Select a row to see why it was flagged, the raw records, and the source files.',
      'Scores currently follow the parser severity: critical and high are Notable, medium is Likely notable.'];
    if (matched > rows.length) notes.push(`Only the first ${RENDER_LIMIT} matching rows are drawn; narrow them with the filter box or Flagged only.`);
    if (category.sampled || category.truncated_rows) notes.push(`This category holds ${category.event_count || 'more'} event(s); the page lists at most ${state.view.row_limit} rows per category, flagged ones first. The timeline and exports hold everything.`);
    $('foot').textContent = notes.join(' ');
  }
  function render() { renderNav(); renderTable(); }

  function select(id) {
    state.current = id; state.open = null; state.text = ''; $('search').value = '';
    if (location.hash.slice(1) !== id) history.replaceState(null, '', `#${id}`);
    render();
  }
  function setFlagged(value) {
    state.flaggedOnly = value; state.open = null;
    $('f-all').setAttribute('aria-pressed', String(!value));
    $('f-flag').setAttribute('aria-pressed', String(value));
    renderTable();
  }

  async function loadView() {
    show('loading');
    try {
      state.view = await getJson(`/api/job/${encodeURIComponent(jobId)}/artifact-view`);
    } catch (error) {
      fail('This case could not be opened', error.message);
      return;
    }
    const hosts = state.view.hosts || [];
    $('host').textContent = `${hosts.slice(0, 3).join(', ')}${hosts.length > 3 ? ` +${hosts.length - 3}` : ''} · ${state.view.event_count} events`;
    const wanted = location.hash.slice(1);
    if (categories().some(c => c.id === wanted)) state.current = wanted;
    show('view');
    render();
  }
  async function loadPicker() {
    show('loading');
    $('loading-text').textContent = 'Listing completed cases.';
    let cases = [];
    try {
      cases = (await getJson('/api/cases')).cases || [];
    } catch (error) {
      fail('Cases could not be listed', error.message);
      return;
    }
    if (!cases.length) {
      fail('No completed cases yet', 'Run an analysis from the workbench first, then open the artifact view from its results.');
      return;
    }
    $('cases').innerHTML = cases.map(item => {
      const done = item.completed_at ? new Date(item.completed_at * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : '';
      const events = item.result && item.result.events != null ? item.result.events : '';
      return `<tr><td><a class="case" href="/artifacts?job=${encodeURIComponent(item.id)}">${esc(item.case_name)}</a></td><td>${esc(done)}</td><td>${esc(events)}</td></tr>`;
    }).join('');
    show('picker');
  }

  $('nav').addEventListener('click', event => { const button = event.target.closest('.nav'); if (button) select(button.dataset.id); });
  $('body').addEventListener('click', event => {
    const tr = event.target.closest('tr.row'); if (!tr) return;
    const index = Number(tr.dataset.i); state.open = state.open === index ? null : index; renderTable();
  });
  $('body').addEventListener('keydown', event => {
    if ((event.key === 'Enter' || event.key === ' ') && event.target.matches('tr.row')) { event.preventDefault(); event.target.click(); }
  });
  $('f-all').addEventListener('click', () => setFlagged(false));
  $('f-flag').addEventListener('click', () => setFlagged(true));
  $('search').addEventListener('input', event => { state.text = event.target.value; state.open = null; renderTable(); });
  window.addEventListener('hashchange', () => {
    const wanted = location.hash.slice(1);
    if (state.view && wanted !== state.current && categories().some(c => c.id === wanted)) select(wanted);
  });

  if (/^[a-f0-9]{12}$/.test(jobId)) loadView(); else loadPicker();
})();
