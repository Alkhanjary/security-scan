/* security-scan dashboard.
 *
 * Every value that reaches the DOM from a scan result goes through esc() or
 * textContent. Findings carry attacker-influenced content — the evidence line
 * is a verbatim slice of whatever file/page was scanned — so building this
 * with innerHTML + raw interpolation would make "scan a hostile repo" a
 * stored-XSS vector against the person reading the report.
 */
(function () {
  'use strict';

  // ------------------------------------------------------------ helpers
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function $(id) { return document.getElementById(id); }

  function toast(msg, kind) {
    var wrap = $('toast-wrap');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'toast-wrap';
      wrap.className = 'toast-wrap';
      document.body.appendChild(wrap);
    }
    var el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = msg;
    wrap.appendChild(el);
    setTimeout(function () { el.remove(); }, 4200);
  }

  function api(path, opts) {
    return fetch(path, opts).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) throw new Error(data.error || ('Request failed (' + res.status + ')'));
        return data;
      });
    });
  }

  function fmtTime(ts) {
    var d = new Date(ts * 1000);
    return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  var SEVERITIES = ['critical', 'high', 'medium', 'low'];

  function isDismissed(f) { return f.ai_verdict === 'false_positive'; }

  // ---------------------------------------------------------- tab switch
  var tabButtons = document.querySelectorAll('#tab-switch .seg-option');
  function showTab(tab) {
    tabButtons.forEach(function (b) { b.classList.toggle('active', b.dataset.tab === tab); });
    $('tab-scan').hidden = tab !== 'scan';
    $('tab-analysis').hidden = tab !== 'analysis';
    $('tab-history').hidden = tab !== 'history';
    if (tab === 'history') loadHistory();
  }
  tabButtons.forEach(function (btn) {
    btn.addEventListener('click', function () { showTab(btn.dataset.tab); });
  });

  // -------------------------------------------------------- source panels
  document.querySelectorAll('input[name="source"]').forEach(function (radio) {
    radio.addEventListener('change', function () {
      $('src-local').hidden = radio.value !== 'local';
      $('src-upload').hidden = radio.value !== 'upload';
      $('src-remote').hidden = radio.value !== 'remote';
      if (radio.value === 'remote') {
        $('opt-code').checked = false;
        syncScanTypePanels();
      }
    });
  });

  function currentSource() {
    var checked = document.querySelector('input[name="source"]:checked');
    return checked ? checked.value : 'local';
  }

  // ------------------------------------------------------ scan type panels
  function syncScanTypePanels() {
    $('opt-web-panel').hidden = !$('opt-web').checked;
    $('opt-network-panel').hidden = !$('opt-network').checked;
  }
  ['opt-code', 'opt-web', 'opt-network'].forEach(function (id) {
    $(id).addEventListener('change', syncScanTypePanels);
  });
  syncScanTypePanels();

  // -------------------------------------------------------- folder picker
  var fpCurrent = null;
  function openPicker() { $('folder-picker').hidden = false; loadFolder($('local-path').value.trim() || ''); }
  function closePicker() { $('folder-picker').hidden = true; }

  function loadFolder(path) {
    api('/api/browse?path=' + encodeURIComponent(path)).then(function (data) {
      fpCurrent = data.path;
      $('fp-current').textContent = data.path || 'Pick a starting point';
      $('fp-selected').textContent = data.path || '';
      $('fp-up').disabled = !data.parent;
      var list = $('fp-list');
      list.innerHTML = '';
      var rows = (data.shortcuts || []).concat(data.entries || []);
      if (!rows.length) {
        var empty = document.createElement('div');
        empty.className = 'hint';
        empty.style.padding = '10px';
        empty.textContent = 'No sub-folders here.';
        list.appendChild(empty);
        return;
      }
      rows.forEach(function (entry) {
        var row = document.createElement('div');
        row.className = 'fp-row' + (entry.is_project ? ' is-project' : '');
        var icon = document.createElement('span');
        icon.className = 'fp-icon';
        icon.textContent = entry.is_project ? '◈' : '▸';
        var name = document.createElement('span');
        name.textContent = entry.name;
        row.appendChild(icon);
        row.appendChild(name);
        if (entry.is_project) {
          var badge = document.createElement('span');
          badge.className = 'fp-badge';
          badge.textContent = 'project';
          row.appendChild(badge);
        }
        row.addEventListener('click', function () { loadFolder(entry.path); });
        list.appendChild(row);
      });
    }).catch(function (e) { toast(e.message, 'error'); });
  }

  $('browse-btn').addEventListener('click', openPicker);
  $('fp-close').addEventListener('click', closePicker);
  $('fp-up').addEventListener('click', function () {
    if (!fpCurrent) return;
    var parts = fpCurrent.replace(/[\\/]+$/, '').split(/[\\/]/);
    parts.pop();
    loadFolder(parts.join('\\') || '');
  });
  $('fp-use').addEventListener('click', function () {
    if (fpCurrent) { $('local-path').value = fpCurrent; closePicker(); }
  });

  // -------------------------------------------------------------- upload
  var uploadedFiles = [];
  $('folder-input').addEventListener('change', function (e) {
    var files = Array.from(e.target.files || []);
    $('upload-count').textContent = 'Reading ' + files.length + ' file(s)…';
    var readable = files.filter(function (f) { return f.size < 2000000; });
    Promise.all(readable.map(function (f) {
      return f.text().then(function (content) {
        return { path: f.webkitRelativePath || f.name, content: content };
      }).catch(function () { return null; });
    })).then(function (results) {
      uploadedFiles = results.filter(Boolean);
      $('upload-count').textContent = uploadedFiles.length + ' file(s) ready to scan';
    });
  });

  // ---------------------------------------------------------- run a scan
  var pollTimer = null;
  var currentJobId = null;
  var logLines = [];
  var logShown = 0;
  var lastRunTarget = '';
  var lastRunTypes = [];
  var lastParsed = 0;

  function selectedScanTypes() {
    var types = [];
    if ($('opt-code').checked) types.push('code');
    if ($('opt-web').checked) types.push('web');
    if ($('opt-network').checked) types.push('network');
    return types;
  }

  function setRunning(running) {
    $('run-btn').disabled = running;
    $('cancel-btn').hidden = !running;
    $('run-btn').textContent = running ? 'Scanning…' : 'Run scan';
  }

  $('run-btn').addEventListener('click', function () {
    var types = selectedScanTypes();
    if (!types.length) { toast('Pick at least one scan type.', 'error'); return; }

    var source = currentSource();
    var payload = {
      scan_types: types,
      ai: $('opt-ai').checked,
      include_test_files: $('opt-include-tests').checked,
      fail_on: $('opt-fail-on').value,
      auto_build: $('opt-autobuild').checked,
      url: $('web-url').value.trim(),
      net_target: $('net-target').value.trim(),
      net_ports: $('net-ports').value.trim()
    };
    if (source === 'local') payload.local_path = $('local-path').value.trim();
    if (source === 'upload') payload.files = uploadedFiles;

    lastRunTypes = types;
    lastRunTarget = payload.local_path ||
      (source === 'upload' ? '(uploaded folder)' : '') ||
      payload.url || payload.net_target || '';

    logLines = [];
    logShown = 0;
    lastParsed = 0;
    resetProgressState();
    $('log-content').textContent = '';
    $('log-card').hidden = false;
    $('results').hidden = true;
    $('analysis-empty').hidden = false;
    $('status-text').textContent = '';
    $('status-text').className = 'status-text';
    setProgress(null, 'Starting scan…');
    setRunning(true);

    api('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (data) {
      currentJobId = data.job_id;
      poll();
    }).catch(function (e) {
      setRunning(false);
      $('status-text').textContent = e.message;
      $('status-text').className = 'status-text error';
      toast(e.message, 'error');
    });
  });

  $('cancel-btn').addEventListener('click', function () {
    if (!currentJobId) return;
    api('/api/scan/cancel/' + currentJobId, { method: 'POST' })
      .then(function () { toast('Cancelling scan…'); })
      .catch(function (e) { toast(e.message, 'error'); });
  });

  $('log-toggle').addEventListener('click', function () {
    var el = $('log-content');
    el.hidden = !el.hidden;
    $('log-toggle').textContent = el.hidden ? 'Show log' : 'Hide log';
  });

  function poll() {
    if (!currentJobId) return;
    api('/api/scan/status/' + currentJobId + '?since=' + logShown).then(function (data) {
      if (data.log && data.log.length) {
        logLines = logLines.concat(data.log);
        logShown = data.log_total;
        var el = $('log-content');
        el.textContent = logLines.join('\n');
        el.scrollTop = el.scrollHeight;
        updateProgressFromLog();
      }

      if (data.status === 'running') {
        pollTimer = setTimeout(poll, 900);
        return;
      }

      setRunning(false);
      if (data.status === 'done') {
        setProgress(100, 'Scan complete in ' + data.elapsed + 's');
        $('status-text').textContent = 'Scan complete in ' + data.elapsed + 's — see the Analysis tab.';
        $('status-text').className = 'status-text ok';
        renderResult(data.result, data.record_id, {
          target: lastRunTarget,
          when: 'just now',
          scanTypes: lastRunTypes.join('/')
        });
        renderCategoryChart(data.result.findings || []);
        showTab('analysis');   // land on the results, not the form you just submitted
        toast('Scan complete — ' + (data.result.findings || []).length + ' finding(s)', 'success');
      } else if (data.status === 'cancelled') {
        setProgress(0, 'Cancelled');
        $('status-text').textContent = 'Scan cancelled.';
        $('status-text').className = 'status-text';
      } else {
        setProgress(0, 'Failed');
        $('status-text').textContent = data.error || 'Scan failed.';
        $('status-text').className = 'status-text error';
        toast(data.error || 'Scan failed', 'error');
      }
    }).catch(function (e) {
      setRunning(false);
      $('status-text').textContent = e.message;
      $('status-text').className = 'status-text error';
    });
  }

  function setProgress(pct, label) {
    var fill = $('progress-fill');
    if (pct === null) {
      fill.classList.add('indeterminate');
      fill.style.width = '35%';
    } else {
      fill.classList.remove('indeterminate');
      fill.style.width = pct + '%';
    }
    $('progress-label').textContent = label;
  }

  // The scanner counts files up ("[regex N] <file>") but never prints a
  // total, so the backend injects "[[progress-total]] N" before starting.
  // With AI on the run has two long phases, so the bar weights them rather
  // than snapping back to 0% when verification begins.
  var REGEX_WEIGHT = 0.4;   // when AI is also running
  var progressTotal = null;
  var regexDone = 0;
  var aiDone = 0;
  var aiTotal = 0;
  var phaseLabel = 'Scanning…';

  function resetProgressState() {
    progressTotal = null; regexDone = 0; aiDone = 0; aiTotal = 0;
    phaseLabel = 'Starting scan…';
  }

  function updateProgressFromLog() {
    var aiEnabled = $('opt-ai').checked;

    logLines.slice(lastParsed).forEach(function (line) {
      var m;
      if ((m = /^\[\[progress-total\]\] (\d+)/.exec(line))) { progressTotal = +m[1]; return; }
      if ((m = /^\[regex (\d+)\]/.exec(line))) { regexDone = +m[1]; phaseLabel = 'Scanning files'; return; }
      if ((m = /^\[(\d+)\/(\d+)\] AI reviewing/.exec(line))) {
        aiDone = +m[1]; aiTotal = +m[2]; phaseLabel = 'AI reviewing'; return;
      }
      if (/Generating AI risk summary/.test(line)) { phaseLabel = 'Writing risk summary'; return; }
      if (/Starting web scan/.test(line)) { phaseLabel = 'Web scan'; return; }
      if (/Starting network scan/.test(line)) { phaseLabel = 'Network scan'; return; }
    });
    lastParsed = logLines.length;

    var regexPct = progressTotal ? Math.min(regexDone / progressTotal, 1) : null;
    var aiPct = aiTotal ? Math.min(aiDone / aiTotal, 1) : null;

    var pct = null;
    if (aiEnabled) {
      if (aiPct !== null) {
        pct = (REGEX_WEIGHT + (1 - REGEX_WEIGHT) * aiPct) * 100;
      } else if (regexPct !== null) {
        pct = regexPct * REGEX_WEIGHT * 100;
      }
    } else if (regexPct !== null) {
      pct = regexPct * 100;
    }

    if (pct === null) { setProgress(null, phaseLabel + '…'); return; }

    pct = Math.max(1, Math.min(99, Math.round(pct)));
    var detail = phaseLabel === 'AI reviewing'
      ? ' (' + aiDone + '/' + aiTotal + ')'
      : (progressTotal && phaseLabel === 'Scanning files' ? ' (' + regexDone + '/' + progressTotal + ')' : '');
    setProgress(pct, pct + '% · ' + phaseLabel + detail);
  }

  // -------------------------------------------------------------- results
  var allFindings = [];
  var currentRecordId = null;
  var filterSeverity = null;
  var filterCategory = null;
  var filterBucket = 'actionable';
  var searchQuery = '';
  var selectedIndex = -1;

  function renderResult(result, recordId, meta) {
    allFindings = (result.findings || []).slice();
    currentRecordId = recordId;
    filterSeverity = null;
    filterCategory = null;
    filterBucket = 'actionable';
    searchQuery = '';
    selectedIndex = -1;
    $('finding-search').value = '';
    $('results').hidden = false;
    $('analysis-empty').hidden = true;

    meta = meta || {};
    $('analysis-target').textContent = meta.target || '';
    var bits = [];
    if (meta.when) bits.push(meta.when);
    if (meta.scanTypes) bits.push(meta.scanTypes);
    bits.push(result.ai_used ? 'AI verification on' : 'AI verification off');
    if (result.fail_on && result.fail_on !== 'none') {
      bits.push(result.exit_code === 0 ? 'gate: pass' : 'gate: fail');
    }
    $('analysis-meta').textContent = bits.join(' · ');

    renderMetrics(result);
    renderAiSummary(result);
    renderExport(recordId);
    renderReviewTabs();
    renderSeverityFilter();
    renderCategoryFilter();
    renderList();
  }

  function bucketFindings(bucket) {
    if (bucket === 'dismissed') return allFindings.filter(isDismissed);
    return allFindings.filter(function (f) { return !isDismissed(f); });
  }

  function renderMetrics(result) {
    var actionable = bucketFindings('actionable');
    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    actionable.forEach(function (f) {
      var s = (f.severity || '').toLowerCase();
      if (counts[s] !== undefined) counts[s]++;
    });
    var el = $('metrics');
    el.innerHTML = '';
    var cards = [
      { label: 'Files scanned', value: result.files_scanned || 0, cls: '' },
      { label: 'Total findings', value: actionable.length, cls: '' },
      { label: 'Critical', value: counts.critical, cls: 'sev-critical' },
      { label: 'High', value: counts.high, cls: 'sev-high' },
      { label: 'Medium', value: counts.medium, cls: 'sev-medium' },
      { label: 'Low', value: counts.low, cls: 'sev-low' }
    ];
    // Only show a pass/fail verdict when a gate threshold was actually set —
    // with gating off ("none") every scan would read PASS, which says nothing.
    if (result.fail_on && result.fail_on !== 'none') {
      cards.push({
        label: 'Gate (' + result.fail_on + ')',
        value: result.exit_code === 0 ? 'PASS' : 'FAIL',
        cls: result.exit_code === 0 ? '' : 'sev-critical'
      });
    }
    cards.forEach(function (c) {
      var d = document.createElement('div');
      d.className = 'metric ' + c.cls;
      var v = document.createElement('div');
      v.className = 'metric-value';
      v.textContent = c.value;
      var l = document.createElement('div');
      l.className = 'metric-label';
      l.textContent = c.label;
      d.appendChild(v); d.appendChild(l);
      el.appendChild(d);
    });
  }

  function renderAiSummary(result) {
    var card = $('ai-summary-card');
    if (!result.ai_used || (!result.ai_risk_summary && !result.ai_recommendations)) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    $('ai-summary').textContent = result.ai_risk_summary || '';
    var recs = $('ai-recs');
    recs.innerHTML = '';
    if (result.ai_recommendations && result.ai_recommendations.length) {
      var ul = document.createElement('ul');
      result.ai_recommendations.forEach(function (r) {
        var li = document.createElement('li');
        li.textContent = r;
        ul.appendChild(li);
      });
      recs.appendChild(ul);
    }
  }

  var exportFormats = null;

  function renderExport(recordId) {
    var row = $('export-row');
    row.innerHTML = '';
    if (!recordId) return;

    function paint(formats) {
      row.innerHTML = '';
      formats.forEach(function (f) {
        if (f.available) {
          var a = document.createElement('a');
          a.className = 'btn btn-xs btn-outline';
          a.href = '/api/scan/report/' + encodeURIComponent(recordId) + '?format=' + f.format;
          a.textContent = f.label;
          a.setAttribute('download', '');
          row.appendChild(a);
        } else {
          var b = document.createElement('button');
          b.className = 'btn btn-xs btn-outline';
          b.type = 'button';
          b.disabled = true;
          b.textContent = f.label;
          b.title = f.label + ' export ' + f.reason;
          row.appendChild(b);
        }
      });
    }

    if (exportFormats) { paint(exportFormats); return; }
    api('/api/scan/formats').then(function (data) {
      exportFormats = data.formats || [];
      paint(exportFormats);
    }).catch(function () {
      exportFormats = [{ format: 'markdown', label: 'Markdown', available: true }];
      paint(exportFormats);
    });
  }

  function renderReviewTabs() {
    var el = $('review-tabs');
    el.innerHTML = '';
    var counts = {
      actionable: bucketFindings('actionable').length,
      dismissed: bucketFindings('dismissed').length
    };
    [['actionable', 'Actionable'], ['dismissed', 'Dismissed by AI']].forEach(function (pair) {
      if (pair[0] === 'dismissed' && !counts.dismissed) return;
      var b = document.createElement('button');
      b.className = 'pill' + (filterBucket === pair[0] ? ' active' : '');
      b.type = 'button';
      b.textContent = pair[1] + ' (' + counts[pair[0]] + ')';
      b.addEventListener('click', function () {
        filterBucket = pair[0];
        selectedIndex = -1;
        renderReviewTabs(); renderSeverityFilter(); renderCategoryFilter(); renderList();
      });
      el.appendChild(b);
    });
  }

  function renderSeverityFilter() {
    var el = $('severity-filter');
    el.innerHTML = '';
    var pool = bucketFindings(filterBucket);
    var counts = {};
    pool.forEach(function (f) {
      var s = (f.severity || '').toLowerCase();
      counts[s] = (counts[s] || 0) + 1;
    });
    var all = document.createElement('button');
    all.className = 'pill' + (filterSeverity === null ? ' active' : '');
    all.type = 'button';
    all.textContent = 'All (' + pool.length + ')';
    all.addEventListener('click', function () { filterSeverity = null; selectedIndex = -1; renderSeverityFilter(); renderList(); });
    el.appendChild(all);
    SEVERITIES.forEach(function (sev) {
      if (!counts[sev]) return;
      var b = document.createElement('button');
      b.className = 'pill sev-' + sev + (filterSeverity === sev ? ' active' : '');
      b.type = 'button';
      b.textContent = sev + ' (' + counts[sev] + ')';
      b.addEventListener('click', function () {
        filterSeverity = filterSeverity === sev ? null : sev;
        selectedIndex = -1;
        renderSeverityFilter(); renderList();
      });
      el.appendChild(b);
    });
  }

  function renderCategoryFilter() {
    var el = $('type-filter');
    el.innerHTML = '';
    var pool = bucketFindings(filterBucket);
    var counts = {};
    pool.forEach(function (f) {
      var c = f.category || f.rule || 'other';
      counts[c] = (counts[c] || 0) + 1;
    });
    var cats = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; }).slice(0, 8);
    if (cats.length < 2) return;
    cats.forEach(function (cat) {
      var b = document.createElement('button');
      b.className = 'pill' + (filterCategory === cat ? ' active' : '');
      b.type = 'button';
      b.textContent = cat + ' (' + counts[cat] + ')';
      b.addEventListener('click', function () {
        filterCategory = filterCategory === cat ? null : cat;
        selectedIndex = -1;
        renderCategoryFilter(); renderList();
      });
      el.appendChild(b);
    });
  }

  $('finding-search').addEventListener('input', function (e) {
    searchQuery = e.target.value.toLowerCase();
    selectedIndex = -1;
    renderList();
  });

  function visibleFindings() {
    return bucketFindings(filterBucket).filter(function (f) {
      if (filterSeverity && (f.severity || '').toLowerCase() !== filterSeverity) return false;
      if (filterCategory && (f.category || f.rule) !== filterCategory) return false;
      if (searchQuery) {
        var hay = ((f.description || '') + ' ' + (f.file || '') + ' ' + (f.evidence || '') + ' ' + (f.rule || '')).toLowerCase();
        if (hay.indexOf(searchQuery) === -1) return false;
      }
      return true;
    }).sort(function (a, b) {
      return SEVERITIES.indexOf((a.severity || '').toLowerCase()) - SEVERITIES.indexOf((b.severity || '').toLowerCase());
    });
  }

  function aiTag(f) {
    if (f.ai_verdict === 'true_positive') return { cls: 'ai-confirmed', text: 'AI-confirmed' };
    if (f.ai_verdict === 'false_positive') return { cls: 'ai-dismissed', text: 'AI: false positive' };
    if (f.source === 'ai') return { cls: 'ai-found', text: 'AI-found' };
    if (f.likely_test_fixture) return { cls: 'ai-dismissed', text: 'test fixture' };
    return null;
  }

  function renderList() {
    var list = $('finding-list');
    list.innerHTML = '';
    var items = visibleFindings();
    if (!items.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No findings match these filters.';
      list.appendChild(empty);
      $('finding-detail').innerHTML = '<div class="detail-empty">Select a finding to see the detail.</div>';
      return;
    }
    items.forEach(function (f, i) {
      var sev = (f.severity || 'low').toLowerCase();
      var row = document.createElement('div');
      row.className = 'finding-row sev-' + sev + (i === selectedIndex ? ' selected' : '');

      var top = document.createElement('div');
      top.className = 'finding-row-top';
      var badge = document.createElement('span');
      badge.className = 'sev-badge sev-' + sev;
      badge.textContent = sev;
      top.appendChild(badge);
      var tag = aiTag(f);
      if (tag) {
        var t = document.createElement('span');
        t.className = 'tag ' + tag.cls;
        t.textContent = tag.text;
        top.appendChild(t);
      }
      row.appendChild(top);

      var desc = document.createElement('div');
      desc.className = 'finding-row-desc';
      desc.textContent = f.description || f.rule || 'Finding';
      row.appendChild(desc);

      var loc = document.createElement('div');
      loc.className = 'finding-row-loc';
      loc.textContent = (f.file || '') + (f.line ? ':' + f.line : '');
      row.appendChild(loc);

      row.addEventListener('click', function () {
        selectedIndex = i;
        renderList();
        renderDetail(f);
      });
      list.appendChild(row);
    });
    if (selectedIndex >= 0 && items[selectedIndex]) renderDetail(items[selectedIndex]);
  }

  function renderDetail(f) {
    var el = $('finding-detail');
    el.innerHTML = '';
    var sev = (f.severity || 'low').toLowerCase();

    var head = document.createElement('div');
    head.className = 'detail-head';
    var badge = document.createElement('span');
    badge.className = 'sev-badge sev-' + sev;
    badge.textContent = sev;
    head.appendChild(badge);
    var tag = aiTag(f);
    if (tag) {
      var t = document.createElement('span');
      t.className = 'tag ' + tag.cls;
      t.textContent = tag.text;
      head.appendChild(t);
    }
    if (f.scan_type) {
      var st = document.createElement('span');
      st.className = 'tag';
      st.textContent = f.scan_type;
      head.appendChild(st);
    }
    el.appendChild(head);

    var title = document.createElement('div');
    title.className = 'detail-title';
    title.textContent = f.description || f.rule || 'Finding';
    el.appendChild(title);

    var loc = document.createElement('div');
    loc.className = 'detail-loc';
    loc.textContent = (f.file || '') + (f.line ? ':' + f.line : '');
    el.appendChild(loc);

    if (f.evidence) {
      var ev = document.createElement('pre');
      ev.className = 'detail-evidence';
      ev.textContent = f.evidence;   // textContent, never innerHTML — this is scanned content
      el.appendChild(ev);
    }

    [['Impact', f.impact], ['Fix', f.improvement], ['AI note', f.ai_reason], ['Rule', f.rule]].forEach(function (pair) {
      if (!pair[1]) return;
      var sec = document.createElement('div');
      sec.className = 'detail-section' + (pair[0] === 'Fix' ? ' detail-fix' : '');
      var lab = document.createElement('div');
      lab.className = 'detail-section-label';
      lab.textContent = pair[0];
      var p = document.createElement('p');
      p.textContent = pair[1];
      sec.appendChild(lab); sec.appendChild(p);
      el.appendChild(sec);
    });
  }

  // -------------------------------------------------------------- history
  var trendChart = null;
  var categoryChart = null;
  var compareSelection = [];

  function chartColors() {
    var styles = getComputedStyle(document.documentElement);
    return {
      grid: styles.getPropertyValue('--border').trim(),
      text: styles.getPropertyValue('--text-muted').trim(),
      accent: styles.getPropertyValue('--accent').trim()
    };
  }

  function loadHistory() {
    api('/api/scan/history?limit=50').then(function (data) {
      renderHistoryList(data.items || []);
      renderTrendChart(data.items || []);
    }).catch(function (e) { toast(e.message, 'error'); });
  }

  function renderHistoryList(items) {
    var el = $('history-list');
    el.innerHTML = '';
    if (!items.length) {
      var hint = document.createElement('span');
      hint.className = 'hint';
      hint.textContent = 'No scans saved yet. Run one from the Scan tab.';
      el.appendChild(hint);
      return;
    }
    items.forEach(function (item) {
      var row = document.createElement('div');
      row.className = 'history-row';

      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.addEventListener('change', function () {
        if (cb.checked) compareSelection.push(item.id);
        else compareSelection = compareSelection.filter(function (id) { return id !== item.id; });
        updateCompareBar();
      });
      row.appendChild(cb);

      var main = document.createElement('div');
      main.className = 'history-main';
      var name = document.createElement('div');
      name.className = 'history-name';
      name.textContent = item.name || item.target;
      var meta = document.createElement('div');
      meta.className = 'history-meta';
      meta.textContent = fmtTime(item.timestamp) + ' · ' + (item.scan_types || []).join('/') +
        ' · ' + item.files_scanned + ' file(s)' + (item.ai_used ? ' · AI' : '');
      main.appendChild(name); main.appendChild(meta);
      row.appendChild(main);

      if (item.history_delta) {
        var d = document.createElement('span');
        var net = item.history_delta.new - item.history_delta.fixed;
        d.className = 'delta ' + (net > 0 ? 'up' : (net < 0 ? 'down' : ''));
        d.textContent = net > 0 ? ('+' + item.history_delta.new + ' new') :
          (item.history_delta.fixed ? ('-' + item.history_delta.fixed + ' fixed') : 'no change');
        row.appendChild(d);
      }

      var counts = document.createElement('div');
      counts.className = 'history-counts';
      SEVERITIES.forEach(function (sev) {
        if (!item.counts[sev]) return;
        var chip = document.createElement('span');
        chip.className = 'count-chip sev-' + sev;
        chip.textContent = item.counts[sev] + ' ' + sev[0].toUpperCase();
        counts.appendChild(chip);
      });
      row.appendChild(counts);

      var actions = document.createElement('div');
      actions.className = 'history-actions';

      var openBtn = document.createElement('button');
      openBtn.className = 'btn btn-xs btn-outline';
      openBtn.type = 'button';
      openBtn.textContent = 'Open';
      openBtn.addEventListener('click', function () { openRecord(item.id); });
      actions.appendChild(openBtn);

      var renameBtn = document.createElement('button');
      renameBtn.className = 'btn btn-xs btn-outline';
      renameBtn.type = 'button';
      renameBtn.textContent = 'Rename';
      renameBtn.addEventListener('click', function () {
        var newName = prompt('Name this scan:', item.name || '');
        if (newName === null) return;
        api('/api/scan/history/' + item.id, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: newName })
        }).then(function () { loadHistory(); toast('Renamed.', 'success'); })
          .catch(function (e) { toast(e.message, 'error'); });
      });
      actions.appendChild(renameBtn);

      var delBtn = document.createElement('button');
      delBtn.className = 'btn btn-xs btn-outline';
      delBtn.type = 'button';
      delBtn.textContent = 'Delete';
      delBtn.addEventListener('click', function () {
        if (!confirm('Delete this saved scan?')) return;
        api('/api/scan/history/' + item.id, { method: 'DELETE' })
          .then(function () { loadHistory(); toast('Deleted.', 'success'); })
          .catch(function (e) { toast(e.message, 'error'); });
      });
      actions.appendChild(delBtn);

      row.appendChild(actions);
      el.appendChild(row);
    });
  }

  function openRecord(recordId) {
    api('/api/scan/history/' + recordId).then(function (record) {
      renderResult({
        findings: record.findings,
        files_scanned: record.files_scanned,
        exit_code: record.exit_code,
        fail_on: record.fail_on,
        ai_used: record.ai_used,
        ai_risk_summary: record.ai_risk_summary,
        ai_recommendations: record.ai_recommendations
      }, record.id, {
        target: record.name ? (record.name + ' — ' + record.target) : record.target,
        when: fmtTime(record.timestamp),
        scanTypes: (record.scan_types || []).join('/')
      });
      renderCategoryChart(record.findings || []);
      showTab('analysis');
    }).catch(function (e) { toast(e.message, 'error'); });
  }

  function updateCompareBar() {
    var bar = $('compare-bar');
    if (compareSelection.length === 0) { bar.hidden = true; return; }
    bar.hidden = false;
    $('compare-label').textContent = compareSelection.length === 1
      ? '1 scan selected — pick one more to compare'
      : compareSelection.length + ' scans selected';
    $('compare-run').disabled = compareSelection.length !== 2;
  }

  $('compare-clear').addEventListener('click', function () {
    compareSelection = [];
    document.querySelectorAll('#history-list input[type="checkbox"]').forEach(function (cb) { cb.checked = false; });
    updateCompareBar();
    $('compare-results').innerHTML = '';
  });

  $('compare-run').addEventListener('click', function () {
    if (compareSelection.length !== 2) return;
    api('/api/scan/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ a: compareSelection[0], b: compareSelection[1] })
    }).then(renderCompare).catch(function (e) { toast(e.message, 'error'); });
  });

  function renderCompare(data) {
    var el = $('compare-results');
    el.innerHTML = '';
    var card = document.createElement('div');
    card.className = 'card';

    var title = document.createElement('div');
    title.className = 'card-title';
    title.textContent = 'Comparison';
    card.appendChild(title);

    var desc = document.createElement('div');
    desc.className = 'card-desc';
    desc.textContent = data.a.name + ' (' + fmtTime(data.a.timestamp) + ')  →  ' +
      data.b.name + ' (' + fmtTime(data.b.timestamp) + ')';
    card.appendChild(desc);

    [['New findings', data.new], ['Fixed findings', data.fixed], ['Still present', data.persisting]].forEach(function (pair) {
      var group = document.createElement('div');
      group.className = 'compare-group';
      var h = document.createElement('h4');
      h.textContent = pair[0] + ' (' + pair[1].length + ')';
      group.appendChild(h);
      if (!pair[1].length) {
        var none = document.createElement('div');
        none.className = 'hint';
        none.textContent = 'None.';
        group.appendChild(none);
      } else {
        pair[1].slice(0, 25).forEach(function (f) {
          var row = document.createElement('div');
          row.className = 'finding-row sev-' + (f.severity || 'low').toLowerCase();
          var d = document.createElement('div');
          d.className = 'finding-row-desc';
          d.textContent = f.description || f.rule;
          var l = document.createElement('div');
          l.className = 'finding-row-loc';
          l.textContent = (f.file || '') + (f.line ? ':' + f.line : '');
          row.appendChild(d); row.appendChild(l);
          group.appendChild(row);
        });
      }
      card.appendChild(group);
    });

    el.appendChild(card);
  }

  function renderTrendChart(items) {
    var canvas = $('trend-chart');
    if (!canvas || typeof Chart === 'undefined') return;
    var ordered = items.slice().reverse().slice(-15);
    var colors = chartColors();
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: ordered.map(function (i) { return fmtTime(i.timestamp); }),
        datasets: SEVERITIES.map(function (sev) {
          var css = getComputedStyle(document.documentElement).getPropertyValue('--sev-' + sev).trim();
          return {
            label: sev,
            data: ordered.map(function (i) { return i.counts[sev] || 0; }),
            borderColor: css,
            backgroundColor: css,
            tension: 0.3,
            pointRadius: 3
          };
        })
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: colors.text, boxWidth: 12, font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: colors.text, font: { size: 10 } }, grid: { color: colors.grid } },
          y: { beginAtZero: true, ticks: { color: colors.text, font: { size: 10 }, precision: 0 }, grid: { color: colors.grid } }
        }
      }
    });
  }

  function renderCategoryChart(findings) {
    var canvas = $('category-chart');
    if (!canvas || typeof Chart === 'undefined') return;
    var counts = {};
    findings.filter(function (f) { return !isDismissed(f); }).forEach(function (f) {
      var c = f.category || f.rule || 'other';
      counts[c] = (counts[c] || 0) + 1;
    });
    var cats = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; }).slice(0, 8);
    $('category-empty').hidden = cats.length > 0;
    if (categoryChart) categoryChart.destroy();
    if (!cats.length) return;
    var colors = chartColors();
    categoryChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: cats,
        datasets: [{ label: 'findings', data: cats.map(function (c) { return counts[c]; }), backgroundColor: colors.accent }]
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { color: colors.text, font: { size: 10 }, precision: 0 }, grid: { color: colors.grid } },
          y: { ticks: { color: colors.text, font: { size: 10 } }, grid: { display: false } }
        }
      }
    });
  }

  // Charts read CSS variables at build time, so rebuild them on theme change.
  var themeBtn = $('theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      setTimeout(function () {
        if (!$('tab-history').hidden) loadHistory();
      }, 60);
    });
  }
})();
