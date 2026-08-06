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

  // Whether a finding is set aside rather than actionable. Mirrors
  // scanner.py's policy exactly: an explicit AI verdict wins either way, and
  // failing that a test/fixture finding is set aside unless this scan asked
  // for those to count.
  var includeTestFiles = false;
  function isDismissed(f) {
    if (f.ai_verdict === 'false_positive') return true;
    if (f.ai_verdict === 'true_positive') return false;
    return !!f.likely_test_fixture && !includeTestFiles;
  }

  // ---------------------------------------------------------- tab switch
  var tabButtons = document.querySelectorAll('#tab-switch .seg-option');
  function showTab(tab) {
    tabButtons.forEach(function (b) {
      var on = b.dataset.tab === tab;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
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
      syncSourceConstraints();
      syncScanTypePanels();
    });
  });

  function currentSource() {
    var checked = document.querySelector('input[name="source"]:checked');
    return checked ? checked.value : 'local';
  }

  // A code scan needs files. With "URL / host only" there are none, so the
  // Code option is turned off and locked rather than left tickable — hitting
  // Run and being told "code scan needs a source" is a dead end the form
  // should never have allowed in the first place.
  function syncSourceConstraints() {
    var remote = currentSource() === 'remote';
    var codeInput = $('opt-code');
    var codeCard = codeInput.closest('.choice');
    if (remote && codeInput.checked) codeInput.checked = false;
    codeInput.disabled = remote;
    if (codeCard) {
      codeCard.classList.toggle('is-disabled', remote);
      codeCard.title = remote
        ? 'A code scan needs files — pick a local folder or upload one.'
        : '';
    }
    // With no code scan available, make sure something is selected so Run
    // isn't silently a no-op.
    if (remote && !$('opt-web').checked && !$('opt-network').checked) {
      $('opt-web').checked = true;
    }
  }

  // ------------------------------------------------------ scan type panels
  function syncScanTypePanels() {
    $('opt-web-panel').hidden = !$('opt-web').checked;
    $('opt-network-panel').hidden = !$('opt-network').checked;
    // Auto-build and a target URL are mutually exclusive — building the
    // source folder is precisely the case where you don't have a URL yet.
    var building = $('opt-autobuild').checked;
    $('web-url-field').hidden = building;
    if (building) $('web-url').value = '';
  }
  ['opt-code', 'opt-web', 'opt-network', 'opt-autobuild'].forEach(function (id) {
    $(id).addEventListener('change', syncScanTypePanels);
  });
  syncSourceConstraints();
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
  var filterScanType = null;
  var filterBucket = 'actionable';
  var searchQuery = '';
  var selectedIndex = -1;
  var currentGroups = [];

  function renderResult(result, recordId, meta) {
    allFindings = (result.findings || []).slice();
    includeTestFiles = !!result.include_test_files;
    currentRecordId = recordId;
    filterSeverity = null;
    filterCategory = null;
    filterScanType = null;
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
    $('analysis-meta').textContent = bits.join(' · ');

    // Remember which scan is on screen so a reload doesn't drop you back to
    // an empty Analysis tab — results live in history, not just in memory.
    if (recordId) {
      try { localStorage.setItem('ss-last-record', recordId); } catch (e) { /* private mode */ }
    }

    renderMetrics(result);
    renderAiSummary(result);
    renderExport(recordId);
    renderReviewTabs();
    renderSeverityFilter();
    renderScanTypeFilter();
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
    cards.forEach(function (c) {
      var d = document.createElement('div');
      // A zero count is dimmed rather than dropped — an explicit "0 critical"
      // is information; a missing tile just looks like the scan didn't check.
      d.className = 'metric ' + c.cls + (c.value === 0 ? ' is-zero' : '');
      var v = document.createElement('div');
      v.className = 'metric-value';
      v.textContent = c.value;
      var l = document.createElement('div');
      l.className = 'metric-label';
      l.textContent = c.label;
      d.appendChild(v); d.appendChild(l);
      el.appendChild(d);
    });

    renderSeverityBar(counts, actionable.length);
  }

  // Proportion at a glance, before any of the numbers are read.
  function renderSeverityBar(counts, total) {
    var bar = $('sev-bar');
    bar.innerHTML = '';
    if (!total) { bar.hidden = true; return; }
    bar.hidden = false;
    SEVERITIES.forEach(function (sev) {
      if (!counts[sev]) return;
      var seg = document.createElement('div');
      seg.className = 'sev-bar-seg sev-' + sev;
      seg.style.width = (counts[sev] / total * 100) + '%';
      seg.title = counts[sev] + ' ' + sev;
      bar.appendChild(seg);
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
    [['actionable', 'Actionable'], ['dismissed', 'Set aside']].forEach(function (pair) {
      if (pair[0] === 'dismissed' && !counts.dismissed) return;
      var b = document.createElement('button');
      b.className = 'pill' + (filterBucket === pair[0] ? ' active' : '');
      b.type = 'button';
      b.textContent = pair[1] + ' (' + counts[pair[0]] + ')';
      b.addEventListener('click', function () {
        filterBucket = pair[0];
        selectedIndex = -1;
        renderReviewTabs(); renderScanTypeFilter(); renderSeverityFilter(); renderCategoryFilter(); renderList();
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

  // Only meaningful when a run covered more than one scan type — with a
  // single type every finding carries the same tag and the row is noise.
  function renderScanTypeFilter() {
    var el = $('scan-type-filter');
    el.innerHTML = '';
    var pool = bucketFindings(filterBucket);
    var counts = {};
    pool.forEach(function (f) {
      var t = f.scan_type || 'code';
      counts[t] = (counts[t] || 0) + 1;
    });
    var types = Object.keys(counts);
    if (types.length < 2) { filterScanType = null; return; }
    types.forEach(function (t) {
      var b = document.createElement('button');
      b.className = 'pill' + (filterScanType === t ? ' active' : '');
      b.type = 'button';
      b.textContent = t + ' (' + counts[t] + ')';
      b.addEventListener('click', function () {
        filterScanType = filterScanType === t ? null : t;
        selectedIndex = -1;
        renderScanTypeFilter(); renderList();
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
      if (filterScanType && (f.scan_type || 'code') !== filterScanType) return false;
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

  // The same rule firing on ten lines of one file is one problem to fix, not
  // ten rows to scroll past — collapse repeats into a single row that keeps
  // every occurrence's line number rather than dropping any of them.
  function groupFindings(items) {
    var order = [];
    var byKey = {};
    items.forEach(function (f) {
      var key = (f.rule || '') + ' ' + (f.file || '') + ' ' + (f.severity || '');
      if (!byKey[key]) {
        byKey[key] = { primary: f, occurrences: [] };
        order.push(key);
      }
      byKey[key].occurrences.push(f);
    });
    return order.map(function (k) { return byKey[k]; });
  }

  function renderList() {
    var list = $('finding-list');
    list.innerHTML = '';
    var groups = groupFindings(visibleFindings());
    currentGroups = groups;

    if (!groups.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No findings match these filters.';
      list.appendChild(empty);
      var detail = $('finding-detail');
      detail.innerHTML = '';
      var de = document.createElement('div');
      de.className = 'detail-empty';
      de.textContent = 'Select a finding to see the detail.';
      detail.appendChild(de);
      return;
    }

    groups.forEach(function (group, i) {
      var f = group.primary;
      var sev = (f.severity || 'low').toLowerCase();
      var row = document.createElement('div');
      row.className = 'finding-row sev-' + sev + (i === selectedIndex ? ' selected' : '');
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
      row.setAttribute('aria-pressed', i === selectedIndex ? 'true' : 'false');

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
      if (group.occurrences.length > 1) {
        var count = document.createElement('span');
        count.className = 'tag occurrence-count';
        count.textContent = '×' + group.occurrences.length;
        top.appendChild(count);
      }
      row.appendChild(top);

      var desc = document.createElement('div');
      desc.className = 'finding-row-desc';
      desc.textContent = f.description || f.rule || 'Finding';
      row.appendChild(desc);

      var loc = document.createElement('div');
      loc.className = 'finding-row-loc';
      loc.textContent = group.occurrences.length > 1
        ? (f.file || '') + ' · ' + group.occurrences.length + ' lines'
        : (f.file || '') + (f.line ? ':' + f.line : '');
      row.appendChild(loc);

      function select() {
        selectedIndex = i;
        renderList();
        var el = $('finding-list').children[i];
        if (el) el.focus();
      }
      row.addEventListener('click', select);
      row.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); }
      });
      list.appendChild(row);
    });

    if (selectedIndex >= 0 && groups[selectedIndex]) renderDetail(groups[selectedIndex]);
  }

  // ↑/↓ and j/k move through the list without leaving the keyboard.
  $('finding-list').addEventListener('keydown', function (e) {
    var step = 0;
    if (e.key === 'ArrowDown' || e.key === 'j') step = 1;
    else if (e.key === 'ArrowUp' || e.key === 'k') step = -1;
    else return;
    e.preventDefault();
    var next = Math.max(0, Math.min(currentGroups.length - 1, selectedIndex + step));
    if (next === selectedIndex) return;
    selectedIndex = next;
    renderList();
    var el = $('finding-list').children[selectedIndex];
    if (el) el.focus();
  });

  function renderDetail(group) {
    var f = group.primary;
    var occurrences = group.occurrences;
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
    loc.textContent = occurrences.length > 1
      ? (f.file || '') + ' — ' + occurrences.length + ' occurrences'
      : (f.file || '') + (f.line ? ':' + f.line : '');
    el.appendChild(loc);

    // Every occurrence is listed with its own line and evidence — grouping is
    // a way to read the list, not a reason to hide any of the hits.
    occurrences.forEach(function (occ) {
      if (!occ.evidence && !occ.line) return;
      if (occurrences.length > 1) {
        var lineLabel = document.createElement('div');
        lineLabel.className = 'occurrence-line';
        lineLabel.textContent = 'line ' + (occ.line || '?');
        el.appendChild(lineLabel);
      }
      if (occ.evidence) {
        var ev = document.createElement('pre');
        ev.className = 'detail-evidence';
        ev.textContent = occ.evidence;  // textContent, never innerHTML — this is scanned content
        el.appendChild(ev);
      }
    });

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

    // Most findings end up pasted into a ticket or a message — make that one
    // click instead of a manual selection across five separate fields.
    var copy = document.createElement('button');
    copy.className = 'btn btn-xs btn-outline';
    copy.type = 'button';
    copy.textContent = 'Copy finding';
    copy.addEventListener('click', function () {
      var lines = [
        '[' + sev.toUpperCase() + '] ' + (f.description || f.rule || ''),
        'Location: ' + (f.file || '') +
          (occurrences.length > 1
            ? ' (lines ' + occurrences.map(function (o) { return o.line; }).join(', ') + ')'
            : (f.line ? ':' + f.line : ''))
      ];
      occurrences.forEach(function (o) {
        if (o.evidence) lines.push('  ' + (o.line ? o.line + ': ' : '') + o.evidence);
      });
      if (f.impact) lines.push('Impact: ' + f.impact);
      if (f.improvement) lines.push('Fix: ' + f.improvement);
      if (f.ai_reason) lines.push('AI note: ' + f.ai_reason);
      if (f.rule) lines.push('Rule: ' + f.rule);

      navigator.clipboard.writeText(lines.join('\n')).then(function () {
        copy.textContent = 'Copied';
        setTimeout(function () { copy.textContent = 'Copy finding'; }, 1500);
      }, function () {
        toast('Could not copy — your browser blocked clipboard access.', 'error');
      });
    });
    el.appendChild(copy);
  }

  // -------------------------------------------------------------- history
  var trendChart = null;
  var categoryChart = null;
  var compareSelection = [];

  function chartColors() {
    var styles = getComputedStyle(document.documentElement);
    return {
      grid: styles.getPropertyValue('--border-soft').trim(),
      text: styles.getPropertyValue('--text-muted').trim(),
      accent: styles.getPropertyValue('--accent').trim(),
      mono: styles.getPropertyValue('--font-mono').trim()
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

      // Rename edits in place rather than opening a browser prompt() — a
      // native dialog looks nothing like the rest of the page and blocks it.
      var renameBtn = document.createElement('button');
      renameBtn.className = 'btn btn-xs btn-outline';
      renameBtn.type = 'button';
      renameBtn.textContent = 'Rename';
      renameBtn.addEventListener('click', function () {
        if (main.querySelector('.rename-input')) return;
        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'input input-sm rename-input';
        input.value = item.name || '';
        input.placeholder = 'Name this scan';
        name.replaceWith(input);
        input.focus();
        input.select();

        var done = false;
        function commit(save) {
          if (done) return;
          done = true;
          if (!save) { input.replaceWith(name); return; }
          var value = input.value.trim();
          api('/api/scan/history/' + item.id, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: value })
          }).then(function () { loadHistory(); toast('Renamed.', 'success'); })
            .catch(function (e) { toast(e.message, 'error'); input.replaceWith(name); });
        }
        input.addEventListener('keydown', function (e) {
          if (e.key === 'Enter') { e.preventDefault(); commit(true); }
          else if (e.key === 'Escape') { e.preventDefault(); commit(false); }
        });
        input.addEventListener('blur', function () { commit(true); });
      });
      actions.appendChild(renameBtn);

      // Delete asks for confirmation on the row itself instead of a browser
      // confirm() — same reason, and it keeps the row you're acting on visible.
      var delBtn = document.createElement('button');
      delBtn.className = 'btn btn-xs btn-outline';
      delBtn.type = 'button';
      delBtn.textContent = 'Delete';
      delBtn.addEventListener('click', function () {
        if (row.classList.contains('confirming')) return;
        row.classList.add('confirming');
        actions.innerHTML = '';
        var ask = document.createElement('span');
        ask.className = 'confirm-text';
        ask.textContent = 'Delete this scan?';
        var yes = document.createElement('button');
        yes.className = 'btn btn-xs btn-danger-outline';
        yes.type = 'button';
        yes.textContent = 'Delete';
        var no = document.createElement('button');
        no.className = 'btn btn-xs btn-outline';
        no.type = 'button';
        no.textContent = 'Cancel';

        // Re-render rather than restoring markup: rebuilding the row is what
        // reattaches its listeners.
        no.addEventListener('click', function () { renderHistoryList(items); });
        yes.addEventListener('click', function () {
          api('/api/scan/history/' + item.id, { method: 'DELETE' })
            .then(function () { loadHistory(); toast('Scan deleted.', 'success'); })
            .catch(function (e) { toast(e.message, 'error'); });
        });

        actions.appendChild(ask);
        actions.appendChild(yes);
        actions.appendChild(no);
        yes.focus();
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
        include_test_files: record.include_test_files,
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

  // ---- remember scan settings -------------------------------------------
  // Retyping a long folder path on every visit is the kind of friction that
  // makes a tool feel disposable. Only the form inputs are stored, never
  // findings — those live in history on disk.
  var SETTINGS_KEY = 'ss-settings';

  function saveSettings() {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify({
        source: currentSource(),
        local_path: $('local-path').value,
        code: $('opt-code').checked,
        web: $('opt-web').checked,
        network: $('opt-network').checked,
        url: $('web-url').value,
        net_target: $('net-target').value,
        net_ports: $('net-ports').value,
        ai: $('opt-ai').checked,
        include_tests: $('opt-include-tests').checked,
        autobuild: $('opt-autobuild').checked
      }));
    } catch (e) { /* private mode — settings just won't persist */ }
  }

  function restoreSettings() {
    var raw = null;
    try { raw = localStorage.getItem(SETTINGS_KEY); } catch (e) { return; }
    if (!raw) return;
    var s;
    try { s = JSON.parse(raw); } catch (e) { return; }

    var radio = document.querySelector('input[name="source"][value="' + s.source + '"]');
    if (radio) {
      radio.checked = true;
      $('src-local').hidden = s.source !== 'local';
      $('src-upload').hidden = s.source !== 'upload';
      $('src-remote').hidden = s.source !== 'remote';
    }
    $('local-path').value = s.local_path || '';
    $('opt-code').checked = !!s.code;
    $('opt-web').checked = !!s.web;
    $('opt-network').checked = !!s.network;
    $('web-url').value = s.url || '';
    $('net-target').value = s.net_target || '';
    $('net-ports').value = s.net_ports || '';
    if (typeof s.ai === 'boolean') $('opt-ai').checked = s.ai;
    $('opt-include-tests').checked = !!s.include_tests;
    $('opt-autobuild').checked = !!s.autobuild;
    syncScanTypePanels();
  }

  restoreSettings();
  syncSourceConstraints();
  ['local-path', 'web-url', 'net-target', 'net-ports', 'opt-code', 'opt-web',
    'opt-network', 'opt-ai', 'opt-include-tests', 'opt-autobuild'].forEach(function (id) {
    $(id).addEventListener('change', saveSettings);
  });
  document.querySelectorAll('input[name="source"]').forEach(function (r) {
    r.addEventListener('change', saveSettings);
  });

  // ---- restore the last scan on load -------------------------------------
  // Every scan is persisted, so a page reload should come back to what you
  // were looking at rather than an empty Analysis tab.
  (function restoreLastScan() {
    var saved = null;
    try { saved = localStorage.getItem('ss-last-record'); } catch (e) { /* private mode */ }

    function load(id) {
      return api('/api/scan/history/' + id).then(function (record) {
        renderResult({
          findings: record.findings,
          files_scanned: record.files_scanned,
          exit_code: record.exit_code,
          include_test_files: record.include_test_files,
          ai_used: record.ai_used,
          ai_risk_summary: record.ai_risk_summary,
          ai_recommendations: record.ai_recommendations
        }, record.id, {
          target: record.name ? (record.name + ' — ' + record.target) : record.target,
          when: fmtTime(record.timestamp),
          scanTypes: (record.scan_types || []).join('/')
        });
        renderCategoryChart(record.findings || []);
        // Stay on Scan: restoring context shouldn't hijack where you landed.
        showTab('scan');
      });
    }

    if (saved) {
      load(saved).catch(function () {
        try { localStorage.removeItem('ss-last-record'); } catch (e) { /* ignore */ }
      });
      return;
    }
    api('/api/scan/history?limit=1').then(function (data) {
      var latest = (data.items || [])[0];
      if (latest) load(latest.id).catch(function () { /* nothing to restore */ });
    }).catch(function () { /* no history yet */ });
  })();

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
