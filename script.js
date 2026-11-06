(function () {
  "use strict";

  var ROLE_CLASS = {
    PII_ADMIN: "role-admin",
    PII_ANALYST: "role-analyst",
    PII_SUPPORT: "role-support",
    PII_MARKETING: "role-marketing"
  };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function roleChip(role) {
    return '<span class="role-chip ' + (ROLE_CLASS[role] || "") + '">' + esc(role) + "</span>";
  }

  // ── SQL blocks: split sql/pii_demo_setup.sql on "-- [step:<id>]" markers ──
  function splitSteps(sql) {
    var steps = {};
    var parts = sql.split(/^-- \[step:([a-z_-]+)\]\s*$/m);
    for (var i = 1; i < parts.length; i += 2) steps[parts[i]] = parts[i + 1].trim();
    return steps;
  }

  function renderCode(el, code) {
    el.innerHTML =
      '<div class="code-bar"><span class="code-lang">SQL</span>' +
      '<button class="copy-btn" type="button">Copy</button></div>' +
      '<pre class="language-sql"><code class="language-sql"></code></pre>';
    var codeEl = el.querySelector("code");
    codeEl.textContent = code;
    if (window.Prism) Prism.highlightElement(codeEl);
    el.querySelector(".copy-btn").addEventListener("click", function () {
      var btn = this;
      copyText(code).then(function () {
        btn.textContent = "Copied!";
        btn.classList.add("copied");
        setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1800);
      });
    });
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    return Promise.resolve();
  }

  var loadErr = '<div class="code-loading">Could not load content. If you opened this file directly, serve the folder over HTTP (e.g. <code>python3 -m http.server</code>).</div>';

  fetch("sql/pii_demo_setup.sql")
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
    .then(function (sql) {
      var steps = splitSteps(sql);
      document.querySelectorAll(".code-wrap[data-step]").forEach(function (el) {
        var code = steps[el.getAttribute("data-step")];
        if (code) renderCode(el, code);
      });
    })
    .catch(function () {
      document.querySelectorAll(".code-wrap[data-step]").forEach(function (el) { el.innerHTML = loadErr; });
    });

  // ── Before vs. After tables from data/sample_results.json ──
  function cellClass(before, after) {
    if (after === "NULL") return "null";
    if (after === before) return "full";
    // Nothing left but mask characters (or a "HIDDEN" label) means fully masked
    if (/HIDDEN/.test(after) || after.replace(/[*\-@. ]/g, "") === "") return "masked";
    return "partial";
  }

  function legend() {
    return '<div class="legend"><span class="l-full">Full value</span><span class="l-partial">Partially masked</span><span class="l-masked">Fully masked / NULL</span></div>';
  }

  function matrixTable(block, roles) {
    var h = '<div class="table-scroll"><table class="results-table"><thead><tr><th>Column</th><th>Stored value</th>';
    roles.forEach(function (r) { h += "<th>" + roleChip(r) + "</th>"; });
    h += "</tr></thead><tbody>";
    block.columns.forEach(function (c) {
      h += '<tr><td class="col-name">' + esc(c.column) + '</td><td class="val before">' + esc(c.before) + "</td>";
      roles.forEach(function (r) {
        var a = c.after[r];
        h += '<td class="val ' + cellClass(c.before, a) + '">' + esc(a) + "</td>";
      });
      h += "</tr>";
    });
    return h + "</tbody></table></div>" + legend();
  }

  function rowAccessTable(ra) {
    var types = Object.keys(ra.before_by_type);
    var h = '<div class="table-scroll"><table class="results-table"><thead><tr><th>Role</th><th>Before (no policy)</th><th>After</th>';
    types.forEach(function (t) { h += "<th>" + esc(t) + "</th>"; });
    h += "</tr></thead><tbody>";
    ra.by_role.forEach(function (r) {
      h += "<tr><td>" + roleChip(r.role) + '</td><td class="val before">' + ra.total_rows + '</td><td class="val ' +
        (r.visible_rows === ra.total_rows ? "full" : "partial") + '"><strong>' + r.visible_rows + "</strong></td>";
      types.forEach(function (t) {
        var n = r.by_type[t];
        h += '<td class="val ' + (n === 0 ? "masked" : "full") + '">' + n + " / " + ra.before_by_type[t] + "</td>";
      });
      h += "</tr>";
    });
    return h + "</tbody></table></div>";
  }

  function rowSampleTable(ra, roles) {
    var h = '<div class="table-scroll"><table class="results-table"><thead><tr><th>Customer</th><th>Type</th>';
    roles.forEach(function (r) { h += "<th>" + roleChip(r) + "</th>"; });
    h += "</tr></thead><tbody>";
    ra.sample_customers.forEach(function (c) {
      h += "<tr><td>#" + c.customer_id + " " + esc(c.name) + '</td><td class="col-name">' + esc(c.customer_type) + "</td>";
      roles.forEach(function (r) {
        h += c.visible_to[r] ? '<td class="yes">✓ Visible</td>' : '<td class="no">✕ Filtered</td>';
      });
      h += "</tr>";
    });
    return h + "</tbody></table></div>";
  }

  function viewTable(v) {
    var cols = Object.keys(v.row);
    var h = '<div class="table-scroll"><table class="results-table"><thead><tr>';
    cols.forEach(function (c) { h += "<th>" + esc(c) + "</th>"; });
    h += "</tr></thead><tbody><tr>";
    cols.forEach(function (c) { h += '<td class="val">' + esc(v.row[c]) + "</td>"; });
    h += "</tr></tbody></table></div>";
    h += '<p class="legend">Not exposed by the view: ' + v.hidden_columns.map(function (c) { return "<code>" + esc(c) + "</code>"; }).join(" ") + "</p>";
    return h;
  }

  fetch("data/sample_results.json")
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function (d) {
      var render = {
        "masking": function () { return matrixTable(d.masking, d.roles); },
        "tag_masking": function () { return matrixTable(d.tag_masking, d.roles); },
        "role_testing": function () { return matrixTable(d.role_testing, d.roles); },
        "rowaccess": function () { return rowAccessTable(d.row_access); },
        "rowaccess-sample": function () { return rowSampleTable(d.row_access, d.roles); },
        "role_view": function () { return viewTable(d.role_view); }
      };
      document.querySelectorAll(".results[data-results]").forEach(function (el) {
        var fn = render[el.getAttribute("data-results")];
        if (fn) el.innerHTML = fn();
      });
    })
    .catch(function () {
      document.querySelectorAll(".results[data-results]").forEach(function (el) { el.innerHTML = loadErr; });
    });

  // ── Mobile Nav ──
  var btn = document.querySelector(".nav-hamburger");
  var links = document.querySelector(".nav-links");
  btn.addEventListener("click", function () {
    var open = links.classList.toggle("open");
    btn.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", String(open));
  });
  links.querySelectorAll("a").forEach(function (a) {
    a.addEventListener("click", function () {
      links.classList.remove("open");
      btn.classList.remove("open");
      btn.setAttribute("aria-expanded", "false");
    });
  });

  // ── Nav Scroll Shadow ──
  var nav = document.getElementById("navbar");
  window.addEventListener("scroll", function () {
    nav.classList.toggle("scrolled", window.scrollY > 10);
  }, { passive: true });

  // ── Reveal on Scroll ──
  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches && "IntersectionObserver" in window) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("visible"); observer.unobserve(e.target); }
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });
    document.querySelectorAll(".reveal").forEach(function (el) { observer.observe(el); });
  } else {
    document.querySelectorAll(".reveal").forEach(function (el) { el.classList.add("visible"); });
  }
})();
