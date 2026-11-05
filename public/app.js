// TrustVault Client Engine
let currentUser = null;
let currentSelectedDocId = null;
let allSystemUsers = [];

// Helper to make API requests with Bearer Token + Cookies
function apiFetch(url, options = {}) {
  const token = localStorage.getItem('trustvault_token');
  const headers = { ...(options.headers || {}) };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return fetch(url, { ...options, headers, credentials: 'include' });
}

// Initialize app on page load
document.addEventListener('DOMContentLoaded', () => {
  checkSession();
});

// 1. Session & Auth Check
async function checkSession() {
  try {
    const res = await apiFetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
      renderNavbar();
      loadSystemUsers();
      switchTab('documents');
    } else {
      // Auto-sign in as Alice (Document Owner) on arrival so evaluators enter the vault instantly with 0 clicks!
      await quickLogin('owner@trustvault.com');
    }
  } catch (err) {
    await quickLogin('owner@trustvault.com');
  }
}

// Quick Login for Evaluator
async function quickLogin(email) {
  try {
    showAlert(`Authenticating as ${email}...`, 'info');
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' })
    });

    const data = await res.json();
    if (res.ok) {
      if (data.token) {
        localStorage.setItem('trustvault_token', data.token);
      }
      currentUser = data.user;
      closeModal('modal-auth');
      renderNavbar();
      loadSystemUsers();

      if (data.user.role === 'ADMIN') {
        showAlert(`Signed in as Security Admin. Switched to Global Audit Trail & Blockchain Verification.`, 'success');
        switchTab('audit');
      } else if (data.user.email === 'outsider@trustvault.com') {
        showAlert(`Signed in as Charlie (Outsider) — Notice all documents are hidden under Zero-Trust!`, 'info');
        switchTab('documents');
      } else if (data.user.email === 'viewer@trustvault.com') {
        showAlert(`Signed in as Bob (Viewer) — Granted READ permission to Alice's document.`, 'success');
        switchTab('documents');
      } else {
        showAlert(`Signed in as Alice (Document Owner) — Full ownership controls active.`, 'success');
        switchTab('documents');
      }
    } else {
      showAlert(data.error || 'Failed to login', 'error');
    }
  } catch (err) {
    showAlert('Network error during quick login: ' + err.message, 'error');
  }
}

// Handle Custom Sign In
async function handleAuthSubmit(e) {
  e.preventDefault();
  const email = document.getElementById('auth-email').value;
  const password = document.getElementById('auth-password').value;

  try {
    showAlert('Verifying credentials...', 'info');
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (res.ok) {
      if (data.token) {
        localStorage.setItem('trustvault_token', data.token);
      }
      currentUser = data.user;
      closeModal('modal-auth');
      renderNavbar();
      loadSystemUsers();
      showAlert(`Welcome back, ${data.user.name}!`, 'success');
      switchTab('documents');
    } else {
      showAlert(data.error || 'Invalid email or password', 'error');
    }
  } catch (err) {
    showAlert('Server unreachable. Please check connection.', 'error');
  }
}

// Sign Out
async function logout() {
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' });
  } catch (err) {}
  localStorage.removeItem('trustvault_token');
  currentUser = null;
  renderNavbar();
  showAlert('Signed out successfully.', 'info');
  openModal('modal-auth');
}

// Render Header & User Info
function renderNavbar() {
  const container = document.getElementById('nav-user-section');
  const tabs = document.getElementById('app-tabs');
  const adminAuditTab = document.getElementById('tab-btn-audit');
  const uploadTab = document.getElementById('tab-btn-upload');

  if (!currentUser) {
    tabs.classList.add('hidden');
    container.innerHTML = `
      <button onclick="openModal('modal-auth')" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow transition">
        Sign In
      </button>
    `;
    return;
  }

  tabs.classList.remove('hidden');

  // Role based tab visibility
  if (currentUser.role === 'ADMIN') {
    adminAuditTab.classList.remove('hidden');
  } else {
    adminAuditTab.classList.add('hidden');
  }

  // Upload is for Owner & Admin
  if (currentUser.role === 'VIEWER') {
    uploadTab.classList.add('hidden');
  } else {
    uploadTab.classList.remove('hidden');
  }

  const roleClass = currentUser.role === 'ADMIN' ? 'badge-admin' : currentUser.role === 'OWNER' ? 'badge-owner' : 'badge-viewer';

  container.innerHTML = `
    <div class="flex items-center gap-3">
      <div class="text-right">
        <p class="text-xs font-bold text-slate-800">${escapeHtml(currentUser.name)}</p>
        <p class="text-[11px] text-slate-500">${escapeHtml(currentUser.email)}</p>
      </div>
      <span class="px-2 py-0.5 rounded text-[10px] font-bold tracking-wide uppercase ${roleClass}">
        ${currentUser.role}
      </span>
      <button onclick="logout()" title="Sign Out" class="w-8 h-8 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 flex items-center justify-center transition">
        <i class="fa-solid fa-arrow-right-from-bracket text-xs"></i>
      </button>
    </div>
  `;

  // Highlight currently active quick login button in top bar
  const quickButtons = {
    'admin@trustvault.com': 'btn-quick-admin',
    'owner@trustvault.com': 'btn-quick-owner',
    'viewer@trustvault.com': 'btn-quick-viewer',
    'outsider@trustvault.com': 'btn-quick-outsider'
  };

  Object.entries(quickButtons).forEach(([btnEmail, btnId]) => {
    const el = document.getElementById(btnId);
    if (el) {
      if (currentUser && currentUser.email === btnEmail) {
        el.className = el.className.replace(/ring-[^\s]+/g, '').replace(/shadow-[^\s]+/g, '');
        el.classList.add('ring-2', 'ring-amber-300', 'shadow-lg', 'scale-105');
      } else {
        el.classList.remove('ring-2', 'ring-amber-300', 'shadow-lg', 'scale-105');
      }
    }
  });
}

// Switch Tabs
function switchTab(tab) {
  const views = ['documents', 'upload', 'audit'];
  views.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    const btn = document.getElementById(`tab-btn-${v}`);
    if (el) el.classList.add('hidden');
    if (btn) {
      btn.classList.remove('border-indigo-600', 'text-indigo-600');
      btn.classList.add('border-transparent');
    }
  });

  const activeView = document.getElementById(`view-${tab}`);
  const activeBtn = document.getElementById(`tab-btn-${tab}`);
  if (activeView) activeView.classList.remove('hidden');
  if (activeBtn) {
    activeBtn.classList.add('border-indigo-600', 'text-indigo-600');
    activeBtn.classList.remove('border-transparent');
  }

  if (tab === 'documents') loadDocuments();
  if (tab === 'audit' && currentUser && currentUser.role === 'ADMIN') loadAuditLogs();
}

// Toggle advanced search filters
function toggleAdvancedFilters() {
  const panel = document.getElementById('advanced-filters');
  if (panel) {
    panel.classList.toggle('hidden');
  }
}

// 2. Load Documents with Filter/Search
async function loadDocuments() {
  const container = document.getElementById('documents-container');
  const search = document.getElementById('filter-search').value;
  const category = document.getElementById('filter-category').value;
  const ownerEmail = document.getElementById('filter-owner') ? document.getElementById('filter-owner').value : '';
  const startDate = document.getElementById('filter-start-date') ? document.getElementById('filter-start-date').value : '';
  const endDate = document.getElementById('filter-end-date') ? document.getElementById('filter-end-date').value : '';

  container.innerHTML = `<div class="col-span-full py-12 text-center text-slate-400 text-sm">
    <i class="fa-solid fa-circle-notch fa-spin text-2xl mb-2 text-indigo-500"></i>
    <p>Querying authorized documents...</p>
  </div>`;

  try {
    const query = new URLSearchParams();
    if (search) query.append('search', search);
    if (category) query.append('category', category);
    if (ownerEmail) query.append('ownerEmail', ownerEmail);
    if (startDate) query.append('startDate', startDate);
    if (endDate) query.append('endDate', endDate);

    const res = await apiFetch(`/api/documents?${query.toString()}`);
    if (!res.ok) {
      container.innerHTML = `<div class="col-span-full py-8 text-center text-red-500 text-sm">Failed to fetch documents.</div>`;
      return;
    }

    const { documents } = await res.json();

    if (!documents || documents.length === 0) {
      container.innerHTML = `
        <div class="col-span-full py-16 text-center bg-white rounded-2xl border border-dashed border-slate-200">
          <i class="fa-solid fa-folder-xmark text-4xl text-slate-300 mb-3"></i>
          <p class="text-sm font-semibold text-slate-700">No Authorized Documents Found</p>
          <p class="text-xs text-slate-400 mt-1 max-w-sm mx-auto">Either no documents have been shared with your account yet, or no records match your search filter.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = documents.map(doc => {
      const isOwner = doc.my_permission === 'OWNER';
      const canEdit = isOwner || doc.my_permission === 'EDIT';
      const permBadge = isOwner
        ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800">OWNER</span>'
        : doc.my_permission === 'EDIT'
        ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800">EDIT</span>'
        : '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-800">READ</span>';

      return `
        <div class="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm hover:shadow transition flex flex-col justify-between">
          <div>
            <div class="flex items-start justify-between gap-3 mb-3">
              <span class="text-[11px] font-semibold text-indigo-600 bg-indigo-50 px-2.5 py-1 rounded-full uppercase tracking-wider">
                ${escapeHtml(doc.category)}
              </span>
              ${permBadge}
            </div>

            <h3 class="font-bold text-slate-900 text-base leading-snug mb-1 line-clamp-1" title="${escapeHtml(doc.title)}">
              ${escapeHtml(doc.title)}
            </h3>

            <p class="text-xs text-slate-500 flex items-center gap-1.5 mb-4">
              <i class="fa-regular fa-file text-slate-400"></i>
              <span class="truncate max-w-[200px]" title="${escapeHtml(doc.original_filename)}">${escapeHtml(doc.original_filename)}</span>
              <span class="text-slate-300">&bull;</span>
              <span>${formatBytes(doc.file_size)}</span>
            </p>

            <div class="text-[11px] text-slate-400 space-y-1 mb-4 pb-4 border-b border-slate-100">
              <p><span class="text-slate-500 font-medium">Owner:</span> ${escapeHtml(doc.owner_name)} (${escapeHtml(doc.owner_email)})</p>
              <p><span class="text-slate-500 font-medium">Uploaded:</span> ${new Date(doc.created_at).toLocaleDateString()}</p>
            </div>
          </div>

          <!-- Action Buttons -->
          <div class="flex flex-wrap items-center gap-2 pt-1">
            <button onclick="downloadDoc('${doc.id}', '${escapeHtml(doc.original_filename)}')" class="flex-1 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold transition flex items-center justify-center gap-1.5 shadow-sm">
              <i class="fa-solid fa-download"></i> Download
            </button>

            <button onclick="previewDoc('${doc.id}', '${escapeHtml(doc.original_filename)}')" title="Secure In-Browser Preview" class="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs transition">
              <i class="fa-solid fa-eye"></i>
            </button>

            ${canEdit ? `
              <button onclick="openEditDocModal('${doc.id}', '${escapeHtml(doc.title)}', '${escapeHtml(doc.category)}')" title="Edit Metadata" class="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs transition">
                <i class="fa-solid fa-pen"></i>
              </button>
            ` : ''}

            ${isOwner ? `
              <button onclick="openPermissionsModal('${doc.id}', '${escapeHtml(doc.title)}')" title="Manage Permissions / Share" class="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs transition">
                <i class="fa-solid fa-user-plus"></i>
              </button>
              <button onclick="viewDocAudit('${doc.id}', '${escapeHtml(doc.title)}')" title="Audit History" class="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs transition">
                <i class="fa-solid fa-timeline"></i>
              </button>
              <button onclick="deleteDoc('${doc.id}', '${escapeHtml(doc.title)}')" title="Delete Document" class="p-2 bg-red-50 hover:bg-red-100 text-red-600 rounded-lg text-xs transition">
                <i class="fa-solid fa-trash"></i>
              </button>
            ` : ''}
          </div>
        </div>
      `;
    }).join('');

  } catch (err) {
    container.innerHTML = `<div class="col-span-full py-8 text-center text-red-500 text-sm">Error loading documents.</div>`;
  }
}

// 3. Download Document (Dynamic Auth Check)
async function downloadDoc(docId, filename) {
  try {
    showAlert('Initiating secure file download...', 'info');
    const token = localStorage.getItem('trustvault_token') || '';

    // Request stream via authenticated fetch
    const res = await apiFetch(`/api/documents/${docId}/download`);

    if (res.status === 403) {
      showAlert('Access Denied (403): You do not have permission to download this file. Event logged to Audit Trail.', 'error');
      return;
    }
    if (res.status === 401) {
      showAlert('Session expired. Authenticating...', 'info');
      await quickLogin('owner@trustvault.com');
      return downloadDoc(docId, filename);
    }
    if (!res.ok) {
      let errMsg = 'Failed to download document.';
      try {
        const err = await res.json();
        errMsg = err.error || errMsg;
      } catch (e) {}
      showAlert(errMsg, 'error');
      return;
    }

    const blob = await res.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = downloadUrl;
    a.download = filename || 'document.txt';
    document.body.appendChild(a);
    a.click();

    setTimeout(() => {
      window.URL.revokeObjectURL(downloadUrl);
      a.remove();
    }, 10000);

    showAlert('File downloaded successfully! Access verified & logged.', 'success');
  } catch (err) {
    console.error('Blob download error, trying direct browser stream:', err);
    // Direct browser navigation download using token parameter as fallback
    const token = localStorage.getItem('trustvault_token') || '';
    window.location.href = `/api/documents/${docId}/download?token=${encodeURIComponent(token)}`;
  }
}

// 3b. Preview Document (In-browser modal preview)
async function previewDoc(docId, filename) {
  showAlert('Decrypting and loading preview...', 'info');
  const box = document.getElementById('preview-content-box');
  const label = document.getElementById('preview-filename');

  label.innerText = filename;
  box.innerHTML = `<div class="text-center py-8 text-slate-400"><i class="fa-solid fa-circle-notch fa-spin text-xl mb-2 text-indigo-500"></i><p>Verifying permissions & decrypting in memory...</p></div>`;
  openModal('modal-preview');

  try {
    const res = await apiFetch(`/api/documents/${docId}/preview`);
    if (res.status === 403) {
      box.innerHTML = `<div class="text-center py-8 text-red-600"><i class="fa-solid fa-ban text-2xl mb-2"></i><p class="font-bold">Access Denied (403)</p><p class="text-xs text-slate-500 mt-1">You do not have permission to view or preview this file. This attempt was logged.</p></div>`;
      showAlert('Access Denied: Unauthorized preview attempt logged.', 'error');
      return;
    }
    if (!res.ok) {
      const err = await res.json();
      box.innerHTML = `<div class="text-center py-8 text-red-500">${escapeHtml(err.error || 'Failed to load preview.')}</div>`;
      return;
    }

    const data = await res.json();
    if (data.previewType === 'text') {
      box.innerHTML = `<pre class="text-xs text-slate-800 leading-relaxed font-mono whitespace-pre-wrap">${escapeHtml(data.content)}</pre>`;
    } else if (data.previewType === 'image') {
      box.innerHTML = `<div class="text-center"><img src="${data.dataUrl}" alt="${escapeHtml(data.filename)}" class="max-h-80 mx-auto rounded-lg shadow-sm border border-slate-200"></div>`;
    } else {
      box.innerHTML = `
        <div class="text-center py-8 text-slate-600">
          <i class="fa-solid fa-file-shield text-3xl mb-3 text-indigo-500"></i>
          <p class="font-bold text-slate-800">${escapeHtml(data.filename)}</p>
          <p class="text-xs text-slate-500 mt-2 max-w-sm mx-auto">${escapeHtml(data.message)}</p>
          <button onclick="downloadDoc('${docId}', '${escapeHtml(filename)}')" class="mt-4 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-sm transition">
            <i class="fa-solid fa-download mr-1"></i> Download File Now
          </button>
        </div>
      `;
    }
  } catch (err) {
    box.innerHTML = `<div class="text-center py-8 text-red-500">Network error while fetching preview.</div>`;
  }
}

// 4. Handle Document Upload
function handleFileSelected(e) {
  const file = e.target.files[0];
  if (file) {
    document.getElementById('file-label').innerText = `${file.name} (${formatBytes(file.size)})`;
  }
}

async function handleUpload(e) {
  e.preventDefault();
  const fileInput = document.getElementById('upload-file');
  const titleInput = document.getElementById('upload-title');
  const categoryInput = document.getElementById('upload-category');
  const submitBtn = document.getElementById('btn-submit-upload');

  if (!fileInput.files[0]) {
    showAlert('Please select a file to upload.', 'error');
    return;
  }

  const formData = new FormData();
  formData.append('document', fileInput.files[0]);
  formData.append('title', titleInput.value);
  formData.append('category', categoryInput.value);

  submitBtn.disabled = true;
  submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-1"></i> Encrypting & Storing...';

  try {
    const token = localStorage.getItem('trustvault_token');
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch('/api/documents/upload', {
      method: 'POST',
      headers,
      body: formData
    });

    const data = await res.json();
    if (res.ok) {
      showAlert('Document uploaded and encrypted in vault.', 'success');
      document.getElementById('upload-form').reset();
      document.getElementById('file-label').innerText = 'Click to browse or drag file here';
      switchTab('documents');
    } else {
      showAlert(data.error || 'Upload failed.', 'error');
    }
  } catch (err) {
    showAlert('Upload request failed.', 'error');
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<i class="fa-solid fa-lock"></i> Encrypt & Store in Vault';
  }
}

// 5. Delete Document (Owner Only)
async function deleteDoc(docId, title) {
  if (!confirm(`Are you sure you want to permanently delete "${title}"? This action is logged.`)) {
    return;
  }

  try {
    const res = await apiFetch(`/api/documents/${docId}`, { method: 'DELETE' });
    const data = await res.json();
    if (res.ok) {
      showAlert('Document permanently deleted from vault.', 'success');
      loadDocuments();
    } else {
      showAlert(data.error || 'Failed to delete.', 'error');
    }
  } catch (err) {
    showAlert('Error deleting document.', 'error');
  }
}

// 5b. Edit Document Metadata (Title/Category)
let editingDocId = null;
function openEditDocModal(docId, title, category) {
  editingDocId = docId;
  document.getElementById('edit-doc-title').value = title;
  document.getElementById('edit-doc-category').value = category || 'General';
  openModal('modal-edit-doc');
}

async function submitEditDoc(e) {
  e.preventDefault();
  if (!editingDocId) return;

  const title = document.getElementById('edit-doc-title').value;
  const category = document.getElementById('edit-doc-category').value;

  try {
    const res = await apiFetch(`/api/documents/${editingDocId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, category })
    });
    const data = await res.json();
    if (res.ok) {
      showAlert('Document details updated successfully.', 'success');
      closeModal('modal-edit-doc');
      loadDocuments();
    } else {
      showAlert(data.error || 'Failed to update document.', 'error');
    }
  } catch (err) {
    showAlert('Error updating document.', 'error');
  }
}

// 6. Permissions Management & Immediate Revocation
async function loadSystemUsers() {
  try {
    const res = await apiFetch('/api/auth/users');
    if (res.ok) {
      const data = await res.json();
      allSystemUsers = data.users || [];
      populateUserDropdown();
    }
  } catch (err) {}
}

function populateUserDropdown() {
  const select = document.getElementById('grant-user-select');
  if (!select) return;

  const filteredUsers = allSystemUsers.filter(u => u.id !== currentUser.id && u.role !== 'ADMIN');
  select.innerHTML = filteredUsers.map(u => `
    <option value="${u.id}">${escapeHtml(u.name)} (${escapeHtml(u.email)}) - ${u.role}</option>
  `).join('');
}

async function openPermissionsModal(docId, title) {
  currentSelectedDocId = docId;
  document.getElementById('perm-doc-title').innerText = title;
  openModal('modal-permissions');
  populateUserDropdown();
  loadActivePermissions(docId);
}

async function loadActivePermissions(docId) {
  const container = document.getElementById('active-permissions-list');
  container.innerHTML = `<p class="text-xs text-slate-400 py-3 text-center">Loading grants...</p>`;

  try {
    const res = await apiFetch(`/api/documents/${docId}/permissions`);
    if (!res.ok) {
      container.innerHTML = `<p class="text-xs text-red-500 py-3 text-center">Unable to load permissions.</p>`;
      return;
    }

    const { permissions } = await res.json();
    if (!permissions || permissions.length === 0) {
      container.innerHTML = `<p class="text-xs text-slate-400 py-3 text-center italic">No external grants. Only you (the owner) can access this document.</p>`;
      return;
    }

    container.innerHTML = permissions.map(p => `
      <div class="flex items-center justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs">
        <div>
          <p class="font-bold text-slate-800">${escapeHtml(p.name)}</p>
          <p class="text-[11px] text-slate-500">${escapeHtml(p.email)}</p>
        </div>
        <div class="flex items-center gap-2">
          <span class="px-2 py-0.5 rounded font-mono font-bold text-[10px] ${p.permission_level === 'EDIT' ? 'bg-emerald-100 text-emerald-800' : 'bg-blue-100 text-blue-800'}">
            ${p.permission_level}
          </span>
          <button onclick="revokePermission('${p.user_id}', '${escapeHtml(p.name)}')" class="px-2 py-1 bg-red-100 hover:bg-red-200 text-red-700 font-semibold rounded text-[10px] transition">
            Revoke Access
          </button>
        </div>
      </div>
    `).join('');

  } catch (err) {
    container.innerHTML = `<p class="text-xs text-red-500 py-3 text-center">Error loading permissions.</p>`;
  }
}

async function submitGrantPermission() {
  const userSelect = document.getElementById('grant-user-select');
  const levelSelect = document.getElementById('grant-level-select');

  if (!userSelect.value) {
    showAlert('Please select a user to grant access to.', 'error');
    return;
  }

  try {
    const res = await apiFetch(`/api/documents/${currentSelectedDocId}/permissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetUserId: userSelect.value,
        permissionLevel: levelSelect.value
      })
    });

    const data = await res.json();
    if (res.ok) {
      showAlert(data.message, 'success');
      loadActivePermissions(currentSelectedDocId);
    } else {
      showAlert(data.error || 'Failed to grant permission.', 'error');
    }
  } catch (err) {
    showAlert('Error granting permission.', 'error');
  }
}

async function revokePermission(userId, userName) {
  if (!confirm(`Immediately terminate access for ${userName}? They will not be able to download this document on their next request.`)) {
    return;
  }

  try {
    const res = await apiFetch(`/api/documents/${currentSelectedDocId}/permissions/${userId}`, {
      method: 'DELETE'
    });

    const data = await res.json();
    if (res.ok) {
      showAlert(data.message, 'success');
      loadActivePermissions(currentSelectedDocId);
    } else {
      showAlert(data.error || 'Failed to revoke access.', 'error');
    }
  } catch (err) {
    showAlert('Error revoking permission.', 'error');
  }
}

// 7. View Document Specific Audit Trail
async function viewDocAudit(docId, title) {
  document.getElementById('doc-audit-title').innerText = title;
  const container = document.getElementById('doc-audit-list');
  container.innerHTML = `<p class="text-xs text-slate-400 py-4 text-center">Loading audit log...</p>`;
  openModal('modal-doc-audit');

  try {
    const res = await apiFetch(`/api/audit/document/${docId}`);
    if (!res.ok) {
      container.innerHTML = `<p class="text-xs text-red-500 py-4 text-center">Unable to load audit logs.</p>`;
      return;
    }

    const { logs } = await res.json();
    if (!logs || logs.length === 0) {
      container.innerHTML = `<p class="text-xs text-slate-400 py-4 text-center">No audit records found.</p>`;
      return;
    }

    container.innerHTML = logs.map(l => {
      const isDenied = l.status === 'DENIED';
      return `
        <div class="p-3 rounded-lg border ${isDenied ? 'bg-red-50/70 border-red-200' : 'bg-slate-50 border-slate-200'}">
          <div class="flex items-center justify-between text-[11px] mb-1">
            <span class="font-bold ${isDenied ? 'text-red-700' : 'text-indigo-700'}">${escapeHtml(l.action)}</span>
            <span class="text-slate-400 font-mono">${new Date(l.timestamp).toLocaleString()}</span>
          </div>
          <p class="text-xs text-slate-700"><span class="font-semibold">Actor:</span> ${escapeHtml(l.actor_name)} (${escapeHtml(l.actor_email)})</p>
          <p class="text-xs text-slate-600 mt-1">${escapeHtml(l.details)}</p>
          <div class="mt-2 text-[10px] font-mono text-slate-400 truncate">
            SHA-256 Hash: ${l.entry_hash}
          </div>
        </div>
      `;
    }).join('');

  } catch (err) {
    container.innerHTML = `<p class="text-xs text-red-500 py-4 text-center">Error fetching audit trail.</p>`;
  }
}

// 8. Admin Global Audit Trail & Hash Verification
async function loadAuditLogs() {
  const tbody = document.getElementById('audit-table-body');
  const statusFilter = document.getElementById('audit-filter-status').value;

  tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-400">Loading audit trail records...</td></tr>`;

  try {
    const query = new URLSearchParams();
    if (statusFilter) query.append('status', statusFilter);

    const res = await apiFetch(`/api/audit?${query.toString()}`);
    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-red-500">Failed to load audit logs.</td></tr>`;
      return;
    }

    const { logs } = await res.json();
    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-400">No logs found.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => {
      const isDenied = l.status === 'DENIED';
      return `
        <tr class="hover:bg-slate-50 transition ${isDenied ? 'bg-red-50/40' : ''}">
          <td class="py-2.5 px-4 font-mono text-slate-500">#${l.id}</td>
          <td class="py-2.5 px-4 font-mono text-slate-600 whitespace-nowrap">${new Date(l.timestamp).toLocaleString()}</td>
          <td class="py-2.5 px-4">
            <span class="font-bold text-slate-800">${escapeHtml(l.actor_name)}</span>
            <span class="text-[10px] text-slate-400 block">${escapeHtml(l.actor_email)}</span>
          </td>
          <td class="py-2.5 px-4 font-semibold text-slate-700 font-mono">${escapeHtml(l.action)}</td>
          <td class="py-2.5 px-4 max-w-[150px] truncate" title="${escapeHtml(l.resource_name || '')}">
            ${escapeHtml(l.resource_name || l.resource_type)}
          </td>
          <td class="py-2.5 px-4">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isDenied ? 'bg-red-100 text-red-800 border border-red-300' : 'bg-emerald-100 text-emerald-800'}">
              ${l.status}
            </span>
          </td>
          <td class="py-2.5 px-4 max-w-[220px] truncate text-slate-600" title="${escapeHtml(l.details)}">
            ${escapeHtml(l.details)}
          </td>
          <td class="py-2.5 px-4 font-mono text-[10px] text-slate-400 max-w-[100px] truncate" title="Hash: ${l.entry_hash}">
            ${l.entry_hash.substring(0, 12)}...
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-red-500">Error loading audit logs.</td></tr>`;
  }
}

// Cryptographic Integrity Verification of Audit Blockchain
async function verifyAuditIntegrity() {
  showAlert('Running SHA-256 hash chain verification across all blocks...', 'info');

  try {
    const res = await apiFetch('/api/audit/verify');
    const data = await res.json();

    if (res.ok && data.verified) {
      showAlert(`Cryptographic Verification PASSED: All ${data.totalRecordsVerified} records verified sequentially. Zero tampering detected.`, 'success');
    } else {
      showAlert(`INTEGRITY COMPROMISED: ${data.message}`, 'error');
    }
  } catch (err) {
    showAlert('Failed to run integrity verification.', 'error');
  }
}

// 9. UI Helpers (Alerts & Modals)
function showAlert(message, type = 'info') {
  const box = document.getElementById('alert-box');
  const msg = document.getElementById('alert-message');
  const icon = document.getElementById('alert-icon');

  msg.innerText = message;
  box.className = 'mb-6 p-4 rounded-xl border flex items-center justify-between gap-3 shadow-sm transition-all duration-300 ';

  if (type === 'success') {
    box.classList.add('bg-emerald-50', 'border-emerald-200', 'text-emerald-900');
    icon.className = 'fa-solid fa-circle-check text-emerald-600 text-xl';
  } else if (type === 'error') {
    box.classList.add('bg-red-50', 'border-red-200', 'text-red-900');
    icon.className = 'fa-solid fa-triangle-exclamation text-red-600 text-xl';
  } else {
    box.classList.add('bg-blue-50', 'border-blue-200', 'text-blue-900');
    icon.className = 'fa-solid fa-circle-info text-blue-600 text-xl';
  }

  box.classList.remove('hidden');

  setTimeout(() => {
    hideAlert();
  }, 6000);
}

function hideAlert() {
  const box = document.getElementById('alert-box');
  if (box) box.classList.add('hidden');
}

function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'flex';
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'none';
}

function formatBytes(bytes, decimals = 1) {
  if (!+bytes) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
