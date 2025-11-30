const API_BASE = "/api";

const dom = {
    refreshWordlistsBtn: document.getElementById("refresh-wordlists"),
    wordlistsStatus: document.getElementById("wordlists-status"),
    wordlistsEmpty: document.getElementById("wordlists-empty"),
    wordlistsList: document.getElementById("wordlists"),

    uploadForm: document.getElementById("upload-form"),
    uploadFile: document.getElementById("upload-file"),
    uploadFilename: document.getElementById("upload-filename"),
    uploadContent: document.getElementById("upload-content"),
    uploadStatus: document.getElementById("upload-status"),

    bruteforceList: document.getElementById("bruteforce-list"),
    bruteforceForm: document.getElementById("bruteforce-form"),
    bruteforceAlgorithm: document.getElementById("bruteforce-algo"),
    bruteforceHash: document.getElementById("bruteforce-hash"),
    bruteforceWordlist: document.getElementById("bruteforce-wordlist"),
    bruteforceStartStatus: document.getElementById("bruteforce-start-status"),
};

function toast({ title = "", body = "", type = "ok" } = {}) {
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.innerHTML = `
    <div class="title">${title}</div>
    <div class="body">${body}</div>
  `;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4200);
}

async function apiGetJson(path) {
    const res = await fetch(`${API_BASE}${path}`, {
        method: "GET",
        headers: {
            Accept: "application/json",
        },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        const msg = data?.error || res.statusText || "Request failed";
        throw new Error(msg);
    }
    return data;
}

async function apiSendJson(path, method, payload) {
    const res = await fetch(`${API_BASE}${path}`, {
        method,
        headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
        },
        body: JSON.stringify(payload || {}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        const msg = data?.error || res.statusText || "Request failed";
        throw new Error(msg);
    }
    return data;
}

async function refreshWordlists() {
    dom.wordlistsStatus.textContent = "Loading...";
    dom.wordlistsList.innerHTML = "";
    dom.wordlistsEmpty.classList.add("hidden");

    try {
        const data = await apiGetJson("/wordlist");
        const files = Array.isArray(data?.files) ? data.files : [];

        // Populate file list UI
        if (files.length === 0) {
            dom.wordlistsEmpty.classList.remove("hidden");
        } else {
            for (const name of files) {
                const li = document.createElement("li");
                li.innerHTML = `
          <span title="${name}">${name}</span>
          <span class="item-actions">
            <button class="btn" data-action="download">Download</button>
            <button class="btn danger" data-action="delete">Delete</button>
          </span>
        `;

                li.querySelector('[data-action="download"]').addEventListener("click", () =>
                    downloadWordlist(name)
                );
                li.querySelector('[data-action="delete"]').addEventListener("click", () =>
                    deleteWordlist(name)
                );

                dom.wordlistsList.appendChild(li);
            }
        }

        // Populate bruteforce wordlist select
        populateWordlistSelect(files);

        dom.wordlistsStatus.textContent = `Found ${files.length} file(s).`;
    } catch (err) {
        dom.wordlistsStatus.textContent = "Error loading files.";
        toast({ title: "Failed to load wordlists", body: String(err.message || err), type: "error" });
        populateWordlistSelect([]);
    }
}

function populateWordlistSelect(files) {
    const sel = dom.bruteforceWordlist;
    sel.innerHTML = "";
    if (!Array.isArray(files) || files.length === 0) {
        const o = document.createElement("option");
        o.value = "";
        o.textContent = "-- no wordlists available --";
        sel.appendChild(o);
        sel.disabled = true;
        return;
    }
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "-- select a wordlist --";
    sel.appendChild(placeholder);

    for (const f of files) {
        const o = document.createElement("option");
        o.value = f;
        o.textContent = f;
        sel.appendChild(o);
    }
    sel.disabled = false;
    sel.selectedIndex = 1;
}

async function downloadWordlist(filename) {
    try {
        const res = await fetch(`${API_BASE}/wordlist/download`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ filename }),
        });

        if (!res.ok) {
            throw new Error(`Download failed with status ${res.status} ${res.statusText}`);
        }

        const data = await res.json();

        const a = document.createElement("a");
        console.log(data);
        a.style.display = 'none';
        a.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(data.content));
        a.setAttribute('download', data.filename);
        document.body.appendChild(a);
        a.click();
        a.remove();

        toast({title: "Download started", body: data.filename, type: "ok"});
    } catch (err) {
        toast({ title: "Download failed", body: String(err.message || err), type: "error" });
    }
}

async function deleteWordlist(filename) {
    if (!confirm(`Delete "${filename}"?`)) return;

    try {
        await apiSendJson("/wordlist", "DELETE", { filename });
        toast({ title: "Deleted", body: filename, type: "ok" });
        await refreshWordlists();
    } catch (err) {
        toast({ title: "Delete failed", body: String(err.message || err), type: "error" });
    }
}

function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const fr = new FileReader();
        fr.onload = () => resolve(String(fr.result || ""));
        fr.onerror = () => reject(fr.error || new Error("Failed to read file"));
        fr.readAsText(file);
    });
}

dom.uploadFile.addEventListener("change", () => {
    if (dom.uploadFile.files && dom.uploadFile.files[0]) {
        dom.uploadFilename.value = dom.uploadFile.files[0].name;
    }
});

dom.uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    dom.uploadStatus.textContent = "Uploading...";

    try {
        const file = dom.uploadFile.files?.[0] || null;
        const filename = (dom.uploadFilename.value || "").trim();

        let content = dom.uploadContent.value;

        if (file) {
            if (!filename) {
                dom.uploadStatus.textContent = "Please enter a filename.";
                return;
            }
            content = await readFileAsText(file);
        } else {
            if (!filename) {
                dom.uploadStatus.textContent = "Please enter a filename.";
                return;
            }
            if (!content) {
                dom.uploadStatus.textContent = "Please select a file or paste content.";
                return;
            }
        }

        await apiSendJson("/wordlist", "POST", { filename, content });
        dom.uploadStatus.textContent = "Uploaded!";
        toast({ title: "Upload successful", body: filename, type: "ok" });

        dom.uploadFile.value = "";
        dom.uploadContent.value = "";

        await refreshWordlists();
    } catch (err) {
        dom.uploadStatus.textContent = "Upload failed.";
        toast({ title: "Upload failed", body: String(err.message || err), type: "error" });
    }
});

dom.bruteforceForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    dom.bruteforceStartStatus.textContent = "Starting...";
    dom.bruteforceList.textContent = "";

    try {
        const algoRaw = dom.bruteforceAlgorithm.value;
        const algo = Number(algoRaw);
        const hash = (dom.bruteforceHash.value || "").trim();
        const wordlist = dom.bruteforceWordlist.value || "";

        if (!Number.isFinite(algo) || Number.isNaN(algo)) {
            throw new Error("Algorithm must be a number");
        }
        if (algo < 0 || algo > 99) {
            throw new Error("Algorithm should be between 0 and 99");
        }
        if (!hash) {
            throw new Error("Hash is required");
        }
        if (!wordlist) {
            throw new Error("Please select a wordlist");
        }

        const payload = {
            algorithm: algo,
            hash: hash,
            wordlist: wordlist,
        };

        const res = await apiSendJson("/bruteforce", "POST", payload);
        dom.bruteforceStartStatus.textContent = "Done.";
        dom.bruteforceList.textContent = JSON.stringify(res, null, 2);
        toast({ title: "Bruteforce request sent", body: JSON.stringify(res, null, 2), type: "ok" });
    } catch (err) {
        dom.bruteforceStartStatus.textContent = "Failed.";
        toast({ title: "Failed to start bruteforce", body: String(err.message || err), type: "error" });
    }
});

dom.refreshWordlistsBtn.addEventListener("click", refreshWordlists);
refreshWordlists();