"use strict";
let bearer = "";
const $ = (id) => document.getElementById(id);
function show(data, status = "OK") {
  $("result").textContent = JSON.stringify(data, null, 2);
  $("result-status").textContent = status;
}
async function request(path, method = "GET", body) {
  if (!bearer) throw new Error("Connect using your private token first.");
  const response = await fetch(path, {
    method, cache: "no-store", credentials: "omit",
    headers: {"Authorization": "Bearer " + bearer, "Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}
function action(id, fn) {
  $(id).addEventListener("click", async () => {
    $(id).disabled = true;
    try { await fn(); } catch (error) { show({error: error.message}, "FAILED"); }
    finally { $(id).disabled = false; }
  });
}
document.querySelectorAll(".nav").forEach(button => button.addEventListener("click", () => {
  document.querySelectorAll(".nav").forEach(n => n.classList.toggle("active", n === button));
  document.querySelectorAll(".view").forEach(v => v.classList.toggle("hidden", v.id !== button.dataset.view));
}));
action("connect", async () => {
  bearer = $("token").value;
  try {
    const data = await request("/api/manifest");
    $("connection-status").textContent = "Workspace connected";
    $("identity").textContent = data.actor + " · " + data.purpose;
    $("tenant").textContent = "Tenant / " + data.tenant;
    $("token").value = "";
    show({connected: true, tenant: data.tenant, collections: Object.keys(data.manifest.collections)});
  } catch (error) { bearer = ""; $("connection-status").textContent = "Connection failed"; throw error; }
});
const recordPath = (prefix) => "/api/records/" + encodeURIComponent($(prefix + "-collection").value) + "/" + encodeURIComponent($(prefix + "-id").value);
action("write", async () => show(await request(recordPath("write"), "PUT", {
  document: JSON.parse($("document").value), expected_revision: Number($("write-revision").value)
})));
action("read", async () => show(await request(recordPath("read"))));
action("search-button", async () => show(await request("/api/search/" + encodeURIComponent($("search-collection").value), "POST", {
  field: $("search-field").value, values: JSON.parse($("search-values").value)
})));
action("audit-button", async () => show(await request("/api/audit/checkpoint")));
action("leakage-button", async () => show((await request("/api/manifest")).leakage));
