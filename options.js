
function save_options() {
  var autoTaint = document.getElementById('autoTaint').checked;
  chrome.storage.local.set({
    'autoTaint': autoTaint,
  }, function() {
    var status = document.getElementById('status');
    status.textContent = 'Options saved.';
    setTimeout(function() {
      status.innerHTML = '&nbsp;';
    }, 1000);
  });
}

function restore_options() {
  chrome.storage.local.get({
    'autoTaint': false,
  }, function(items) {
    document.getElementById('autoTaint').checked = items.autoTaint;
  });
}
document.addEventListener('DOMContentLoaded', restore_options);
document.getElementById('save').addEventListener('click', save_options);
