
function save_options() {
  var autoTaint = document.getElementById('autoTaint').checked;
  var muteNotifications = document.getElementById('muteNotifications').checked;
  chrome.storage.local.set({
    'autoTaint': autoTaint,
    'muteNotifications': muteNotifications,
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
    'muteNotifications': false,
  }, function(items) {
    document.getElementById('autoTaint').checked = items.autoTaint;
    document.getElementById('muteNotifications').checked = items.muteNotifications;
  });
}
document.addEventListener('DOMContentLoaded', restore_options);
document.getElementById('save').addEventListener('click', save_options);
