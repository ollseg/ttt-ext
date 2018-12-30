
//
// This is the persistent background script, it keeps global state for the extension
//

// make sure this is the same as in the content script
const taintString = "t4inT3d";


//
// handler for the browser action button
//
chrome.browserAction.onClicked.addListener(function (tab) {
    chrome.tabs.sendMessage(tab.id, {op: "scanPage"});
    //chrome.runtime.openOptionsPage();
});


//
// handle warning notifications for the content scripts
//
var warningCounter = 0;
var warningsAtLAstNotification = 0;
var muteNotifications = false;

// Fetch our options and make sure to notice when they are changed
chrome.storage.local.get(['muteNotifications'], function(result) {
    muteNotifications = result['muteNotifications'];
});
chrome.storage.onChanged.addListener(function(changes, namespace) {
    var change = changes['muteNotifications'];
    if (change) {
        muteNotifications = change['newValue'];
    }
});

// listen to requests from content script
chrome.runtime.onMessage.addListener( function(req, sender, sendResponse) {
    if (req.op == "addWarning") {
        console.log(req.message, "color: Red", "color: Default");
        warningCounter++;
        chrome.browserAction.setBadgeText({text: warningCounter.toString()});
    }
    return true;
});

// reset warnings on page navigation
chrome.webNavigation.onBeforeNavigate.addListener( function (details) {
    if (details.frameId == 0) {
        warningCounter = 0;
        warningsAtLAstNotification = 0;
        chrome.browserAction.setBadgeText({text: ""});
    }
});

// show notifications if page has triggered warnings
function showNotifications() {
    if (!muteNotifications && warningsAtLAstNotification < warningCounter) {
        chrome.notifications.create("", { type: "basic",
                                          title: "Taint Testing Tool",
                                          message: "Page has triggered " + warningCounter + " warning" + (warningCounter > 1 ? "s" : "") + "!" +
                                                   "\nSee the JavaScript console for more info.",
                                          iconUrl:"images/injection128.png"
                                         });
        warningsAtLAstNotification = warningCounter;
    }
}
// notify on page load
chrome.webNavigation.onCompleted.addListener( showNotifications );
// and also at regular intervals
window.setInterval( showNotifications, 1000 );

