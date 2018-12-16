
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
    if (warningsAtLAstNotification < warningCounter) {
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


//
// intercept network requests to clean any tainted data
//
chrome.webRequest.onBeforeSendHeaders.addListener( function(details) {

    // clean request headers
    for (var i = 0; i < details.requestHeaders.length; ++i) {
        var pos = details.requestHeaders[i].value.indexOf(taintString);
        if (pos != -1) {
            details.requestHeaders[i].value = details.requestHeaders[i].value.substring(0, pos);
            //console.log("Cleaned " + details.requestHeaders[i].name + ": " + details.requestHeaders[i].value);
        }
    }

    return { requestHeaders: details.requestHeaders };
},
{urls: ["http://*/*", "https://*/*"]},
["blocking", "requestHeaders"]);

chrome.webRequest.onBeforeRequest.addListener( function(details) {
    var url = new URL(details.url);

    // cancel fetch of tainted paths
    if (url.pathname.indexOf(taintString) != -1) {
        //console.log("Cancel " + details.url);
        return { cancel: true };
    }

    // clean URL parameters
    var search ="";
    for (var p of url.searchParams) {
        // remove tainted keys
        if (p[0].indexOf(taintString) == -1) {
            // remove tainted values
            var pos = p[1].indexOf(taintString);
            if (pos != -1) {
                p[1] = p[1].substring(0,pos);
            }
            if (search.length) { search += '&'; };
            search += p[0] + (p[1] ? "=" + p[1] : '');
        }
    }
    url.search = search;

    // don't redirect to same url
    if (details.url == url)
        return {};

    //console.log("Redirect " + details.url + " => " +  url);
    return {redirectUrl: url.toString()};
},
{urls: ["http://*/*", "https://*/*"]},
["blocking"]);
