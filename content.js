
//
// taintString - the unique string to taint data with
// filterString - additional characters to detect filtering/encoding
//
const taintString = 't4inT3d';
const filterString = '"\\\'%3ch1>lol';

// Fetch our options, so they are ready when page is loaded
if (top == window) {
    chrome.storage.local.get(['autoTaint'], function(result) {
        var autoTaintEnabled = result['autoTaint'];
        var script = document.createElement('script');
        script.textContent = `window.autoTaintEnabled = ${autoTaintEnabled}`;
        (document.head||document.documentElement).appendChild(script);
        script.remove();
    });
}

//
// Code to inject into the page before load, must be inline.
// Any delay in fetching it and we will inject too late!
//
var injectedCode = `

function addTaintHooks( thisWindow ) {

    // Don't process already instrumented windows
    if (!thisWindow || thisWindow.orgEval) {
        return;
    }

    const taintString = '${taintString}';
    const filterString = '${filterString}';
    const taintRegex = new RegExp(taintString);

    //
    // Some helper functions
    //

    // report a warning to the content script
    function addWarning(warningLabel, warningText) {

        // try to weed out false positives
        var match, regEx = /${taintString}/ig;
        var matches = 0, falseMatches = 0;
        while (match = regEx.exec(warningText)) {
            matches++;

            // look at string just boefore and after the match
            var pre = match.input.slice(match.index-filterString.length, match.index);
            var post = match.input.slice(match.index+match[0].length);
            post = post.slice(0, post.search(/[^a-z.0-9-]/i)+filterString.length);
            //console.log(pre + " : " + match[0] + " : " + post);

            // if filterString appears this is a good match
            if (post.includes(filterString)) continue;

            // if we find "special" characters that are not encoded, this is a good match
            if (post.match(/["<>]/)) continue;

            // make sure that single quotes are actually in use before accepting them
            if (post.includes("'") && warningText.match(/[:=] *\'/)) { console.log('GOOD'); continue;}

            // report all tainted src attributes
            if (pre.includes("src=")) continue;

            // if this is a DOM match, it's probably a false positive?
            if (warningLabel.includes('DOM'))
                falseMatches++;
        }
        if (matches && matches == falseMatches) {
            console.warn("FP? " + warningLabel + ": " +  warningText);
            return;
        }

        // print the warning to the console
        console.warn("%c" + warningLabel + "%c: " + warningText, "color: Red", "color: Black");

        // tell content script that we found something
        thisWindow.top.dispatchEvent(new CustomEvent('addWarning', { detail: thisWindow.location.origin + " " + warningLabel + ": " +  warningText }));
    };

    // concatenate arguments to form a string
    function argsToString(args) {
        var argString = "";
        for (arg of args) { argString += (argString.length ? ", " : "") + arg; }
        return argString;
    }

    // create a tainted version of a URL
    var discoveredKeywords = [];
    thisWindow.myDecodeURIComponent = thisWindow.decodeURIComponent;
    function addTaintToUrl(u) {
        var url = new URL(u);
        var taintedUrl = new URL(url.origin + url.pathname);

        // decline navigation from /abc#123 to /123 
        if (thisWindow.location.hash.length > 2) {
            if (url.pathname.slice(1).toLowerCase() == thisWindow.location.hash.slice(1).toLowerCase())
            {
                console.log("Not changing URL " + thisWindow.location.href + " to " + url);
                return thisWindow.location.href;
            }
        }

        // add the original parameters, if any
        var search = thisWindow.myDecodeURIComponent(url.search);

        // if no tainted parameters, add one
        if (!taintRegex.test(search)) {
            if (search.length != 0) 
                search += "&";
            search += taintString + ".param=" + taintString + ".value" + filterString;
        }
        for (var word of discoveredKeywords) {
            search += "&" + word + "=" + taintString + ".disco" + filterString;
        }
        taintedUrl.search = search;

        // if old hash values exist, extract keywords
        var hash = "";
        for (var h of thisWindow.myDecodeURIComponent(url.hash).split(/[#&]/)) {
            var p = h.split('=');
            if (p.length > 1) {
                if (!discoveredKeywords.includes(p[0]))
                    discoveredKeywords.push(p[0]);
            } else if (h.length != 0) {
                if (hash.length != 0) 
                    hash += "#";
                hash += h;
            }
        }

        // add any discovered keywords to hash
        for (var word of discoveredKeywords) {
            if (hash.length != 0) 
                hash += "#";
            hash += word + "=" + taintString + ".hash." + word + filterString;
        }

        // if nothing tainted in hash, add something
        if (!taintRegex.test(hash)) {
            hash += "#!//" + taintString + ".hash" + filterString;
        }
        taintedUrl.hash = hash;

        //console.log("Original href: " + location.href);
        //console.warn("Tainted href: " + taintedUrl.toString());
        return taintedUrl.toString();
    }

    //
    // Search script source for keywords to taint
    //
    const scanScriptsForKeywords = async() => {

        console.log('Scanning script source for new keywords.');

        function extractKeywords(text) {
            for (let regEx of [ ///indexOf\\(\\s*['"]([a-z0-9_-]{0,20}[a-z0-9])=?['"]/ig,
                                ///location.{4,32}\\(\\s*['"]([a-z0-9_-]{0,20}[a-z0-9])=?['"]/ig
                                /(\\(|=)\\s*['"]([a-z0-9_-]{0,20}[a-z0-9])=?['"]/ig
                              ])
            {
                var match;
                while (match = regEx.exec(text)) {
                    if (!discoveredKeywords.includes(match[2])) {
                        discoveredKeywords.push(match[2]);
                    }
                }
            }
        }

        // examine inline scripts
        for (script of thisWindow.document.querySelectorAll("script:not([src])")) {
            extractKeywords(script.textContent);
        }

        // fetch all other scripts
        for (script of thisWindow.document.querySelectorAll("script[src]")) {
            try {
                console.log("Fetching " + script.src);
                const response = await fetch(script.src);
                const body = await response.text();
                extractKeywords(body);
            } catch (e) {
                console.log("Couldn't fetch " + script.src + ": " + e);
            }
        }

        console.log("Found new keywords: " + discoveredKeywords.toString());

        // re-taint window location
        var newUrl = addTaintToUrl(thisWindow.location.href);
        if (unescape(newUrl) != unescape(thisWindow.location.href)) {
            console.log("Setting new href: " + newUrl);
            thisWindow.location.href = newUrl;
            //thisWindow.location.reload();
        }
    }
    thisWindow.addEventListener('scanPage', scanScriptsForKeywords);


    //
    // Add taint sources to the page
    //

    //
    // Taint the location without reloading the page
    //
    if (thisWindow.top == thisWindow) {
        var taintedHref = addTaintToUrl(thisWindow.location.href);
        thisWindow.history.replaceState(null, "", taintedHref);
    }

    //
    // taint the window name
    //
    Object.defineProperty(thisWindow, 'name', {
        value: thisWindow.name + taintString + ".window.name" + filterString,
        writable: false
    });

    //
    // taint the referrer (maybe this should be a valid URL to detect SSRF?)
    //
    Object.defineProperty(thisWindow.document, 'referrer', {
        value: "https://" + taintString + ".example.com/"+ taintString + ".referrer?test=" + taintString + ".referrer" + filterString + "#" + taintString + ".referrer" + filterString,
        writable: false
    });

    //
    // taint the cookie data
    // TODO: actually taint existing cookies?
    //
    thisWindow.document.orgCookie = thisWindow.document.cookie + "; " + taintString + ".cookie.name=" + taintString + ".cookie.value" + filterString;
    try {
        Object.defineProperty(thisWindow.document, 'cookie', {
            set: function() {
                thisWindow.document.orgCookie += "; " + arguments[0];
                var argString = argsToString(arguments);
                //console.log("document.cookie set for " + thisWindow.document.origin + ": " + argString);
            },
            get: function() {
                var argString = argsToString(arguments);
                //console.log("document.cookie get for " + thisWindow.document.origin);
                return thisWindow.document.orgCookie
            }
        });
    } catch (e) {
        console.error( "Couldn't hook document.cookie: " + e); 
    }


    //
    // Inspect History changes
    //
    try {
        thisWindow.History.prototype.orgPushState = thisWindow.History.prototype.pushState;
        thisWindow.History.prototype.pushState = function(){

            // mostly because I am curious
            if (arguments[0] && JSON.stringify(arguments[0]) != '{}')
                console.warn("History.pushState: " + JSON.stringify(arguments[0]) + ", " + arguments[1] + ", " + arguments[2]);

            // intercept and taint any one-page navigation
            if (thisWindow.autoTaintEnabled)
            arguments[2] = addTaintToUrl(arguments[2].startsWith("http") ? arguments[2] : location.origin + arguments[2]);

            //console.log("History.pushState: " + JSON.stringify(arguments[0]) + ", " + arguments[1] + ", " + arguments[2]);
            return thisWindow.History.prototype.orgPushState.apply(this, arguments);
        };
        thisWindow.History.prototype.orgReplaceState = thisWindow.History.prototype.replaceState;
        thisWindow.History.prototype.replaceState = function(){

            // mostly because I am curious
            if (arguments[0] && JSON.stringify(arguments[0]) != '{}')
                console.warn("History.replaceState: " + JSON.stringify(arguments[0]) + ", " + arguments[1] + ", " + arguments[2]);

            // intercept and taint any one-page navigation
            if (thisWindow.autoTaintEnabled)
            arguments[2] = addTaintToUrl(arguments[2].startsWith("http") ? arguments[2] : location.origin + arguments[2]);

            //console.log("History.replaceState: " + JSON.stringify(arguments[0]) + ", " + arguments[1] + ", " + arguments[2]);
            return thisWindow.History.prototype.orgReplaceState.apply(this, arguments);
        };
    } catch (e) {
        console.error( "Couldn't hook History.pushState/replaceState: " + e); 
    }


    //
    // Inspect sinks for tainted data
    //

    //
    // Inspect URLs passed to XMLHttpRequest
    // TODO: also hook setHeaders ?
    //
    try {
        thisWindow.XMLHttpRequest.prototype.orgOpen = thisWindow.XMLHttpRequest.prototype.open;
        thisWindow.XMLHttpRequest.prototype.open = function(){

            // only match on origin and path
            var url = arguments[1];
            var pos = url.indexOf('?');
            if (pos == -1) pos = url.indexOf('#');
            if (pos != -1)
                url = url.substring(0, pos);

            // warn if URL is tainted
            if (taintRegex.test(url))
            {
                var argString = argsToString(arguments);
                addWarning("XHR.open", argString);

                // propagate taint to responseText / responseXML
                this.addEventListener('readystatechange', function() {
                    if (this.readyState == 4) {
                        var resp = this.responseText + "//<!-- " + taintString + ".XHR.responseText -->";
                        Object.defineProperty(this, 'responseText', {
                            value: resp,
                            writable: false
                        });
                        Object.defineProperty(this, 'responseXML', {
                            value: resp,
                            writable: false
                        });
                    }
                }, useCapture = true);
            }

            return this.orgOpen.apply( this, arguments );
        }
    } catch (e) {
        console.error( "Couldn't hook XMLHttpRequest.open: " + e); 
    }

    //
    // Inspect HTMLElement attribute setters
    //
    try {
        thisWindow.HTMLElement.prototype.orgSetAttribute = thisWindow.HTMLElement.prototype.setAttribute;
        thisWindow.HTMLElement.prototype.setAttribute = function(){

            var name = this.localName + (this.id ? "#" + this.id : "");
            var argString = argsToString(arguments);
            if (taintRegex.test(argString))
            {
                // don't warn on orphaned a.href (used for "URL parsing" by eg. Angular)
                if (this.parentNode || this.tagName != "A" || arguments[0] != "href") {
                    addWarning("DOM setAttribute", name + "." + argString);
                }
            }

            return thisWindow.HTMLElement.prototype.orgSetAttribute.apply(this, arguments);
        }
    } catch (e) {
        console.error( "Couldn't hook HTMLElement.setAttribute: " + e); 
    }

    //
    // Inspect calls to document.write()
    //
    try {
        thisWindow.HTMLDocument.prototype.orgWrite = thisWindow.HTMLDocument.prototype.write;
        thisWindow.HTMLDocument.prototype.write = function () {
            var argString = argsToString(arguments);
            if (taintRegex.test(argString))
                addWarning("DOMXSS document.write", argString);
            return thisWindow.HTMLDocument.prototype.orgWrite.apply(this, arguments);
        }
        thisWindow.HTMLDocument.prototype.orgWriteln = thisWindow.HTMLDocument.prototype.writeln;
        thisWindow.HTMLDocument.prototype.writeln = function () {
            var argString = argsToString(arguments);
            if (taintRegex.test(argString))
                addWarning("DOMXSS document.writeln", argString);
            return thisWindow.HTMLDocument.prototype.orgWriteln.apply(this, arguments);
        }
    } catch (e) {
        console.error( "Couldn't hook document.write/writeln: " + e); 
    }

    //
    // Inspect setTimeout / setInterval calls
    //
    try {
        thisWindow.orgSetTimeout = thisWindow.setTimeout;
        thisWindow.setTimeout = function(){

            var argString = argsToString(arguments);
            if (taintRegex.test(argString))
                addWarning("DOMXSS setTimeout", argString);

            return thisWindow.orgSetTimeout.apply( this, arguments );
        }
        thisWindow.orgSetInterval = thisWindow.setInterval;
        thisWindow.setInterval = function(){

            var argString = argsToString(arguments);
            if (taintRegex.test(argString))
                addWarning("DOMXSS setInterval", argString);

            return thisWindow.orgSetInterval.apply( this, arguments );
        }
    } catch (e) {
        console.error( "Couldn't hook window.setTimeout/setInterval: " + e); 
    }

    //
    // Inspect JavaScript unescape/decode calls
    //
    /* // This is just creates a lot of noise and isn't very helpful
    try {
        thisWindow.orgUnescape = thisWindow.unescape;
        thisWindow.unescape = function(){

            var argString = argsToString(arguments);
            if (taintRegex.test(argString)) {
                console.warn("unescape: " + argString);
            }

            return thisWindow.orgUnescape.apply(this, arguments);
        }
        thisWindow.orgDecodeURI = thisWindow.decodeURI;
        thisWindow.decodeURI = function(){

            var argString = argsToString(arguments);
            if (taintRegex.test(argString)) {
                console.warn("decodeURI: " + argString);
            }

            return thisWindow.orgDecodeURI.apply(this, arguments);
        }
        thisWindow.orgDecodeURIComponent = thisWindow.decodeURIComponent;
        thisWindow.decodeURIComponent = function(){

            var argString = argsToString(arguments);
            if (taintRegex.test(argString)) {
                console.warn("decodeURIComponent: " + argString);
            }

            return thisWindow.orgDecodeURIComponent.apply(this, arguments);
        }
    } catch (e) {
        console.error( "Couldn't hook window.unescape/decodeURI: " + e); 
    }
    */

    //
    // Inspect JavaScript eval() calls
    //
    try {
        thisWindow.orgEval = thisWindow.eval;
        thisWindow.eval = function () {

            var argString = argsToString(arguments);
            if (taintRegex.test(argString)) {
                addWarning("DOMXSS eval", argString);
            }

            // catch any execution errors in eval()
            var ret = undefined;
            try {
                // Known bug:
                // calling eval indirectly like this will change scope in sloppy mode
                // see http://www.ecma-international.org/ecma-262/5.1/#sec-10.4.2
                //
                ret = thisWindow.orgEval.apply( thisWindow, arguments );
            } catch (e) {
                // error will now be caught by our eventListener
                e.filename = "eval()";
                throw e;
            }
            return ret;
        }
    } catch (e) {
        console.error( "Couldn't hook window.eval: " + e); 
    }

    //
    // Catch and report JavaScript errors in page
    //
    thisWindow.addEventListener('error', function(e) {
        var name = e.error ? e.error.filename : (e.filename ? e.filename : "unknown");
        var text = e.error ? e.error.message : e.message;
        if (name == 'eval()' || taintRegex.test(text)) {
            addWarning("JavaScript Error in " + name, text);
        }
    });


    //
    // Inspect window messages
    //
    thisWindow.orgPostMessage = thisWindow.postMessage;
    thisWindow.postMessage = function () {
            var argString = argsToString(arguments);
            if (taintRegex.test(argString)) {
                addWarning("Tainted postMessage call", argString);
            } else {
                console.log( "postMessage: " + argString);
            }
    }
    thisWindow.addEventListener('message', function(msg) {
        if (taintRegex.test(msg.data)) {
            addWarning("Tainted message event", msg.data);
        }
    });

    //
    // Inspect all assignments to innerHTML/outerHTML
    //
    var originalInnerHTML = Element.prototype.__lookupSetter__('innerHTML');
    var originalOuterHTML = Element.prototype.__lookupSetter__('outerHTML');
    try {
        Element.prototype.__defineSetter__('innerHTML', function () {
            var argString = argsToString(arguments);
            if (taintRegex.test(argString)) {
                var name = "[" + this.localName + (this.id ? "#" + this.id : "") + "]";
                addWarning("DOMXSS " + name + ".innerHTML", argString);
            }
            return originalInnerHTML.apply(this, arguments);
        });
        Element.prototype.__defineSetter__('outerHTML', function () {
            var argString = argsToString(arguments);
            if (taintRegex.test(argString)) {
                var name = "[" + this.localName + (this.id ? "#" + this.id : "") + "]";
                addWarning("DOMXSS " + name + ".outerHTML", argString);
            }
            return originalOuterHTML.apply(this, arguments);
        });
    } catch (e) {
            console.error( "Couldn't hook innerHTML/outerHTML: " + e); 
    }

    //
    // create a MutationObserver to monitor the DOM for changes
    //
    var observer = new MutationObserver( function (mutationsList, observer) {
        for(var mutation of mutationsList) {

            var name = mutation.target.localName + (mutation.target.id ? "#" + mutation.target.id : "");

            if (mutation.type == 'childList') {

                var text = "";
                for (var i=0; i<mutation.addedNodes.length; i++){
                    var node =  mutation.addedNodes[i];
                    text += node.outerHTML;

                    // discover new iframes and add our hooks to them
                    if (node.contentWindow) {
                        addTaintHooks(node.contentWindow);
                    }
                }
                if (taintRegex.test(text)) {
                    addWarning("DOM child node added to '" + name + "'", text );
                }

            } else if (mutation.type == 'attributes'){

                try { 
                    if ( taintRegex.test(mutation.attributeName)
                        || ( mutation.target.attributes[mutation.attributeName]
                            && taintRegex.test(mutation.target.attributes[mutation.attributeName].nodeValue) )
                       )
                    {
                        // ignore tainted links
                        if (mutation.target.tagName != "A" || mutation.attributeName != "href") {
                            addWarning("DOM attribute '" + mutation.attributeName + "' was modified on '" + name + "'", mutation.target.attributes[mutation.attributeName].nodeValue);
                        }
                    }
                } catch (e) {
                    console.error("Problem reporting tainted attribute: " + e);
                }

            } else if (mutation.type == 'characterData'){

                if (taintRegex.test(mutation.target.textContent)) {
                    addWarning("DOM tainted characterData added to '" + name + "'", mutation.target.textContent);
                }

            } else {
                console.group("Unknown MutationEvent");
                console.dir(mutation);
                console.groupEnd();
            }
        }
    });
    observer.observe(thisWindow.document, { attributes: true, childList: true, characterData: true, subtree: true });

    //
    // Inspect new elements added to the DOM
    //
    try {
        thisWindow.HTMLElement.prototype.orgAppendChild = thisWindow.HTMLElement.prototype.appendChild;
        thisWindow.HTMLElement.prototype.appendChild = function () {
            var obj = thisWindow.HTMLElement.prototype.orgAppendChild.apply(this, arguments);

            // add inspection hooks to new iframes as well
            if (obj instanceof thisWindow.HTMLIFrameElement && obj.contentWindow) {
                addTaintHooks(obj.contentWindow);
            }

            return obj;
        }
    } catch (e) {
        console.error( "Couldn't hook HTMLElement.appendChild: " + e); 
    }


    //
    // Stuff related to navigation, only for top frame
    //
    if (thisWindow.top == thisWindow) {

        //
        // re-trigger location tainting on single-page navigation
        //
        function taintChangedHash(e) {
            console.log("onhashchange: " + thisWindow.location.hash);
            if (thisWindow.autoTaintEnabled) {
                var taintedHref = addTaintToUrl(e.newURL);
                if (unescape(taintedHref) != unescape(e.newURL)) {
                    //thisWindow.location.hash = (new URL(taintedHref)).hash;
                    thisWindow.location.href = taintedHref;
                }
            }
        }
        thisWindow.addEventListener('hashchange', taintChangedHash);

        //
        // automatically scan for keywords after loading the page
        //
        thisWindow.addEventListener("load", function () {
            if (thisWindow.autoTaintEnabled) {
                scanScriptsForKeywords();
            }
        });
    }

}
addTaintHooks(window);

`;

// inject our script code into the page
var s = document.createElement('script');
s.textContent = injectedCode;
(document.head||document.documentElement).appendChild(s);
s.remove();

// listen for warnings from the injected script
window.addEventListener("addWarning", function(data) {
    chrome.runtime.sendMessage({op: "addWarning", message: data.detail});
});

// listen for messages from the background script
chrome.runtime.onMessage.addListener( function(req, sender, sendResponse) {
    if (req.op == "scanPage") {
        if (window === window.top) {
            window.dispatchEvent(new Event('scanPage'));
        }
    }
});
