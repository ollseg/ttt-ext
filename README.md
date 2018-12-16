Taint Testing Tool
==================

Simple Chrome extension to assist in finding DOMXSS and similar security issues.
Works by injecting a unique string into "sources" such as page location, referrer, cookies, etc.
JavaScript hooks then instrument various "sinks" such as eval() and innerHTML to look for the "taint".

Clicking the "browser action" icon scans the included script sources for keywords to add as parameters, similar to DOMinator's "smart fuzzing" technique. This helps find stuff that parses location.hash as key-value and where only a certain keyword will be vulnerable to injection.

Options page contains a setting to automatically trigger the keyword search on every page load, which sometimes confuses single-page web apps.

There is currently NO way to limit the scope of the extension, so please disable it when not in use.
And, of course, please don't use it on sites where you don't have permission to test for security issues.
