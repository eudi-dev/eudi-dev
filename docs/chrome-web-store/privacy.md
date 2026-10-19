# Privacy policy of the eudi-dev Digital Credentials extension

The eudi-dev Digital Credentials browser extension helps developers test websites that use the W3C Digital Credentials API. This policy describes the data it handles.

## Data the extension sends

When a web page calls `navigator.credentials.get()` with a `digital` request, the extension sends that request and the origin of the page to the eudi-dev wallet set in the extension. It sends nothing else. Pages that don't call the Digital Credentials API cause no traffic.

The wallet shows the request and asks for your consent. If you approve, it returns a presentation of test credentials to the page, as the Digital Credentials API does.

By default the wallet is the public demo at https://eudi-test.dev. You can set another wallet in the extension's popup, for example a wallet on your own computer. Requests then go only to that wallet.

## The public demo

The public demo at https://eudi-test.dev is a test wallet with test credentials. It keeps the requests and presentations in its activity log until its daily reset. Its web server keeps an access log with anonymized IP addresses. The operator and contact details are in the [imprint of eudi-test.dev](https://eudi-test.dev/imprint).

Don't use real personal data with the public demo.

## Data stored in the browser

The extension stores the wallet URL you set and a random ID in the browser's extension storage. The random ID lets the wallet show its consent dialog in the window that the extension opens. Both stay in your browser.

## Use of data

The extension doesn't collect browsing history, doesn't track you and doesn't send data to anyone other than the wallet you set. It doesn't sell or share data, and it uses data only to answer Digital Credentials API requests.

## Source code

The extension is open source: https://github.com/eudi-dev/eudi-dev/tree/main/internal/dcextension/extension

## Contact

Report questions or problems at https://github.com/eudi-dev/eudi-dev/issues or through the contact details in the imprint.
