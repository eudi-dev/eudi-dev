# Chrome Web Store listing

This folder holds everything the Chrome Web Store listing of the eudi-dev browser extension needs: the texts to paste into the developer dashboard, the images and the steps to publish. The extension itself is in [`internal/dcextension/extension`](../../internal/dcextension/extension). See [Digital Credentials API](../wallet/browser-extension.md) for what it does.

The store version uses the public demo at https://eudi-test.dev by default. Publish it only after eudi-test.dev runs a release with the extension support (3.3.0 or later), because older wallets don't read the page origin from the extension.

## Files

| File | Dashboard field |
|---|---|
| `icon-128.png` | Store icon (128×128, artwork 96×96 with transparent padding) |
| `screenshot-1.png` to `screenshot-4.png` | Screenshots (1280×800) |
| `promo-small-440x280.png` | Small promo tile |
| `promo-marquee-1400x560.png` | Marquee promo tile (optional) |
| [`privacy.md`](privacy.md) | Privacy policy (link its GitHub URL) |

## 1. Package

The manifest version comes from the eudi-dev version, so build the package from a release tag. Every upload needs a higher version than the last one.

```bash
git checkout v3.3.0
scripts/chrome-web-store-package.sh v3.3.0     # writes dist/eudi-dev-dc-api-extension-3.3.0.zip
```

## 2. Developer account

1. Turn on 2-step verification for the Google account that publishes the extension.
2. Open the [developer dashboard](https://chrome.google.com/webstore/devconsole), accept the developer agreement and pay the one-time registration fee of 5 USD.
3. Set the publisher name, for example `eudi-dev`, and verify the contact email.
4. Fill in the trader declaration (EU Digital Services Act).

## 3. Upload and listing

Choose **New item** and upload the zip. Then fill in the tabs.

### Store listing

**Description** (the summary under the name comes from the manifest):

```text
eudi-dev Digital Credentials lets you test websites that use the W3C Digital Credentials API without a phone. It works with any verifier website, without changes to the website.

A verifier page asks for a credential with navigator.credentials.get(). Chrome normally passes the request to a wallet on a phone, which needs Bluetooth and a mobile wallet with test credentials. This extension answers the call with an eudi-dev test wallet instead. The wallet opens in a window and shows what the verifier asks for. You approve or deny the presentation there.

Features
• OpenID4VP 1.0 over the Digital Credentials API: openid4vp-v1-unsigned, openid4vp-v1-signed and openid4vp-v1-multisigned
• Encrypted (dc_api.jwt) and plain (dc_api) responses
• Test credentials of the eudi-dev wallet, such as the EUDI PID as SD-JWT VC and mdoc
• The wallet binds each presentation to the page origin, which the extension reads from the browser
• Works with the public demo wallet at https://eudi-test.dev, a local wallet started with eudi wallet serve, or your own server. Set the wallet in the extension's popup.
• Other credential requests, such as passkeys, still go to Chrome

The extension answers presentation requests only. It doesn't handle navigator.credentials.create().

Try it on the demo verifier at https://eudi-test.dev/verifier/ and choose Digital Credentials API under Delivery.

eudi-dev is an open source developer toolkit for the EUDI Wallet ecosystem: https://github.com/eudi-dev/eudi-dev

Unofficial, independent open source project. Not affiliated with or endorsed by the European Commission or the European Union.
```

| Field | Value |
|---|---|
| Category | Developer Tools |
| Language | English |
| Store icon | `icon-128.png` |
| Screenshots | `screenshot-1.png` to `screenshot-4.png`, in this order |
| Small promo tile | `promo-small-440x280.png` |
| Marquee promo tile | `promo-marquee-1400x560.png` |
| Official URL | none, unless you verify a domain in Google Search Console |
| Homepage URL | https://github.com/eudi-dev/eudi-dev |
| Support URL | https://github.com/eudi-dev/eudi-dev/issues |

### Privacy

**Single purpose:**

```text
Lets developers answer Digital Credentials API requests (navigator.credentials.get() with a digital member) with an eudi-dev test wallet, to test verifier websites.
```

**Permission justifications:**

| Permission | Justification |
|---|---|
| `storage` | Stores the wallet URL that the user sets in the popup, and a random ID that lets the wallet show its consent dialog in the window the extension opens. |
| `offscreen` | Waits for the wallet's answer to a request. The user decides in the wallet, which can take minutes, longer than a service worker may wait for a fetch. |
| Host permission `<all_urls>` | Any verifier website can call the Digital Credentials API, so the content script runs on every page. The extension also sends the request to the wallet at the URL the user sets, which can be any host, including localhost. |

**Remote code:** No, I am not using remote code. All scripts are in the package.

**Data usage:**

- Check **Website content**. The extension sends the request that a page passes to `navigator.credentials.get()`, and the page origin, to the wallet set in the popup. By default that is https://eudi-test.dev, which the publisher operates. It collects nothing else.
- Check the 3 certifications: no sale to third parties, no use unrelated to the single purpose, no use for creditworthiness or lending.

**Privacy policy URL:** https://github.com/eudi-dev/eudi-dev/blob/main/docs/chrome-web-store/privacy.md

### Distribution

| Field | Value |
|---|---|
| Visibility | Public, or Unlisted to make it installable only by link |
| Regions | All regions |

## 4. Review

Choose **Submit for review**. The first review is likely to take several days. Extensions with a host permission for all sites and a script that replaces a browser API get an in-depth review. The justifications above explain both.

The extension is published as https://chromewebstore.google.com/detail/nbddeclckpkklpejkmhchmhmajginnok with the ID `nbddeclckpkklpejkmhchmhmajginnok`. The demo verifier, the wallet's How to use dialog, the README and [browser extension](../wallet/browser-extension.md) link it.

The release job uploads only the package. Changes to the description, the screenshots or the promo tiles in this folder have to be made in the dashboard by hand.

## 5. Updates from releases

The `chrome-web-store` job of the release workflow builds the package for a stable release, uploads it and publishes it with the Chrome Web Store API V2. Google reviews every version before users get it. When the extension is unchanged since the published version, the job skips the upload. The job signs in as a Google Cloud service account with Workload Identity Federation, so the repository holds no Google key or token. It is skipped until all of these repository variables exist:

| Variable | Value |
|---|---|
| `CHROME_WEB_STORE_PUBLISHER_ID` | Publisher ID from the **Account** page of the dashboard. It is also the ID in the dashboard URL, `https://chrome.google.com/webstore/devconsole/<publisher ID>`. |
| `CHROME_WEB_STORE_EXTENSION_ID` | `nbddeclckpkklpejkmhchmhmajginnok` |
| `CHROME_WEB_STORE_SERVICE_ACCOUNT` | Email of the service account |
| `CHROME_WEB_STORE_WORKLOAD_IDENTITY_PROVIDER` | Full name of the workload identity provider |

To set them up:

1. In the [Google Cloud console](https://console.cloud.google.com/), create a project, enable the **Chrome Web Store API** and create a service account without roles.
2. On the **Account** page of the developer dashboard, add the email of the service account. A publisher can have 1 service account.
3. Let release runs of this repository sign in as the service account:

```bash
PROJECT_ID=<project id>
SERVICE_ACCOUNT=<service account email>
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')

gcloud services enable iamcredentials.googleapis.com sts.googleapis.com --project "$PROJECT_ID"
gcloud iam workload-identity-pools create github --project "$PROJECT_ID" --location global \
  --display-name "GitHub Actions"
gcloud iam workload-identity-pools providers create-oidc eudi-dev --project "$PROJECT_ID" --location global \
  --workload-identity-pool github \
  --issuer-uri https://token.actions.githubusercontent.com \
  --attribute-mapping 'google.subject=assertion.sub,attribute.repository=assertion.repository' \
  --attribute-condition "assertion.repository == 'eudi-dev/eudi-dev' && assertion.ref.startsWith('refs/tags/v')"
gcloud iam service-accounts add-iam-policy-binding "$SERVICE_ACCOUNT" --project "$PROJECT_ID" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository/eudi-dev/eudi-dev"
```

4. Set the repository variables:

```bash
gh variable set CHROME_WEB_STORE_PUBLISHER_ID -R eudi-dev/eudi-dev --body <publisher id>
gh variable set CHROME_WEB_STORE_EXTENSION_ID -R eudi-dev/eudi-dev --body nbddeclckpkklpejkmhchmhmajginnok
gh variable set CHROME_WEB_STORE_SERVICE_ACCOUNT -R eudi-dev/eudi-dev --body "$SERVICE_ACCOUNT"
gh variable set CHROME_WEB_STORE_WORKLOAD_IDENTITY_PROVIDER -R eudi-dev/eudi-dev \
  --body "projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/providers/eudi-dev"
```

The provider accepts only runs of `eudi-dev/eudi-dev` for a tag that starts with `v`, so other workflows and forks can't publish.

The API updates existing items only. Sections 3 and 4 publish the first version by hand.
