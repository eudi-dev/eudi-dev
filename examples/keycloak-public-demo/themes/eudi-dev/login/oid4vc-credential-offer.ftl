<#-- Keycloak's keycloak.v2 template as of 26.8.1, laid out like its wallet sign-in page and with a web wallet button. Compare it after a Keycloak upgrade. -->
<#import "template.ftl" as layout>
<#import "buttons.ftl" as buttons>
<#import "divider.ftl" as divider>
<#import "qr-code.ftl" as qr>
<@layout.registrationLayout displayRequiredFields=false displayMessage=!messagesPerField.existsError('credentialOffer'); section>
<!-- template: oid4vc-credential-offer.ftl -->
    <#if section = "header">
        ${msg("credentialOfferTitle", credentialDisplayName)}
    <#elseif section = "form">
        <div id="kc-cred-offer-settings" class="${properties.kcFormGroupClass!}">
            <@qr.qrCode id="kc-credential-offer-qr-code" content=credentialOffer.qrCode alt="QR code to claim a credential with a wallet" title=msg("oid4vpScanQrCodeTitle") label=msg("oid4vpScanQrCode") />
        </div>
        <@divider.or />
        <div id="kc-credential-offer-links" class="${properties.kcFormGroupClass!}">
            <#-- The wallet's web address takes the same parameters as the openid-credential-offer:// link. -->
            <a id="credential-offer-web-wallet-link" href="${properties.walletUrl}/credential-offer?${credentialOffer.uri?keep_after("?")}" target="_blank" rel="noopener"
               class="${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}">${msg("credentialOfferWebWallet", properties.walletUrl?keep_after("://"))}</a>
            <a id="credential-offer-uri-link" href="${credentialOffer.uri}"
               class="${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}">${msg("oid4vpOpenWalletApp")}</a>
        </div>
        <p id="kc-credential-offer-next" class="${properties.kcLoginMainFooterHelperText!}">${msg("credentialOfferNext", credentialDisplayName)}</p>
        <form action="${url.loginAction}" class="${properties.kcFormClass!}" id="kc-cred-offer-settings-form" method="post" novalidate="novalidate">
            <@buttons.actionGroup horizontal=true>
                <@buttons.button id="continue-vc-offer" label="doContinue" />
                <#if !skipCancelButton??>
                    <@buttons.button id="cancel-vc-offer" name="cancel-aia" label="doCancel" type="secondary" value="true" />
                </#if>
            </@buttons.actionGroup>
        </form>
    </#if>
</@layout.registrationLayout>
