// showQR shows the QR code of a link. The server omits it for a link too long
// for a QR code.
function showQR(id, svg) {
  const img = document.getElementById(id);
  img.classList.remove("large");
  img.hidden = !svg;
  if (svg) img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
}
for (const img of document.querySelectorAll("img.qr")) {
  img.addEventListener("click", () => img.classList.toggle("large"));
}
