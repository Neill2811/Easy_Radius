document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-reveal]");
  if (button) {
    const cell = button.closest(".secret-cell");
    const hidden = cell.querySelector(".shown").hasAttribute("hidden");
    cell.querySelector(".shown").toggleAttribute("hidden", !hidden);
    cell.querySelector(".mask").toggleAttribute("hidden", hidden);
    button.textContent = hidden ? "Hide" : "Show";
    return;
  }
  const blockButton = event.target.closest("[data-reveal-block]");
  if (!blockButton) {
    return;
  }
  const block = document.getElementById(blockButton.getAttribute("data-reveal-block"));
  if (!block) {
    return;
  }
  const hidden = block.hasAttribute("hidden");
  block.toggleAttribute("hidden", !hidden);
  blockButton.textContent = hidden ? "Hide MikroTik config" : "Copy MikroTik config";
  if (hidden && navigator.clipboard) {
    const text = block.innerText.trim();
    navigator.clipboard.writeText(text).catch(() => {});
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (form instanceof HTMLFormElement && form.dataset.confirm) {
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  }
});
