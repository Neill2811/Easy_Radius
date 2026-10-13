document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-reveal]");
  if (!button) {
    return;
  }
  const cell = button.closest(".secret-cell");
  const hidden = cell.querySelector(".shown").hasAttribute("hidden");
  cell.querySelector(".shown").toggleAttribute("hidden", !hidden);
  cell.querySelector(".mask").toggleAttribute("hidden", hidden);
  button.textContent = hidden ? "Hide" : "Show";
});

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (form instanceof HTMLFormElement && form.dataset.confirm) {
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  }
});
