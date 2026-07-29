(function () {
  var root = document.documentElement;
  var toggle = document.querySelector("[data-theme-toggle]");
  if (!toggle) return;

  toggle.addEventListener("click", function () {
    var isLight = root.getAttribute("data-theme") === "light";
    if (isLight) {
      root.removeAttribute("data-theme");
      localStorage.setItem("wardline-theme", "dark");
    } else {
      root.setAttribute("data-theme", "light");
      localStorage.setItem("wardline-theme", "light");
    }
  });
})();
