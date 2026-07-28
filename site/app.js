document.querySelectorAll("pre.terminal").forEach(function (pre) {
  var button = document.createElement("button");
  button.className = "copy";
  button.type = "button";
  button.textContent = "Copy";
  button.setAttribute("aria-label", "Copy code to clipboard");
  button.addEventListener("click", function () {
    var text = pre.querySelector("code") ? pre.querySelector("code").innerText : pre.innerText;
    navigator.clipboard.writeText(text).then(function () {
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = "Copy"; }, 1500);
    });
  });
  pre.appendChild(button);
});