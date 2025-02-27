document.addEventListener("DOMContentLoaded", function () {
    const fileTab = document.getElementById("file-tab");
    const textTab = document.getElementById("text-tab");
    const fileShellcode = document.getElementById("file-shellcode");
    const textShellcode = document.getElementById("text-shellcode");

    // Function to switch tabs
    function switchTab(activeTab, inactiveTab, showElement, hideElement) {
        activeTab.classList.add("is-active");
        inactiveTab.classList.remove("is-active");
        showElement.classList.remove("hidden");
        hideElement.classList.add("hidden");
    }

    // Event listeners
    fileTab.addEventListener("click", () => switchTab(fileTab, textTab, fileShellcode, textShellcode));
    textTab.addEventListener("click", () => switchTab(textTab, fileTab, textShellcode, fileShellcode));
});
