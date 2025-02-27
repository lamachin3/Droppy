document.addEventListener("DOMContentLoaded", function () {
    /*** Confirm Delete Modal ***/
    let cancelDeleteButton = document.getElementById("modalCancelDelete");
    let deleteModalElement = document.getElementById("deleteModal");

    if (cancelDeleteButton && deleteModalElement) {
        cancelDeleteButton.addEventListener("click", function () {
            let deleteModal = bootstrap.Modal.getInstance(deleteModalElement);
            if (deleteModal) deleteModal.hide();
        });
    }

    /*** Tabs ***/
    let fileTab = document.getElementById("file-tab");
    let textTab = document.getElementById("text-tab");
    let fileShellcode = document.getElementById("file-shellcode");
    let textShellcode = document.getElementById("text-shellcode");

    if (fileTab && textTab && fileShellcode && textShellcode) {
        function switchTab(activeTab, inactiveTab, showElement, hideElement) {
            activeTab.classList.add("is-active");
            inactiveTab.classList.remove("is-active");
            showElement.classList.remove("hidden");
            hideElement.classList.add("hidden");
        }

        fileTab.addEventListener("click", () => switchTab(fileTab, textTab, fileShellcode, textShellcode));
        textTab.addEventListener("click", () => switchTab(textTab, fileTab, textShellcode, fileShellcode));
    }

    /*** Toast ***/
    let toastElement = document.getElementById("toastContainer");
    if (toastElement) {
        function showToast(message) {
            let toastBody = toastElement.querySelector(".toast-body");
            toastBody.textContent = message;
            let toast = new bootstrap.Toast(toastElement);
            toast.show();
        }

        let storedMessage = localStorage.getItem("toastMessage");
        if (storedMessage) {
            showToast(storedMessage);
            localStorage.removeItem("toastMessage"); // Clear after displaying
        }
    }

    /*** Tooltips ***/
    let tooltipElements = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (tooltipElements.length > 0) {
        tooltipElements.forEach(function (tooltipTriggerEl) {
            new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
});
