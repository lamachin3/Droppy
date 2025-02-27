function showToast(message) {
    let toastElement = document.getElementById('toastContainer');
    let toastBody = toastElement.querySelector('.toast-body');
    toastBody.textContent = message;

    let toast = new bootstrap.Toast(toastElement);
    toast.show();
}

// Show toast after page reload if a message exists
document.addEventListener("DOMContentLoaded", function () {
    let storedMessage = localStorage.getItem("toastMessage");
    if (storedMessage) {
        showToast(storedMessage);
        localStorage.removeItem("toastMessage"); // Clear message after showing
    }
});
