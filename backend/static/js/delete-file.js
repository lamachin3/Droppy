function deleteFile(filename) {
    const modalConfirmBtn = document.getElementById("deleteModal");

    // Set the filename to be deleted in a data attribute
    modalConfirmBtn.setAttribute("data-filename", filename);

    // Show the modal
    let deleteModal = new bootstrap.Modal(document.getElementById("deleteModal"));
    deleteModal.show();
}

// Confirm delete function triggered when user clicks "Delete" in modal
function confirmDelete() {
    const modalConfirmBtn = document.getElementById("deleteModal");
    const filename = modalConfirmBtn.getAttribute("data-filename");

    fetch(`/delete/${filename}`, { method: 'DELETE' })
        .then(response => response.json())
        .then(data => {
            localStorage.setItem("toastMessage", data.message || data.error);
            location.reload();
        })
        .catch(error => showToast('Error deleting file'));
}

// Attach event listener to confirm button
document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("deleteModal").addEventListener("click", confirmDelete);
});
