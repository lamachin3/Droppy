document.addEventListener("DOMContentLoaded", function () {
    // Ensure modal hides properly on cancel
    document.getElementById("modalCancelDelete").addEventListener("click", function () {
        let deleteModal = bootstrap.Modal.getInstance(document.getElementById("deleteModal"));
        deleteModal.hide();
    });
});
