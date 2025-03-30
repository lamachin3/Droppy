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
            localStorage.removeItem("toastMessage");
        }
    }

    /*** Tooltips ***/
    let tooltipElements = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (tooltipElements.length > 0) {
        tooltipElements.forEach(function (tooltipTriggerEl) {
            new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    /*** Checkboxes ***/
    // Select all checkboxes under encryption and obfuscation
    const allCheckboxes = document.querySelectorAll('input[name^="encryption"], input[name^="obfuscation"]');

    function handleSelection(event) {
        if (event.target.checked) {
            // Disable all other checkboxes in both sections
            allCheckboxes.forEach(cb => {
                if (cb !== event.target) {
                    cb.disabled = true;
                }
            });
        } else {
            // If the user unchecks, re-enable all checkboxes
            allCheckboxes.forEach(cb => {
                cb.disabled = false;
            });
        }
    }

    // Attach event listeners to all checkboxes
    allCheckboxes.forEach(checkbox => {
        checkbox.addEventListener("change", handleSelection);
    });

    
    /*** Buttons ***/
    document.getElementById("deleteModal").addEventListener("click", confirmDelete);
});

/* Dropzone handlers */
document.addEventListener("DOMContentLoaded", function () {
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");

    if (!dropZone || !fileInput) {
        console.error("Drop zone or file input not found. Check your HTML IDs.");
        return; // Stop execution if elements are missing
    }

    // Drag over
    dropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropZone.style.background = "rgba(255, 255, 255, 0.05)";
    });

    // Drag leave
    dropZone.addEventListener("dragleave", () => {
        dropZone.style.background = "#26303f";
    });

    // Drop event
    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.style.background = "#26303f";
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files; // Assign dropped files to input
            console.log("Files dropped:", files);
        }
    });

    // Handle file selection
    fileInput.addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (file) {
            console.log("File selected:", file);
        }
    });
});



document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('file-input');
    const filePreview = document.getElementById('file-preview');
    const fileNameElement = document.getElementById('file-name');
    const fileSizeElement = document.getElementById('file-size');
    const removeFileButton = document.getElementById('remove-file-btn');

    // Handle file selection
    fileInput.addEventListener('change', function(event) {
        const file = event.target.files[0];

        if (file) {
            // Convert file size to KB/MB
            const fileSize = file.size < 1024 * 1024 
                ? (file.size / 1024).toFixed(2) + ' KB' 
                : (file.size / (1024 * 1024)).toFixed(2) + ' MB';

            // Update file preview section
            fileNameElement.textContent = file.name;
            fileSizeElement.textContent = fileSize;

            // Show the preview section
            filePreview.classList.remove('d-none');
        }
    });

    // Remove file when "X" is clicked
    removeFileButton.addEventListener('click', function() {
        fileInput.value = ''; // Clear file input
        filePreview.classList.add('d-none'); // Hide preview
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const fileTab = document.getElementById("file-tab");
    const textTab = document.getElementById("text-tab");
    const fileContent = document.getElementById("file-shellcode");
    const textContent = document.getElementById("text-shellcode");
    const sliderBg = document.querySelector(".tab-slider-bg");
    const tabOptions = document.querySelectorAll(".tab-option");

    function switchTab(activeTab) {
        // Reset both tab contents and hide them
        fileContent.classList.remove("show", "active");
        textContent.classList.remove("show", "active");

        // Activate the right tab content
        if (activeTab === "file") {
            sliderBg.style.transform = "translateX(0%)";
            fileTab.classList.add("active");
            textTab.classList.remove("active");
            fileContent.classList.add("show", "active");
        } else {
            sliderBg.style.transform = "translateX(100%)";
            textTab.classList.add("active");
            fileTab.classList.remove("active");
            textContent.classList.add("show", "active");
        }
    }

    tabOptions.forEach(tabOption => {
        tabOption.addEventListener("click", () => {
            const activeTab = tabOption.id === "file-tab" ? "file" : "text";
            switchTab(activeTab);
        });
    });

    // Optional: handle background slider position on page load
    const activeTab = document.querySelector(".tab-option.active");
    const position = activeTab.offsetLeft;
    const width = activeTab.offsetWidth;
    sliderBg.style.left = position + "px";
    sliderBg.style.width = width + "px";
});

