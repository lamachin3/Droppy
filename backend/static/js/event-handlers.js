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
    // Define tabs and their related content
    const tabs = [
        { tabId: "file-tab", elementId: "file-shellcode", contentElementId: "file-input" },
        { tabId: "text-tab", elementId: "text-shellcode", contentElementId: "textarea-shellcode" },
        { tabId: "executables-tab", elementId: "executable", contentElementId: "autocompleteInput" },
    ];

    const sliderBg = document.querySelector(".tab-slider-bg");
    const tabOptions = document.querySelectorAll(".tab-option");

    function disableInputs(tabElement) {
        if (!tabElement) return;
        const inputs = tabElement.querySelectorAll("input, textarea, select, button");
        inputs.forEach(input => input.disabled = true);
    }

    function enableInputs(tabElement) {
        if (!tabElement) return;
        const inputs = tabElement.querySelectorAll("input, textarea, select, button");
        inputs.forEach(input => input.disabled = false);
    }

    function switchTab(activeTabId) {
        // Reset all tab contents, hide them, and disable inputs
        tabs.forEach(({ elementId, contentElementId }) => {
            const tabElement = document.getElementById(elementId);
            const contentElement = document.getElementById(contentElementId);

            if (tabElement) {
                tabElement.classList.remove("show", "active");
                disableInputs(tabElement);
            }
            if (contentElement) contentElement.value = '';
        });
        document.getElementsByName("execution_arguments").forEach(arg => {
            arg.value = ''; // Clear execution arguments
        });
        document.getElementById("autocompleteValue").value = '';

        // Activate the selected tab content and enable its inputs
        const activeTab = tabs.find(tab => tab.tabId === activeTabId);
        if (activeTab) {
            const activeTabIndex = tabs.findIndex(tab => tab.tabId === activeTabId);
            sliderBg.style.transform = `translateX(${activeTabIndex * 100}%)`;

            tabOptions.forEach(tabOption => {
                tabOption.classList.remove("active");
            });

            const activeTabElement = document.getElementById(activeTabId);
            activeTabElement.classList.add("active");

            const activeContent = document.getElementById(activeTab.elementId);
            activeContent.classList.add("show", "active");
            enableInputs(activeContent);
        }
    }

    tabOptions.forEach(tabOption => {
        tabOption.addEventListener("click", () => {
            switchTab(tabOption.id);
        });
    });

    // Optional: handle background slider position on page load
    const activeTab = document.querySelector(".tab-option.active");
    if (activeTab) {
        const position = activeTab.offsetLeft;
        const width = activeTab.offsetWidth;
        sliderBg.style.left = position + "px";
        sliderBg.style.width = width + "px";
    }
});


document.addEventListener("DOMContentLoaded", function () {
    const data = precompiledExecutablesData || [];
    const input = document.getElementById("autocompleteInput");
    const inputValue = document.getElementById("autocompleteValue");
    const dropdown = document.getElementById("autocompleteDropdown");

    input.addEventListener("input", () => {
        const query = input.value.toLowerCase();
        dropdown.innerHTML = "";

        if (query) {
            const filteredData = data.filter(file =>
                file.filename.toLowerCase().includes(query)
            );

            if (filteredData.length) {
                filteredData.forEach(file => {
                    const li = document.createElement("li");
                    li.innerHTML = `<button class="dropdown-item text-primary" type="button">${file.filename}</button>`;
                    li.querySelector("button").addEventListener("click", () => {
                        input.value = file.filename;
                        inputValue.value = JSON.stringify(file);
                        dropdown.innerHTML = "";
                    });
                    dropdown.appendChild(li);
                });

                dropdown.classList.add("show");
            } else {
                dropdown.classList.remove("show");
            }
        } else {
            dropdown.classList.remove("show");
        }
    });

    document.addEventListener("click", (e) => {
        if (!dropdown.contains(e.target) && e.target !== input) {
            dropdown.classList.remove("show");
        }
    });
});