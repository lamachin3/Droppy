document.addEventListener("DOMContentLoaded", function () {
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
});
