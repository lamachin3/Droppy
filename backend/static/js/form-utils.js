function toggleTextBox(moduleId) {
    const textBox = document.getElementById(`textbox_${moduleId}`);
    const checkBox = document.getElementById(moduleId);
    if (checkBox.checked) {
        textBox.style.display = "flex";
    } else {
        textBox.style.display = "none";
        // Optionally clear the value if hidden
        textBox.querySelector("input").value = "";
    }
}
