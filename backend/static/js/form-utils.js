function toggleTextBox(moduleId) {

    const checkbox = document.getElementById(moduleId);
    const textbox = document.getElementById('textbox_' + moduleId);
    if (checkbox.checked) {
        textbox.style.display = 'flex';
    } else {
        textbox.style.display = 'none';
    }
}
