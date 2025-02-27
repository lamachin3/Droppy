document.addEventListener("DOMContentLoaded", function () {
    const fileInput = document.querySelector("#file-shellcode input[type=file]");
    const fileBlock = document.querySelector("#file-shellcode .file");
    const fileCta = document.querySelector("#file-shellcode .file-cta");
    const fileName = document.querySelector("#file-shellcode .file-name");
    const allowedExtensions = ["bin", "raw", "exe"];
  
    if (fileInput) {
        fileInput.addEventListener("change", function () {
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const fileExt = file.name.split('.').pop().toLowerCase();
  
                // Remove the 'is-empty' class and add 'is-filled' class
                fileBlock.classList.remove("is-empty");
                fileBlock.classList.add("is-filled");
                fileCta.classList.remove("is-empty");
                fileCta.classList.add("is-filled");
  
                if (allowedExtensions.includes(fileExt)) {
                    fileName.textContent = file.name;
                } else {
                    alert("Invalid file type! Please upload a .bin, .raw, or .exe file.");
                    fileInput.value = "";
                    fileName.textContent = "No file uploaded";
                    
                    // Reset classes if invalid file is selected
                    fileBlock.classList.remove("is-filled");
                    fileBlock.classList.add("is-empty");
                    fileCta.classList.remove("is-filled");
                    fileCta.classList.add("is-empty");
                }
            } else {
                // If no file is selected, reset classes back to 'is-empty'
                fileBlock.classList.remove("is-filled");
                fileBlock.classList.add("is-empty");
                fileCta.classList.remove("is-filled");
                fileCta.classList.add("is-empty");
                fileName.textContent = "No file selected";
            }
        });
    }
  });
  