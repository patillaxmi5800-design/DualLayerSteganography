/* StegoSecure client-side behaviour.
   No external libraries. Backend independently validates everything. */

(function () {
    "use strict";

    var MAX_SIZE = 20 * 1024 * 1024; // 20 MB, mirrors the server limit.
    var ALLOWED = ["image/png", "image/jpeg", "image/jpg", "image/bmp", "image/webp", "image/gif"];

    /* ---------- Mobile sidebar toggle ---------- */
    var menuToggle = document.getElementById("menuToggle");
    var sidebar = document.getElementById("sidebar");
    if (menuToggle && sidebar) {
        menuToggle.addEventListener("click", function () {
            sidebar.classList.toggle("open");
        });
    }

    /* ---------- Key show/hide toggles ---------- */
    var toggles = document.querySelectorAll(".key-toggle");
    toggles.forEach(function (btn) {
        btn.addEventListener("click", function () {
            var target = document.getElementById(btn.getAttribute("data-target"));
            if (!target) { return; }
            if (target.type === "password") {
                target.type = "text";
                btn.textContent = "🙈"; // see-no-evil monkey
            } else {
                target.type = "password";
                btn.textContent = "👁"; // eye
            }
        });
    });

    /* ---------- Image preview + drag/drop + validation ---------- */
    var input = document.getElementById("imageInput");
    var dropzone = document.getElementById("dropzone");
    var previewImage = document.getElementById("previewImage");
    var previewPlaceholder = document.getElementById("previewPlaceholder");
    var dropzoneInner = document.getElementById("dropzoneInner");

    function isValidImage(file) {
        if (!file) { return false; }
        if (ALLOWED.indexOf(file.type) === -1) {
            alert("❌ Unsupported image type. Please choose PNG, JPG, JPEG, BMP, WEBP or GIF.");
            return false;
        }
        if (file.size > MAX_SIZE) {
            alert("❌ Image file is too large. Maximum size is 20 MB.");
            return false;
        }
        return true;
    }

    function showPreview(file) {
        var reader = new FileReader();
        reader.onload = function (e) {
            if (previewImage) {
                previewImage.src = e.target.result;
                previewImage.hidden = false;
            }
            if (previewPlaceholder) { previewPlaceholder.hidden = true; }
            if (dropzoneInner) {
                dropzoneInner.querySelector(".dropzone-title").textContent = file.name;
            }
        };
        reader.readAsDataURL(file);
    }

    function handleFile(file) {
        if (!isValidImage(file)) {
            if (input) { input.value = ""; }
            return;
        }
        showPreview(file);
    }

    if (input) {
        input.addEventListener("change", function () {
            if (input.files && input.files[0]) {
                handleFile(input.files[0]);
            }
        });
    }

    if (dropzone) {
        ["dragenter", "dragover"].forEach(function (evt) {
            dropzone.addEventListener(evt, function (e) {
                e.preventDefault();
                dropzone.classList.add("dragover");
            });
        });
        ["dragleave", "drop"].forEach(function (evt) {
            dropzone.addEventListener(evt, function (e) {
                e.preventDefault();
                dropzone.classList.remove("dragover");
            });
        });
        dropzone.addEventListener("drop", function (e) {
            var files = e.dataTransfer && e.dataTransfer.files;
            if (files && files[0]) {
                if (isValidImage(files[0]) && input) {
                    input.files = files;
                    showPreview(files[0]);
                }
            }
        });
    }

    /* ---------- Friendly client-side form validation ---------- */
    var encryptForm = document.getElementById("encryptForm");
    if (encryptForm) {
        encryptForm.addEventListener("submit", function (e) {
            var message = document.getElementById("messageInput");
            var key = document.getElementById("keyInput");
            if (input && (!input.files || !input.files[0])) {
                e.preventDefault();
                alert("❌ Please select an image.");
                return;
            }
            if (message && !message.value.trim()) {
                e.preventDefault();
                alert("❌ Please enter a secret message.");
                return;
            }
            if (key && !key.value) {
                e.preventDefault();
                alert("❌ Please enter an AES key.");
            }
        });
    }

    var decryptForm = document.getElementById("decryptForm");
    if (decryptForm) {
        decryptForm.addEventListener("submit", function (e) {
            var key = document.getElementById("keyInput");
            if (input && (!input.files || !input.files[0])) {
                e.preventDefault();
                alert("❌ Please select an image.");
                return;
            }
            if (key && !key.value) {
                e.preventDefault();
                alert("❌ Please enter an AES key.");
            }
        });
    }

    /* ---------- Login: one-click demo credential fill ---------- */
    var demoFill = document.getElementById("demoFill");
    var demoInfo = document.getElementById("demoInfo");
    if (demoFill && demoInfo) {
        demoFill.addEventListener("click", function () {
            // The login form uses an "identifier" field (username OR email).
            var identifier = document.getElementById("identifierInput") ||
                             document.getElementById("usernameInput");
            var password = document.getElementById("passwordInput");
            if (identifier) { identifier.value = demoInfo.getAttribute("data-username"); }
            if (password) { password.value = demoInfo.getAttribute("data-password"); }
            if (identifier) { identifier.focus(); }
        });
    }

    /* ---------- Register: confirm-password check ---------- */
    var registerForm = document.getElementById("registerForm");
    if (registerForm) {
        registerForm.addEventListener("submit", function (e) {
            var pw = document.getElementById("passwordInput");
            var confirm = document.getElementById("confirmInput");
            if (pw && confirm && pw.value !== confirm.value) {
                e.preventDefault();
                alert("❌ Passwords do not match.");
            }
        });
    }
})();
